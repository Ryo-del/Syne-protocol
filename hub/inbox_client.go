package hub

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrCloudInbox — облако отклонило запрос (код и сообщение — в тексте).
var ErrCloudInbox = errors.New("hub: Hub-входящие облака отклонили запрос")

var inboxHTTP = &http.Client{Timeout: 30 * time.Second}

func (c *Client) cloudBase() (string, error) {
	u := strings.TrimRight(c.CloudURL(), "/")
	if u == "" {
		return "", fmt.Errorf("hub: облако не настроено на сервере колледжа")
	}
	return u, nil
}

func inboxErr(resp *http.Response) error {
	var e struct{ Error, Message string }
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&e)
	return fmt.Errorf("%w: %d %s %s", ErrCloudInbox, resp.StatusCode, e.Error, e.Message)
}

// PostToInbox кладёт конверт во входящие облака для собеседника (и для своих других
// устройств). Облачный аккаунт не нужен: облако проверяет подпись конверта по реестру.
func (c *Client) PostToInbox(ctx context.Context, peerServerLogin string, env *Envelope, msgID string) error {
	base, err := c.cloudBase()
	if err != nil {
		return err
	}
	post := InboxPost{From: c.Login(), To: c.peerLoginSafe(peerServerLogin), Envelope: env, MsgID: msgID}
	raw, err := json.Marshal(post)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/hub/inbox", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := inboxHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return inboxErr(resp)
	}
	return nil
}

// PostGroupToInbox кладёт конверт группы во входящие облака для всех участников (и для своих
// других устройств): телефоны участников получат его без облачного аккаунта.
func (c *Client) PostGroupToInbox(ctx context.Context, groupID int64, groupName string, memberServerLogins []string, env *Envelope, msgID string) error {
	base, err := c.cloudBase()
	if err != nil {
		return err
	}
	post := InboxPost{From: c.Login(), Envelope: env, MsgID: msgID, Group: groupID, GroupName: groupName,
		Members: c.GroupLogins(memberServerLogins)}
	raw, err := json.Marshal(post)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/hub/inbox", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := inboxHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return inboxErr(resp)
	}
	return nil
}

func (c *Client) peerLoginSafe(serverLogin string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerLogin(serverLogin)
}

// FetchInbox забирает свои входящие после курсора after. Запрос подписан ключом
// устройства.
func (c *Client) FetchInbox(ctx context.Context, after int64) ([]InboxItem, error) {
	base, err := c.cloudBase()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	dev, derr := c.deviceLocked()
	login := c.login
	now := c.now()
	c.mu.Unlock()
	if derr != nil {
		return nil, derr
	}
	a := dev.SignFetch(login, after, now)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/hub/inbox/"+login+"?after="+strconv.FormatInt(after, 10), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Hub-Device", a.DeviceID)
	req.Header.Set("X-Hub-Ts", strconv.FormatInt(a.TS, 10))
	req.Header.Set("X-Hub-Sig", base64.StdEncoding.EncodeToString(a.Sig))
	resp, err := inboxHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, inboxErr(resp)
	}
	var out struct {
		Items []InboxItem `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Items, nil
}
