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
	"net/url"
	"strconv"
	"time"
)

// Значения по умолчанию, если облако не сообщило свои пределы (HUB_BLOB_* в его .env).
const (
	DefaultBlobMax      = 25 << 20 // файл в личной беседе
	DefaultBlobGroupMax = 10 << 20 // файл в групповой беседе
)

// blobUploadChunk — размер части при загрузке блоба в облако.
const blobUploadChunk = 4 << 20

// ErrCloudBlob — облако отклонило запрос к блобу (код и сообщение — в тексте).
var ErrCloudBlob = errors.New("hub: облако отклонило запрос вложения")

// BlobError — ответ облака об ошибке: Status — код HTTP (404/410 — блоб удалён или истёк срок хранения).
// errors.Is(err, ErrCloudBlob) выполняется.
type BlobError struct {
	Status        int
	Code, Message string
}

func (e *BlobError) Error() string {
	return fmt.Sprintf("%s: %d %s %s", ErrCloudBlob, e.Status, e.Code, e.Message)
}

func (e *BlobError) Is(target error) bool { return target == ErrCloudBlob }

// Gone — вложения больше нет в облаке (истёк срок хранения или оно удалено).
func (e *BlobError) Gone() bool {
	return e.Status == http.StatusGone || e.Status == http.StatusNotFound
}

// BlobOffsetError — облако ждёт продолжения загрузки с другого места (Received байт уже есть).
type BlobOffsetError struct{ Received int64 }

func (e *BlobOffsetError) Error() string { return "offset mismatch" }

var (
	blobMetaHTTP = &http.Client{Timeout: 60 * time.Second}
	blobDataHTTP = &http.Client{} // скачивание без общего таймаута: файл может быть большим
)

func blobErr(resp *http.Response) error {
	var b struct {
		Error, Message string
		Received       int64
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&b)
	if b.Error == "offset_mismatch" {
		return &BlobOffsetError{Received: b.Received}
	}
	return &BlobError{Status: resp.StatusCode, Code: b.Error, Message: b.Message}
}

// blobSigner возвращает ключ устройства и логин под замком клиента.
func (c *Client) blobSigner() (*DeviceKey, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev, err := c.deviceLocked()
	if err != nil {
		return nil, "", err
	}
	return dev, c.login, nil
}

func (c *Client) blobRequest(ctx context.Context, method, path string, query url.Values, body []byte, ctype string, a FetchAuth, out any) error {
	base, err := c.cloudBase()
	if err != nil {
		return err
	}
	u := base + "/api/v1/hub/" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("X-Hub-Device", a.DeviceID)
	req.Header.Set("X-Hub-Ts", strconv.FormatInt(a.TS, 10))
	req.Header.Set("X-Hub-Sig", base64.StdEncoding.EncodeToString(a.Sig))
	resp, err := blobMetaHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return blobErr(resp)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return nil
}

// BlobUpload загружает зашифрованный блоб (результат SealBlob) в облако с докачкой при обрыве.
// Запросы подписаны ключом устройства, облачный аккаунт не нужен.
func (c *Client) BlobUpload(ctx context.Context, src io.ReaderAt, info BlobInfo) error {
	dev, login, err := c.blobSigner()
	if err != nil {
		return err
	}
	sign := func(domain string, size int64) FetchAuth {
		c.mu.Lock()
		now := c.now()
		c.mu.Unlock()
		return dev.SignBlob(domain, login, info.BlobID, size, now)
	}
	var start struct {
		Received int64 `json:"received"`
		Complete bool  `json:"complete"`
	}
	begin, _ := json.Marshal(map[string]any{"from": login, "blob": info.BlobID, "size": info.EncSize})
	if err := c.blobRequest(ctx, "POST", "blobs", nil, begin, "application/json", sign(DomainBlobPut, info.EncSize), &start); err != nil {
		return err
	}
	received := start.Received
	buf := make([]byte, blobUploadChunk)
	for !start.Complete && received < info.EncSize {
		n, rerr := src.ReadAt(buf, received)
		if n == 0 && rerr != nil {
			return fmt.Errorf("hub: не удалось прочитать зашифрованный файл: %w", rerr)
		}
		var next struct {
			Received int64 `json:"received"`
		}
		q := url.Values{"from": {login}, "offset": {strconv.FormatInt(received, 10)}}
		for attempt := 0; ; attempt++ {
			err = c.blobRequest(ctx, "PUT", "blobs/"+info.BlobID, q, buf[:n], "application/octet-stream", sign(DomainBlobPut, info.EncSize), &next)
			var oe *BlobOffsetError
			if errors.As(err, &oe) {
				next.Received, err = oe.Received, nil
			}
			if err == nil || attempt >= 3 || ctx.Err() != nil {
				break
			}
		}
		if err != nil {
			return err
		}
		received = next.Received
	}
	return c.blobRequest(ctx, "POST", "blobs/"+info.BlobID+"/complete", url.Values{"from": {login}}, nil, "", sign(DomainBlobPut, info.EncSize), nil)
}

// BlobDownload открывает поток зашифрованного блоба (его расшифровывает OpenBlob). Вызывающий закрывает поток.
func (c *Client) BlobDownload(ctx context.Context, blobID string) (io.ReadCloser, error) {
	if !ValidBlobID(blobID) {
		return nil, fmt.Errorf("%w: идентификатор вложения", ErrFormat)
	}
	base, err := c.cloudBase()
	if err != nil {
		return nil, err
	}
	dev, login, err := c.blobSigner()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	now := c.now()
	c.mu.Unlock()
	a := dev.SignBlob(DomainBlobGet, login, blobID, 0, now)
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/v1/hub/blobs/"+blobID+"?"+url.Values{"login": {login}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Hub-Device", a.DeviceID)
	req.Header.Set("X-Hub-Ts", strconv.FormatInt(a.TS, 10))
	req.Header.Set("X-Hub-Sig", base64.StdEncoding.EncodeToString(a.Sig))
	resp, err := blobDataHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, blobErr(resp)
	}
	return resp.Body, nil
}
