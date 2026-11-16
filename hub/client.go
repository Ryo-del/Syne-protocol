package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Caller — вызов реестра сервера колледжа (libp2p-поток для Study, HTTPS для Mobile).
// Сессия пользователя подставляется вызывающим.
type Caller func(ctx context.Context, req Request) (Response, error)

// Blobber шифрует blob устройства ключом пользователя (мастер-ключ Study), чтобы
// сервер его не прочитал. Blob лежит на сервере, потому что Study ничего не хранит на
// общем компьютере.
type Blobber struct {
	Seal func(plain []byte) ([]byte, error)
	Open func(sealed []byte) ([]byte, error)
}

var (
	ErrNoHub        = errors.New("hub: у пользователя нет Hub")
	ErrNotReady     = errors.New("hub: это устройство ещё не зарегистрировано")
	ErrBadPairCode  = errors.New("hub: код сопряжения не совпал")
	ErrNoRequest    = errors.New("hub: запрос регистрации не найден")
	ErrNeedMoreSigs = errors.New("hub: политика требует подписей нескольких устройств")
	ErrNoRecipients = errors.New("hub: у получателя нет доверенных устройств")
)

// TrustChangeError — у собеседника изменилась идентичность (сброс Hub), или реестр откатился
// или разошёлся. Отправка блокируется, пока пользователь не подтвердит (AcceptPeer).
type TrustChangeError struct {
	Login        string
	Kind         ChangeKind
	SafetyNumber string
}

func (e *TrustChangeError) Error() string {
	switch e.Kind {
	case ChangeReset:
		return fmt.Sprintf("у %s сменилась идентичность (сброс); сверьте номер безопасности", e.Login)
	case ChangeRollback:
		return fmt.Sprintf("реестр устройств %s откатился назад", e.Login)
	}
	return fmt.Sprintf("реестр устройств %s не совпадает с запомненным", e.Login)
}

// State — состояние устройства относительно Hub.
type LinkState string

const (
	StateReady          LinkState = "ready"           // устройство зарегистрировано
	StateCreated        LinkState = "created"         // Hub только что создан (показать код восстановления!)
	StateAwaiting       LinkState = "awaiting"        // запрос отправлен, ждём подтверждения другим устройством
	StateRevoked        LinkState = "revoked"         // это устройство отозвано
	StateResetAvailable LinkState = "reset_available" // администратор открыл сброс: можно создать новый Hub
)

// InitResult — итог Init.
type InitResult struct {
	State        LinkState
	Login        string
	DeviceID     string
	RecoveryCode string // только при StateCreated; нигде не хранится
	PairCode     string // при StateAwaiting
}

type blob struct {
	Version int            `json:"v"`
	Device  []byte         `json:"device"`
	Pins    map[string]Pin `json:"pins,omitempty"`
}

// Client — клиент реестра для одного устройства одного пользователя.
type Client struct {
	call Caller
	bl   Blobber
	now  func() time.Time

	mu       sync.Mutex
	login    string // login@org
	cloudURL string
	dev      *DeviceKey
	own      *Log
	trust    *TrustStore
	peers    map[string]*peerCache
	state    LinkState
	deviceNm string
	devType  string
}

type peerCache struct {
	log *Log
	at  time.Time
}

const peerTTL = 30 * time.Second

func NewClient(call Caller, bl Blobber, deviceName string) *Client {
	return &Client{call: call, bl: bl, now: time.Now, trust: NewTrustStore(), peers: map[string]*peerCache{}, deviceNm: deviceName, devType: TypeStudy}
}

// SetDeviceType задаёт тип устройства в запросах и сертификатах (по умолчанию study).
func (c *Client) SetDeviceType(t string) { c.mu.Lock(); c.devType = t; c.mu.Unlock() }

func (c *Client) newRequest(code string) CertRequest {
	return NewSignedRequest(c.login, c.deviceNm, c.devType, c.dev, code, c.now())
}

func (c *Client) do(ctx context.Context, req Request) (Response, error) {
	req.Version = APIVersion
	resp, err := c.call(ctx, req)
	if err != nil {
		return resp, err
	}
	if !resp.OK {
		return resp, &APIError{Code: resp.Code, Msg: resp.Error}
	}
	return resp, nil
}

// APIError — ошибка, вернувшаяся от реестра.
type APIError struct{ Code, Msg string }

func (e *APIError) Error() string { return e.Msg }

func isCode(err error, code string) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == code
}

// CloudURL — адрес Syne Cloud для Hub-входящих ("" — облако не настроено).
func (c *Client) CloudURL() string { c.mu.Lock(); defer c.mu.Unlock(); return c.cloudURL }

// SetClock подменяет часы (тесты).
func (c *Client) SetClock(now func() time.Time) { c.mu.Lock(); c.now = now; c.mu.Unlock() }

func (c *Client) Login() string { c.mu.Lock(); defer c.mu.Unlock(); return c.login }
func (c *Client) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == StateReady || c.state == StateCreated
}
func (c *Client) CurrentState() LinkState { c.mu.Lock(); defer c.mu.Unlock(); return c.state }

// DeviceID — Device ID этого устройства ("" пока ключа нет).
func (c *Client) DeviceID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dev == nil {
		return ""
	}
	return c.dev.DeviceID()
}

func (c *Client) saveBlob(ctx context.Context) error {
	b := blob{Version: 1, Pins: c.trust.Pins()}
	if c.dev != nil {
		b.Device = c.dev.Marshal()
	}
	raw, _ := json.Marshal(b)
	sealed, err := c.bl.Seal(raw)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, Request{Op: OpPutDevice, Blob: sealed})
	return err
}

func (c *Client) loadBlob(ctx context.Context) error {
	resp, err := c.do(ctx, Request{Op: OpGetDevice})
	if err != nil {
		return err
	}
	if len(resp.Blob) == 0 {
		return nil
	}
	raw, err := c.bl.Open(resp.Blob)
	if err != nil {
		// Не перезаписываем то, что не смогли прочитать.
		return fmt.Errorf("hub: blob устройства не расшифровывается: %w", err)
	}
	var b blob
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("hub: blob устройства повреждён: %w", err)
	}
	if len(b.Device) > 0 {
		if c.dev, err = UnmarshalDeviceKey(b.Device); err != nil {
			return err
		}
	}
	c.trust.SetPins(b.Pins)
	return nil
}

// fetchLog забирает и полностью перепроверяет журнал реестра (без доверия серверу и
// облаку). Если у нас есть кэш — запрашиваем только хвост и проверяем целиком.
func (c *Client) fetchLog(ctx context.Context, login string, cached *Log) (*Log, error) {
	var have []Entry
	if cached != nil {
		have = cached.Entries
	}
	resp, err := c.do(ctx, Request{Op: OpRegistry, Login: login, After: uint64(len(have))})
	if err != nil {
		if isCode(err, ErrCodeNotFound) {
			return nil, ErrNoHub
		}
		return nil, err
	}
	full := append(append([]Entry(nil), have...), resp.Entries...)
	l, err := LoadLog(full, DefaultPolicy())
	if err != nil {
		// Хвост не стыкуется с кэшем (например, сброс): пробуем с нуля.
		if cached != nil {
			return c.fetchLog(ctx, login, nil)
		}
		return nil, fmt.Errorf("hub: реестр %s не прошёл проверку: %w", login, err)
	}
	if resp.Head != nil && resp.Head.Hash != "" && resp.Head.Hash != l.State().Head.Hash {
		// Кэш устарел (например, у логина новый Hub после сброса): перезапрашиваем целиком.
		if cached != nil {
			return c.fetchLog(ctx, login, nil)
		}
		return nil, fmt.Errorf("hub: вершина реестра %s не совпадает с журналом", login)
	}
	return l, nil
}

func newCode() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Init приводит устройство в рабочее состояние. Вызывается после входа пользователя.
//   - Hub нет → создаётся (Root Key, первое устройство, код восстановления);
//   - Hub есть, устройство в нём → ready;
//   - Hub есть, устройства нет → запрос регистрации (нужно подтверждение другим устройством).
func (c *Client) Init(ctx context.Context) (InitResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := c.do(ctx, Request{Op: OpInfo})
	if err != nil {
		return InitResult{}, err
	}
	c.login, c.cloudURL = info.Login, info.CloudURL
	if err := c.loadBlob(ctx); err != nil {
		return InitResult{}, err
	}
	l, err := c.fetchLog(ctx, c.login, nil)
	if errors.Is(err, ErrNoHub) {
		return c.createHubLocked(ctx, "")
	}
	if err != nil {
		return InitResult{}, err
	}
	c.own = l
	if c.trust.Observe(c.login, l) == ChangeReset {
		c.trust.AcceptReset(c.login, l) // мы сами владелец: это наш реестр
	}
	return c.stateAfterLoadLocked(ctx, info.ResetOpen)
}

func (c *Client) stateAfterLoadLocked(ctx context.Context, resetOpen bool) (InitResult, error) {
	res := InitResult{Login: c.login}
	if c.dev != nil {
		res.DeviceID = c.dev.DeviceID()
		if _, err := c.own.State().Active(res.DeviceID, c.now()); err == nil {
			c.state = StateReady
			res.State = StateReady
			return res, c.saveBlobIfPinsChanged(ctx)
		} else if errors.Is(err, ErrDeviceRevok) {
			c.state = StateRevoked
			if !resetOpen {
				res.State = StateRevoked
				return res, nil
			}
		}
	}
	if resetOpen {
		c.state = StateResetAvailable
		res.State = StateResetAvailable
		return res, nil
	}
	// Устройства в реестре нет: просим подтверждение у других.
	if c.dev == nil || c.state == StateRevoked {
		d, err := GenerateDeviceKey()
		if err != nil {
			return res, err
		}
		c.dev = d
		if err := c.saveBlob(ctx); err != nil {
			return res, err
		}
	}
	req := c.newRequest(newCode())
	if _, err := c.do(ctx, Request{Op: OpRequest, Req: &req}); err != nil {
		return res, err
	}
	c.state = StateAwaiting
	res.State, res.DeviceID, res.PairCode = StateAwaiting, c.dev.DeviceID(), req.PairCode()
	return res, nil
}

func (c *Client) saveBlobIfPinsChanged(ctx context.Context) error { return c.saveBlob(ctx) }

func (c *Client) createHubLocked(ctx context.Context, prevHubID string) (InitResult, error) {
	root, err := GenerateRootKey()
	if err != nil {
		return InitResult{}, err
	}
	dev, err := GenerateDeviceKey()
	if err != nil {
		return InitResult{}, err
	}
	l, err := NewLog(root, c.login, NewSignedRequest(c.login, c.deviceNm, c.devType, dev, "", c.now()), prevHubID, c.now(), DefaultPolicy())
	if err != nil {
		return InitResult{}, err
	}
	if _, err := c.do(ctx, Request{Op: OpCreate, Genesis: &l.Entries[0]}); err != nil {
		return InitResult{}, err
	}
	// Сразу после создания: копия Root Key под кодом восстановления. Сам root дальше
	// не используется и из памяти уходит вместе с этой функцией.
	code, err := NewRecoveryCode()
	if err != nil {
		return InitResult{}, err
	}
	wrapped, err := WrapRoot(root, code)
	if err != nil {
		return InitResult{}, err
	}
	if _, err := c.do(ctx, Request{Op: OpPutBackup, Backup: wrapped}); err != nil {
		return InitResult{}, err
	}
	c.dev, c.own, c.state = dev, l, StateCreated
	c.trust.AcceptReset(c.login, l)
	if err := c.saveBlob(ctx); err != nil {
		return InitResult{}, err
	}
	return InitResult{State: StateCreated, Login: c.login, DeviceID: dev.DeviceID(), RecoveryCode: FormatRecoveryCode(code)}, nil
}

// CreateNewHub создаёт новый Hub после сброса идентичности администратором. Собеседники
// увидят смену Hub и номера безопасности.
func (c *Client) CreateNewHub(ctx context.Context) (InitResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := c.do(ctx, Request{Op: OpInfo})
	if err != nil {
		return InitResult{}, err
	}
	if !info.ResetOpen {
		return InitResult{}, &APIError{Code: ErrCodeResetNeeded, Msg: "сброс не открыт администратором"}
	}
	c.login = info.Login
	l, err := c.fetchLog(ctx, c.login, nil)
	if err != nil {
		return InitResult{}, err
	}
	return c.createHubLocked(ctx, l.State().HubID)
}

// FormatRecoveryCode — код восстановления в виде групп для записи на бумагу.
func FormatRecoveryCode(code []byte) string {
	h := strings.ToUpper(hex.EncodeToString(code))
	var parts []string
	for i := 0; i < len(h); i += 8 {
		parts = append(parts, h[i:i+8])
	}
	return strings.Join(parts, "-")
}

// ParseRecoveryCode — обратное преобразование (пробелы и дефисы игнорируются).
func ParseRecoveryCode(s string) ([]byte, error) {
	s = strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s))
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, ErrRecovery
	}
	return b, nil
}

// Refresh обновляет свой реестр и состояние (например, после подтверждения запроса).
func (c *Client) Refresh(ctx context.Context) (LinkState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.login == "" {
		return "", ErrNotReady
	}
	l, err := c.fetchLog(ctx, c.login, c.own)
	if err != nil {
		return c.state, err
	}
	if c.trust.Observe(c.login, l) == ChangeRollback {
		return c.state, &TrustChangeError{Login: c.login, Kind: ChangeRollback}
	}
	c.own = l
	if c.dev != nil {
		if _, err := l.State().Active(c.dev.DeviceID(), c.now()); err == nil {
			if c.state != StateReady && c.state != StateCreated {
				c.state = StateReady
				return c.state, c.saveBlob(ctx)
			}
			return c.state, nil
		} else if errors.Is(err, ErrDeviceRevok) {
			c.state = StateRevoked
		}
	}
	return c.state, nil
}

// Devices — доверенные устройства пользователя (для экрана «Устройства»).
func (c *Client) Devices() []Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.own == nil {
		return nil
	}
	return c.own.State().ActiveDevices(c.now())
}

// DeviceInfo — устройство пользователя с действующим статусом (Trusted — может подтверждать).
type DeviceInfo struct {
	Cert    Certificate
	Trusted bool
}

// DeviceInfos — действующие устройства со статусами для экрана «Устройства».
func (c *Client) DeviceInfos() []DeviceInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.own == nil {
		return nil
	}
	st := c.own.State()
	var out []DeviceInfo
	for _, cert := range st.ActiveDevices(c.now()) {
		out = append(out, DeviceInfo{Cert: cert, Trusted: st.Devices[cert.DeviceID].Trusted})
	}
	return out
}

// BindAccount подписывает связь «аккаунт Syne Web (облака) ↔ эта идентичность Hub». Подписывает
// только доверенное устройство; облако проверяет подпись по реестру и само связать не может.
func (c *Client) BindAccount(accountID string) (Binding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev, err := c.approverLocked()
	if err != nil {
		return Binding{}, err
	}
	return dev.SignBinding(c.login, accountID, c.now()), nil
}

// CanApprove — может ли это устройство подтверждать новые (доверенное ли оно).
func (c *Client) CanApprove() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.approverLocked()
	return err == nil
}

// Events — журнал безопасности пользователя (сервер колледжа).
func (c *Client) Events(ctx context.Context) ([]SecurityEvent, error) {
	resp, err := c.do(ctx, Request{Op: OpEvents})
	return resp.Events, err
}

// Pending — запросы на регистрацию устройств, ожидающие подтверждения.
func (c *Client) Pending(ctx context.Context) ([]PendingRequest, error) {
	resp, err := c.do(ctx, Request{Op: OpPending})
	return resp.Pending, err
}

func (c *Client) deviceLocked() (*DeviceKey, error) {
	if c.dev == nil || (c.state != StateReady && c.state != StateCreated) {
		return nil, ErrNotReady
	}
	return c.dev, nil
}

// approverLocked — устройство готово И доверенное: только такое подтверждает, повышает и отзывает.
func (c *Client) approverLocked() (*DeviceKey, error) {
	dev, err := c.deviceLocked()
	if err != nil {
		return nil, err
	}
	if c.own == nil {
		return nil, ErrNotReady
	}
	if err := c.own.State().CanApprove(dev.DeviceID(), c.now()); err != nil {
		return nil, err
	}
	return dev, nil
}

// Approve — это устройство ручается за новое. pairCode — код, который пользователь
// прочитал на экране нового устройства: без совпадения подтверждение невозможно.
func (c *Client) Approve(ctx context.Context, deviceID string, trusted bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev, err := c.approverLocked()
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, Request{Op: OpPending})
	if err != nil {
		return err
	}
	for _, p := range resp.Pending {
		if p.Req.DeviceID() != deviceID {
			continue
		}
		if err := p.Req.Verify(c.now()); err != nil {
			return err
		}
		cert, err := dev.Endorse(c.own.State().HubID, p.Req, c.now(), 0, trusted)
		if err != nil {
			return err
		}
		if _, err := c.do(ctx, Request{Op: OpApprove, Cert: &cert}); err != nil {
			return err
		}
		l, err := c.fetchLog(ctx, c.login, c.own)
		if err == nil {
			c.own = l
			c.trust.Observe(c.login, l)
		}
		return nil
	}
	return ErrNoRequest
}

// Promote передаёт доверие уже привязанному устройству (настройки безопасности).
func (c *Client) Promote(ctx context.Context, deviceID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev, err := c.approverLocked()
	if err != nil {
		return err
	}
	l, err := c.fetchLog(ctx, c.login, c.own)
	if err != nil {
		return err
	}
	p := NewPromotion(l.State().HubID, deviceID, l.HeadHash(), c.now())
	dev.SignPromotion(p)
	if _, err := c.do(ctx, Request{Op: OpPromote, Promotion: p}); err != nil {
		return err
	}
	if l, err = c.fetchLog(ctx, c.login, l); err == nil {
		c.own = l
		c.trust.Observe(c.login, l)
	}
	return nil
}

// Reject отклоняет запрос регистрации.
func (c *Client) Reject(ctx context.Context, deviceID string) error {
	_, err := c.do(ctx, Request{Op: OpReject, DeviceID: deviceID})
	return err
}

// Revoke отзывает устройство. cascade — заодно отозвать все, за которые оно поручилось
// (если устройство украдено и успело добавить чужое).
func (c *Client) Revoke(ctx context.Context, deviceID string, cascade bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev, err := c.approverLocked()
	if err != nil {
		return err
	}
	if deviceID == dev.DeviceID() {
		return fmt.Errorf("hub: нельзя отозвать устройство, с которого вы работаете")
	}
	// Всегда свежий реестр: подпись привязана к вершине журнала.
	l, err := c.fetchLog(ctx, c.login, c.own)
	if err != nil {
		return err
	}
	if need := DefaultPolicy().need(); need > 1 {
		return ErrNeedMoreSigs
	}
	r := NewRevocation(l.State().HubID, deviceID, l.HeadHash(), cascade, c.now())
	r.Sign(dev)
	if _, err := c.do(ctx, Request{Op: OpRevoke, Revocation: r}); err != nil {
		return err
	}
	if l, err = c.fetchLog(ctx, c.login, l); err == nil {
		c.own = l
		c.trust.Observe(c.login, l)
	}
	return nil
}

// Recover восстанавливает доступ с кодом восстановления: расшифровывает Root Key, регистрирует
// этим устройством новое устройство (подпись корнем) и при необходимости отзывает потерянные.
func (c *Client) Recover(ctx context.Context, code string, revokeOthers bool) (InitResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, err := ParseRecoveryCode(code)
	if err != nil {
		return InitResult{}, err
	}
	resp, err := c.do(ctx, Request{Op: OpRecovery})
	if err != nil {
		return InitResult{}, err
	}
	root, err := UnwrapRoot(resp.Backup, raw)
	if err != nil {
		return InitResult{}, err
	}
	l, err := c.fetchLog(ctx, c.login, nil)
	if err != nil {
		return InitResult{}, err
	}
	if root.HubID() != l.State().HubID {
		return InitResult{}, ErrRecovery // копия от другого Hub
	}
	if c.dev == nil {
		if c.dev, err = GenerateDeviceKey(); err != nil {
			return InitResult{}, err
		}
	}
	if _, trusted := l.State().Active(c.dev.DeviceID(), c.now()); trusted != nil {
		req := c.newRequest(newCode())
		if _, err := c.do(ctx, Request{Op: OpRequest, Req: &req}); err != nil {
			return InitResult{}, err
		}
		cert, err := root.IssueFirstDevice(req, c.now(), 0)
		if err != nil {
			return InitResult{}, err
		}
		if _, err := c.do(ctx, Request{Op: OpApprove, Cert: &cert}); err != nil {
			return InitResult{}, err
		}
		if l, err = c.fetchLog(ctx, c.login, l); err != nil {
			return InitResult{}, err
		}
	}
	if revokeOthers {
		for _, d := range l.State().ActiveDevices(c.now()) {
			if d.DeviceID == c.dev.DeviceID() {
				continue
			}
			r := NewRevocation(l.State().HubID, d.DeviceID, l.HeadHash(), true, c.now())
			r.SignRoot(root)
			if _, err := c.do(ctx, Request{Op: OpRevoke, Revocation: r}); err != nil {
				return InitResult{}, err
			}
			if l, err = c.fetchLog(ctx, c.login, l); err != nil {
				return InitResult{}, err
			}
		}
	}
	c.own, c.state = l, StateReady
	c.trust.Observe(c.login, l)
	if err := c.saveBlob(ctx); err != nil {
		return InitResult{}, err
	}
	return InitResult{State: StateReady, Login: c.login, DeviceID: c.dev.DeviceID()}, nil
}

func (c *Client) peerLogin(serverLogin string) string {
	if strings.Contains(serverLogin, "@") {
		return serverLogin
	}
	_, org, _ := strings.Cut(c.login, "@")
	return serverLogin + "@" + org
}

// peer возвращает проверенный реестр собеседника. Смена идентичности, откат и развилка
// выдаются как *TrustChangeError.
func (c *Client) peer(ctx context.Context, serverLogin string, force bool) (*Log, error) {
	login := c.peerLogin(serverLogin)
	if pc, ok := c.peers[login]; ok && !force && c.now().Sub(pc.at) < peerTTL {
		return pc.log, nil
	}
	var cached *Log
	if pc, ok := c.peers[login]; ok {
		cached = pc.log
	}
	l, err := c.fetchLog(ctx, login, cached)
	if err != nil {
		return nil, err
	}
	switch kind := c.trust.Observe(login, l); kind {
	case ChangeReset, ChangeRollback, ChangeFork:
		return nil, &TrustChangeError{Login: login, Kind: kind, SafetyNumber: c.safetyNumberLocked(login, l)}
	case ChangeNew:
		_ = c.saveBlob(ctx)
	}
	c.peers[login] = &peerCache{log: l, at: c.now()}
	return l, nil
}

func (c *Client) safetyNumberLocked(peerLogin string, pl *Log) string {
	if c.own == nil {
		return ""
	}
	return SafetyNumber(c.login, c.own.State().RootPub, peerLogin, pl.State().RootPub)
}

// SafetyNumber возвращает номер безопасности с собеседником для экрана «Проверить».
func (c *Client) SafetyNumber(ctx context.Context, serverLogin string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	login := c.peerLogin(serverLogin)
	l, err := c.fetchLog(ctx, login, nil)
	if err != nil {
		return "", err
	}
	return c.safetyNumberLocked(login, l), nil
}

// AcceptPeer подтверждает новый Hub собеседника (после сверки номера безопасности).
func (c *Client) AcceptPeer(ctx context.Context, serverLogin string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	login := c.peerLogin(serverLogin)
	l, err := c.fetchLog(ctx, login, nil)
	if err != nil {
		return err
	}
	c.trust.AcceptReset(login, l)
	c.peers[login] = &peerCache{log: l, at: c.now()}
	return c.saveBlob(ctx)
}

// Encrypt шифрует сообщение для всех доверенных устройств собеседника и для своих других
// устройств. ErrNoHub — у собеседника Hub нет (клиент использует старую схему).
func (c *Client) Encrypt(ctx context.Context, peerServerLogin string, chatCtx, plaintext []byte) (*Envelope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev, err := c.deviceLocked()
	if err != nil {
		return nil, err
	}
	pl, err := c.peer(ctx, peerServerLogin, false)
	if err != nil {
		return nil, err
	}
	rcpts := pl.State().ActiveDevices(c.now())
	if len(rcpts) == 0 {
		return nil, ErrNoRecipients
	}
	if l, err := c.fetchLog(ctx, c.login, c.own); err == nil {
		c.own = l
	}
	rcpts = append(rcpts, c.own.State().ActiveDevices(c.now())...)
	return Seal(plaintext, chatCtx, dev, rcpts)
}

// Decrypt расшифровывает сообщение собеседника: отправитель должен быть доверенным
// устройством в его реестре.
func (c *Client) Decrypt(ctx context.Context, fromServerLogin string, env *Envelope) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev, err := c.deviceLocked()
	if err != nil {
		return nil, err
	}
	pl, err := c.peer(ctx, fromServerLogin, false)
	if err != nil {
		var tc *TrustChangeError
		if !errors.As(err, &tc) {
			return nil, err
		}
		return nil, err
	}
	cert, err := pl.State().Active(env.SenderID, c.now())
	if err != nil {
		// Реестр мог обновиться после кэша: одна попытка со свежим.
		if pl, err = c.peer(ctx, fromServerLogin, true); err != nil {
			return nil, err
		}
		if cert, err = pl.State().Active(env.SenderID, c.now()); err != nil {
			return nil, fmt.Errorf("hub: отправитель не доверен: %w", err)
		}
	}
	return Open(env, dev, *cert)
}

// HasHub — есть ли Hub у собеседника (для выбора схемы шифрования).
func (c *Client) HasHub(ctx context.Context, serverLogin string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.peer(ctx, serverLogin, false)
	if errors.Is(err, ErrNoHub) {
		return false, nil
	}
	return err == nil, err
}

// EncryptGroup шифрует сообщение группы на все доверенные устройства участников (кроме нас)
// и на свои устройства. Состав группы определяет сервер колледжа; ключа группы ни у кого нет.
// Участники без Hub или недоступные пропускаются и возвращаются в skipped: они сообщения не
// прочитают, пока не подключат Hub. Это «веерная» схема (по конверту на устройство), а не
// MLS: она годится для групп до MaxGroupMembers участников; см. 09-выбор-библиотек.
func (c *Client) EncryptGroup(ctx context.Context, memberServerLogins []string, chatCtx, plaintext []byte) (env *Envelope, skipped []string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dev, err := c.deviceLocked()
	if err != nil {
		return nil, nil, err
	}
	if len(memberServerLogins) > MaxGroupMembers {
		return nil, nil, fmt.Errorf("hub: в группе больше %d участников", MaxGroupMembers)
	}
	var rcpts []Certificate
	for _, m := range memberServerLogins {
		if c.peerLogin(m) == c.login {
			continue
		}
		pl, perr := c.peer(ctx, m, false)
		if perr != nil {
			var tc *TrustChangeError
			if errors.As(perr, &tc) {
				return nil, nil, perr // смена идентичности участника: нужно решение пользователя
			}
			skipped = append(skipped, m)
			continue
		}
		rcpts = append(rcpts, pl.State().ActiveDevices(c.now())...)
	}
	if l, lerr := c.fetchLog(ctx, c.login, c.own); lerr == nil {
		c.own = l
	}
	rcpts = append(rcpts, c.own.State().ActiveDevices(c.now())...)
	env, err = Seal(plaintext, chatCtx, dev, rcpts)
	return env, skipped, err
}

// GroupLogins превращает логины сервера в login@org.
func (c *Client) GroupLogins(serverLogins []string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(serverLogins))
	for _, l := range serverLogins {
		out = append(out, c.peerLogin(l))
	}
	return out
}
