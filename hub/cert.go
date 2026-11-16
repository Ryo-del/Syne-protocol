package hub

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// IssuerRoot — значение IssuedBy для сертификата, подписанного корневым ключом
// (только первое устройство и сброс).
const IssuerRoot = "root"

// Certificate — подписанное утверждение «это устройство принадлежит пользователю».
// Подписывает либо Root Key (первое устройство), либо доверенное устройство-поручитель.
type Certificate struct {
	Version   int    `json:"v"`
	Login     string `json:"login"` // login@org
	HubID     string `json:"hub_id"`
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	SignPub   []byte `json:"sign_pub"`
	AgreePub  []byte `json:"agree_pub"`
	IssuedBy  string `json:"issued_by"` // IssuerRoot или DeviceID поручителя
	IssuedAt  int64  `json:"issued_at"` // unix, секунды
	ExpiresAt int64  `json:"expires_at,omitempty"`
	// DeviceType — тип устройства: study, ios, android, desktop (входит в подпись).
	DeviceType string `json:"device_type,omitempty"`
	// Trusted — устройство получило право подтверждать подключение новых устройств в момент
	// выдачи сертификата («Да и сделать доверенным»). Позже статус можно повысить записью
	// promote; действующий статус даёт State, а не это поле.
	Trusted bool   `json:"trusted,omitempty"`
	Sig     []byte `json:"sig"`
}

func (c *Certificate) signedBytes() []byte {
	t := uint64(0)
	if c.Trusted {
		t = 1
	}
	return newEnc("syne-hub-cert-v1").
		u64(uint64(c.Version)).str(c.Login).str(c.HubID).str(c.DeviceID).str(c.Name).
		bytes(c.SignPub).bytes(c.AgreePub).str(c.IssuedBy).
		u64(uint64(c.IssuedAt)).u64(uint64(c.ExpiresAt)).str(c.DeviceType).u64(t).b
}

// checkShape проверяет внутреннюю согласованность: DeviceID выведен из ключей,
// длины ключей верные, логин имеет вид login@org.
func (c *Certificate) checkShape() error {
	if c.Version != Version {
		return fmt.Errorf("%w: версия сертификата %d", ErrFormat, c.Version)
	}
	if !ValidLogin(c.Login) {
		return fmt.Errorf("%w: логин %q", ErrFormat, c.Login)
	}
	if len(c.SignPub) != ed25519.PublicKeySize || len(c.AgreePub) != 32 {
		return fmt.Errorf("%w: длина ключей", ErrFormat)
	}
	if DeviceIDOf(c.SignPub, c.AgreePub) != c.DeviceID {
		return fmt.Errorf("%w: device_id не соответствует ключам", ErrFormat)
	}
	return nil
}

// ValidLogin — формат login@org (одна @, обе части непустые).
func ValidLogin(s string) bool {
	login, org, ok := strings.Cut(s, "@")
	return ok && login != "" && org != "" && !strings.ContainsAny(s, " \t\r\n") && !strings.Contains(org, "@")
}

// Expired — истёк ли срок на момент now.
func (c *Certificate) Expired(now time.Time) bool {
	return c.ExpiresAt != 0 && now.Unix() > c.ExpiresAt
}

// Типы устройств.
const (
	TypeStudy   = "study"
	TypeIOS     = "ios"
	TypeAndroid = "android"
	TypeDesktop = "desktop"
	TypeDevice  = "device"
)

func validDeviceType(t string) bool {
	switch t {
	case TypeStudy, TypeIOS, TypeAndroid, TypeDesktop, TypeDevice:
		return true
	}
	return false
}

// RequestTTL — срок жизни запроса на подключение в Holding (48 часов).
const RequestTTL = 48 * time.Hour

// CertRequest — запрос на регистрацию устройства: публичные ключи, имя, тип и одноразовый
// код, который пользователь сверяет глазами на двух экранах. Запрос подписан ключом НОВОГО
// устройства: облако и сервер не могут подменить в нём ключи или срок.
type CertRequest struct {
	Login     string `json:"login"`
	Name      string `json:"name"`
	SignPub   []byte `json:"sign_pub"`
	AgreePub  []byte `json:"agree_pub"`
	Code      string `json:"code"`
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Sig       []byte `json:"sig"`
}

func (r CertRequest) signedBytes() []byte {
	return newEnc("syne-cert-request-v1").str(r.Login).str(r.Name).str(r.Type).bytes(r.SignPub).bytes(r.AgreePub).
		str(r.Code).str(r.RequestID).u64(uint64(r.CreatedAt)).u64(uint64(r.ExpiresAt)).b
}

// NewSignedRequest создаёт запрос заданного типа, подписанный ключом d.
func NewSignedRequest(login, name, devType string, d *DeviceKey, code string, now time.Time) CertRequest {
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	r := CertRequest{Login: login, Name: name, SignPub: d.SignPub, AgreePub: d.AgreePub, Code: code, Type: devType,
		RequestID: hex.EncodeToString(id), CreatedAt: now.Unix(), ExpiresAt: now.Add(RequestTTL).Unix()}
	r.Sig = d.Sign(r.signedBytes())
	return r
}

// NewCertRequest — запрос типа TypeDevice (удобно в тестах и для первого устройства).
func NewCertRequest(login, name string, d *DeviceKey, code string) CertRequest {
	return NewSignedRequest(login, name, TypeDevice, d, code, time.Now())
}

// Verify проверяет форму, подпись запроса ключом самого устройства и срок.
func (r CertRequest) Verify(now time.Time) error {
	if !ValidLogin(r.Login) || len(r.SignPub) != ed25519.PublicKeySize || len(r.AgreePub) != 32 ||
		r.Name == "" || len(r.Name) > 64 || len(r.Code) > 64 || !validDeviceType(r.Type) || r.RequestID == "" || len(r.RequestID) > 64 {
		return fmt.Errorf("%w: запрос регистрации", ErrFormat)
	}
	if !ed25519.Verify(r.SignPub, r.signedBytes(), r.Sig) {
		return ErrSignature
	}
	if now.Unix() > r.ExpiresAt || r.ExpiresAt-r.CreatedAt > int64((RequestTTL+time.Hour).Seconds()) {
		return fmt.Errorf("%w: срок запроса", ErrFormat)
	}
	return nil
}

func (r CertRequest) DeviceID() string { return DeviceIDOf(r.SignPub, r.AgreePub) }

func (r CertRequest) newCert(hubID, issuer string, at time.Time, ttl time.Duration, trusted bool) Certificate {
	c := Certificate{
		Version: Version, Login: r.Login, HubID: hubID, DeviceID: r.DeviceID(), Name: r.Name,
		SignPub: r.SignPub, AgreePub: r.AgreePub, IssuedBy: issuer, IssuedAt: at.Unix(),
		DeviceType: r.Type, Trusted: trusted,
	}
	if ttl > 0 {
		c.ExpiresAt = at.Add(ttl).Unix()
	}
	return c
}

// IssueFirstDevice подписывает сертификат устройства корневым ключом: первое устройство и
// устройство, восстановленное по коду. Такое устройство всегда доверенное.
func (r *RootKey) IssueFirstDevice(req CertRequest, at time.Time, ttl time.Duration) (Certificate, error) {
	c := req.newCert(r.HubID(), IssuerRoot, at, ttl, true)
	if err := c.checkShape(); err != nil {
		return Certificate{}, err
	}
	c.Sig = ed25519.Sign(r.priv, c.signedBytes())
	return c, nil
}

// Endorse — доверенное устройство (поручитель) подписывает сертификат нового. trusted — выбор
// пользователя «Да и сделать доверенным» (true) или «Да» (false: обычное привязанное устройство).
// Перед вызовом пользователь сверяет код сопряжения на двух экранах.
func (d *DeviceKey) Endorse(hubID string, req CertRequest, at time.Time, ttl time.Duration, trusted bool) (Certificate, error) {
	c := req.newCert(hubID, d.DeviceID(), at, ttl, trusted)
	if err := c.checkShape(); err != nil {
		return Certificate{}, err
	}
	c.Sig = d.Sign(c.signedBytes())
	return c, nil
}
