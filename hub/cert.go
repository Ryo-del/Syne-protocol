package hub

import (
	"crypto/ed25519"
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
	Sig       []byte `json:"sig"`
}

func (c *Certificate) signedBytes() []byte {
	return newEnc("syne-hub-cert-v1").
		u64(uint64(c.Version)).str(c.Login).str(c.HubID).str(c.DeviceID).str(c.Name).
		bytes(c.SignPub).bytes(c.AgreePub).str(c.IssuedBy).
		u64(uint64(c.IssuedAt)).u64(uint64(c.ExpiresAt)).b
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

// CertRequest — запрос на регистрацию устройства: публичные ключи, имя и одноразовый
// код, который пользователь сверяет на доверенном устройстве.
type CertRequest struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	SignPub  []byte `json:"sign_pub"`
	AgreePub []byte `json:"agree_pub"`
	Code     string `json:"code"`
}

// NewCertRequest создаёт запрос для ключей d.
func NewCertRequest(login, name string, d *DeviceKey, code string) CertRequest {
	return CertRequest{Login: login, Name: name, SignPub: d.SignPub, AgreePub: d.AgreePub, Code: code}
}

func (r CertRequest) DeviceID() string { return DeviceIDOf(r.SignPub, r.AgreePub) }

func (r CertRequest) newCert(hubID, issuer string, at time.Time, ttl time.Duration) Certificate {
	c := Certificate{
		Version: Version, Login: r.Login, HubID: hubID, DeviceID: r.DeviceID(), Name: r.Name,
		SignPub: r.SignPub, AgreePub: r.AgreePub, IssuedBy: issuer, IssuedAt: at.Unix(),
	}
	if ttl > 0 {
		c.ExpiresAt = at.Add(ttl).Unix()
	}
	return c
}

// IssueFirstDevice подписывает сертификат первого устройства корневым ключом.
func (r *RootKey) IssueFirstDevice(req CertRequest, at time.Time, ttl time.Duration) (Certificate, error) {
	c := req.newCert(r.HubID(), IssuerRoot, at, ttl)
	if err := c.checkShape(); err != nil {
		return Certificate{}, err
	}
	c.Sig = ed25519.Sign(r.priv, c.signedBytes())
	return c, nil
}

// Endorse — доверенное устройство (поручитель) подписывает сертификат нового.
// Перед вызовом пользователь должен сверить req.Code на экране поручителя.
func (d *DeviceKey) Endorse(hubID string, req CertRequest, at time.Time, ttl time.Duration) (Certificate, error) {
	c := req.newCert(hubID, d.DeviceID(), at, ttl)
	if err := c.checkShape(); err != nil {
		return Certificate{}, err
	}
	c.Sig = d.Sign(c.signedBytes())
	return c, nil
}
