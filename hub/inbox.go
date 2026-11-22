package hub

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// Hub-входящие (облако): место, куда отправитель кладёт зашифрованный конверт для
// устройств получателя. Облачный аккаунт не нужен ни отправителю, ни получателю:
//   - кладёт отправитель — конверт подписан ключом его устройства, облако проверяет подпись
//     и доверенность устройства по зеркалу реестра (VerifyPost);
//   - забирает устройство получателя — запрос подписан ключом устройства (VerifyFetch).
// Облако видит только шифртекст, логины и размеры.

// InboxPost — запрос на доставку.
type InboxPost struct {
	From     string    `json:"from"`     // login@org отправителя
	To       string    `json:"to"`       // login@org получателя (личное сообщение)
	Envelope *Envelope `json:"envelope"` // подписан устройством отправителя
	MsgID    string    `json:"msg_id"`   // идентификатор сообщения (идемпотентность)

	// Групповое сообщение: To пуст, получатели — Members (login@org), Group — номер группы
	// на сервере колледжа, GroupName — название для телефона.
	Group     int64    `json:"group,omitempty"`
	GroupName string   `json:"group_name,omitempty"`
	Members   []string `json:"members,omitempty"`

	// Blobs — зашифрованные файлы, привязанные к сообщению (файл 13): облако даёт получателям
	// скачать их. Имя, тип и ключ файла — только в конверте.
	Blobs []string `json:"blobs,omitempty"`
}

// MaxBlobsPerMessage — предел вложений в одном сообщении.
const MaxBlobsPerMessage = 4

// MaxGroupMembers — предел числа получателей одного группового сообщения.
const MaxGroupMembers = 200

// InboxItem — элемент входящих.
type InboxItem struct {
	ID       int64     `json:"id"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	MsgID    string    `json:"msg_id"`
	Envelope *Envelope `json:"envelope"`
	At       int64     `json:"at"`

	Group     int64  `json:"group,omitempty"`
	GroupName string `json:"group_name,omitempty"`
}

// MaxEnvelopeBytes — предел размера одного конверта.
const MaxEnvelopeBytes = 128 << 10

// VerifyPost проверяет, что конверт подписан доверенным устройством отправителя.
// cert — сертификат env.SenderID из реестра отправителя (уже проверенный State.Trusted).
func VerifyPost(p *InboxPost, cert Certificate) error {
	if p == nil || p.Envelope == nil || p.MsgID == "" || !ValidLogin(p.From) {
		return fmt.Errorf("%w: запрос доставки", ErrFormat)
	}
	if p.Group != 0 {
		if p.To != "" || len(p.Members) == 0 || len(p.Members) > MaxGroupMembers {
			return fmt.Errorf("%w: получатели группы", ErrFormat)
		}
		for _, m := range p.Members {
			if !ValidLogin(m) {
				return fmt.Errorf("%w: участник %q", ErrFormat, m)
			}
		}
	} else if !ValidLogin(p.To) {
		return fmt.Errorf("%w: получатель", ErrFormat)
	}
	if len(p.Blobs) > MaxBlobsPerMessage {
		return fmt.Errorf("%w: слишком много вложений", ErrFormat)
	}
	for _, b := range p.Blobs {
		if !ValidBlobID(b) {
			return fmt.Errorf("%w: идентификатор вложения", ErrFormat)
		}
	}
	if cert.Login != p.From || cert.DeviceID != p.Envelope.SenderID {
		return fmt.Errorf("%w: отправитель не совпадает с сертификатом", ErrSignature)
	}
	if p.Envelope.Version != MessageVersion {
		return fmt.Errorf("%w: версия конверта", ErrFormat)
	}
	if !ed25519.Verify(cert.SignPub, p.Envelope.signedBytes(), p.Envelope.Sig) {
		return ErrSignature
	}
	return nil
}

// Домены подписи запросов устройства к облаку.
const (
	DomainInboxFetch    = "syne-inbox-fetch-v1"
	DomainRequestsFetch = "syne-requests-fetch-v1" // список ожидающих запросов (только доверенным)
)

func fetchBytes(domain, login string, after int64, ts int64) []byte {
	return newEnc(domain).str(login).u64(uint64(after)).u64(uint64(ts)).b
}

// FetchAuth — подпись запроса входящих устройством.
type FetchAuth struct {
	DeviceID string `json:"device_id"`
	TS       int64  `json:"ts"`
	Sig      []byte `json:"sig"`
}

// SignFetch подписывает запрос «отдайте входящие login после after».
func (d *DeviceKey) SignFetch(login string, after int64, now time.Time) FetchAuth {
	return d.SignAction(DomainInboxFetch, login, after, now)
}

// SignAction подписывает запрос к облаку в заданном домене.
func (d *DeviceKey) SignAction(domain, login string, after int64, now time.Time) FetchAuth {
	ts := now.Unix()
	return FetchAuth{DeviceID: d.DeviceID(), TS: ts, Sig: d.Sign(fetchBytes(domain, login, after, ts))}
}

// FetchWindow — допустимое расхождение часов при проверке запроса.
const FetchWindow = 5 * time.Minute

// VerifyFetch проверяет подпись запроса и свежесть метки времени. cert — сертификат
// a.DeviceID из реестра login (уже проверенный Trusted).
func VerifyFetch(a FetchAuth, login string, after int64, cert Certificate, now time.Time) error {
	return VerifyAction(DomainInboxFetch, a, login, after, cert, now)
}

// VerifyAction — как VerifyFetch для любого домена.
func VerifyAction(domain string, a FetchAuth, login string, after int64, cert Certificate, now time.Time) error {
	if cert.Login != login || cert.DeviceID != a.DeviceID {
		return fmt.Errorf("%w: устройство не из реестра %s", ErrSignature, login)
	}
	if d := now.Sub(time.Unix(a.TS, 0)); d > FetchWindow || d < -FetchWindow {
		return fmt.Errorf("%w: метка времени вне окна", ErrSignature)
	}
	if !ed25519.Verify(cert.SignPub, fetchBytes(domain, login, after, a.TS), a.Sig) {
		return ErrSignature
	}
	return nil
}

// Binding — подписанная связь «аккаунт Syne Web ↔ идентичность Hub». Её создаёт доверенное
// устройство (Study) при привязке аккаунта; облако проверяет подпись по зеркалу реестра, поэтому
// сам подделать связь не может (иначе оно могло бы подсунуть телефону чужой логин).
type Binding struct {
	HubLogin  string `json:"hub_login"`
	AccountID string `json:"account_id"` // идентификатор аккаунта облака (Syne Web Account)
	At        int64  `json:"at"`
	DeviceID  string `json:"device_id"`
	Sig       []byte `json:"sig"`
}

func (b Binding) signedBytes() []byte {
	return newEnc("syne-account-binding-v1").str(b.HubLogin).str(b.AccountID).u64(uint64(b.At)).b
}

// SignBinding подписывает связь ключом (доверенного) устройства.
func (d *DeviceKey) SignBinding(hubLogin, accountID string, now time.Time) Binding {
	b := Binding{HubLogin: hubLogin, AccountID: accountID, At: now.Unix(), DeviceID: d.DeviceID()}
	b.Sig = d.Sign(b.signedBytes())
	return b
}

// VerifyBinding проверяет подпись и свежесть. cert — сертификат b.DeviceID из реестра b.HubLogin;
// вызывающий обязан проверить, что устройство доверенное (State.CanApprove).
func VerifyBinding(b Binding, cert Certificate, now time.Time) error {
	if cert.Login != b.HubLogin || cert.DeviceID != b.DeviceID || b.AccountID == "" {
		return fmt.Errorf("%w: связь аккаунта", ErrSignature)
	}
	if d := now.Sub(time.Unix(b.At, 0)); d > 10*time.Minute || d < -10*time.Minute {
		return fmt.Errorf("%w: метка времени вне окна", ErrSignature)
	}
	if !ed25519.Verify(cert.SignPub, b.signedBytes(), b.Sig) {
		return ErrSignature
	}
	return nil
}

// RequestDecision — подписанный отказ доверенного устройства по запросу (Rejected в Holding).
type RequestDecision struct {
	RequestID string `json:"request_id"`
	DeviceID  string `json:"device_id"` // устройство, чей запрос отклонён
	Login     string `json:"login"`
	At        int64  `json:"at"`
	By        string `json:"by"` // DeviceID подписавшего
	Sig       []byte `json:"sig"`
}

func (r RequestDecision) signedBytes() []byte {
	return newEnc("syne-request-reject-v1").str(r.RequestID).str(r.DeviceID).str(r.Login).u64(uint64(r.At)).str(r.By).b
}

func (d *DeviceKey) SignReject(login, requestID, targetDeviceID string, now time.Time) RequestDecision {
	r := RequestDecision{RequestID: requestID, DeviceID: targetDeviceID, Login: login, At: now.Unix(), By: d.DeviceID()}
	r.Sig = d.Sign(r.signedBytes())
	return r
}

func VerifyReject(r RequestDecision, cert Certificate, now time.Time) error {
	if cert.Login != r.Login || cert.DeviceID != r.By {
		return fmt.Errorf("%w: отказ", ErrSignature)
	}
	if d := now.Sub(time.Unix(r.At, 0)); d > FetchWindow*2 || d < -FetchWindow*2 {
		return fmt.Errorf("%w: метка времени вне окна", ErrSignature)
	}
	if !ed25519.Verify(cert.SignPub, r.signedBytes(), r.Sig) {
		return ErrSignature
	}
	return nil
}
