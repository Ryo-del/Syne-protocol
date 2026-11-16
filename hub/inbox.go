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
}

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

func fetchBytes(login string, after int64, ts int64) []byte {
	return newEnc("syne-inbox-fetch-v1").str(login).u64(uint64(after)).u64(uint64(ts)).b
}

// FetchAuth — подпись запроса входящих устройством.
type FetchAuth struct {
	DeviceID string `json:"device_id"`
	TS       int64  `json:"ts"`
	Sig      []byte `json:"sig"`
}

// SignFetch подписывает запрос «отдайте входящие login после after».
func (d *DeviceKey) SignFetch(login string, after int64, now time.Time) FetchAuth {
	ts := now.Unix()
	return FetchAuth{DeviceID: d.DeviceID(), TS: ts, Sig: d.Sign(fetchBytes(login, after, ts))}
}

// FetchWindow — допустимое расхождение часов при проверке запроса.
const FetchWindow = 5 * time.Minute

// VerifyFetch проверяет подпись запроса и свежесть метки времени. cert — сертификат
// a.DeviceID из реестра login (уже проверенный Trusted).
func VerifyFetch(a FetchAuth, login string, after int64, cert Certificate, now time.Time) error {
	if cert.Login != login || cert.DeviceID != a.DeviceID {
		return fmt.Errorf("%w: устройство не из реестра %s", ErrSignature, login)
	}
	if d := now.Sub(time.Unix(a.TS, 0)); d > FetchWindow || d < -FetchWindow {
		return fmt.Errorf("%w: метка времени вне окна", ErrSignature)
	}
	if !ed25519.Verify(cert.SignPub, fetchBytes(login, after, a.TS), a.Sig) {
		return ErrSignature
	}
	return nil
}
