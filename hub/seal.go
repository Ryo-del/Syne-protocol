package hub

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// MessageVersion — версия формата зашифрованного сообщения (protocol_version).
// 1 — старые личные чаты (ECDH identity-ключей), 2 — шифрование на устройства.
const MessageVersion = 2

var (
	ErrNotForMe = errors.New("hub: сообщение не адресовано этому устройству")
	ErrDecrypt  = errors.New("hub: не удалось расшифровать")
)

// Wrapped — ключ сообщения, зашифрованный для одного устройства.
type Wrapped struct {
	DeviceID string `json:"device_id"`
	EphPub   []byte `json:"eph_pub"`
	Nonce    []byte `json:"nonce"`
	Key      []byte `json:"key"`
}

// Envelope — сообщение, зашифрованное на каждое устройство получателя и на свои
// остальные устройства. Сервер и облако хранят и пересылают только его.
//
// ВАЖНО: это «запечатывание» без храповика (нет прямой секретности между сообщениями
// и защиты после компрометации). Оно использует только стандартные примитивы
// (X25519, HKDF-SHA256, ChaCha20-Poly1305, Ed25519), но по RFC §7.1 целевой
// протокол — libsignal/MLS; Envelope — переходный формат, см. 09-выбор-библиотек.
type Envelope struct {
	Version    int       `json:"v"`
	SenderID   string    `json:"sender_device"`
	Context    []byte    `json:"context"` // например chatID; входит в подпись и AAD
	Recipients []Wrapped `json:"recipients"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
	Sig        []byte    `json:"sig"`
}

func (e *Envelope) signedBytes() []byte {
	enc := newEnc("syne-envelope-v2").u64(uint64(e.Version)).str(e.SenderID).bytes(e.Context).
		bytes(e.Nonce).bytes(e.Ciphertext)
	for _, r := range e.Recipients {
		enc.str(r.DeviceID).bytes(r.EphPub).bytes(r.Nonce).bytes(r.Key)
	}
	return enc.b
}

func wrapKey(shared, ephPub, recipAgree []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, append(append([]byte{}, ephPub...), recipAgree...), []byte("syne-seal-wrap-v1"))
	k := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}

func wrapAAD(senderID, recipID string, ctx []byte) []byte {
	return newEnc("syne-seal-aad-v1").str(senderID).str(recipID).bytes(ctx).b
}

// Seal шифрует plaintext для устройств recipients. Вызывающий обязан передать ТОЛЬКО
// сертификаты, проверенные по реестру (State.Trusted) — в том числе свои собственные
// другие устройства, иначе они не прочитают сообщение.
func Seal(plaintext, context []byte, sender *DeviceKey, recipients []Certificate) (*Envelope, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: нет получателей", ErrFormat)
	}
	msgKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(msgKey); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}
	env := &Envelope{Version: MessageVersion, SenderID: sender.DeviceID(), Context: context,
		Nonce: make([]byte, chacha20poly1305.NonceSize)}
	if _, err := rand.Read(env.Nonce); err != nil {
		return nil, err
	}
	env.Ciphertext = aead.Seal(nil, env.Nonce, plaintext, newEnc("syne-seal-body-v1").str(env.SenderID).bytes(context).b)

	seen := map[string]bool{}
	for _, rc := range recipients {
		if seen[rc.DeviceID] {
			continue
		}
		seen[rc.DeviceID] = true
		pub, err := ecdh.X25519().NewPublicKey(rc.AgreePub)
		if err != nil {
			return nil, fmt.Errorf("%w: ключ устройства %s", ErrFormat, rc.DeviceID)
		}
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		shared, err := eph.ECDH(pub)
		if err != nil {
			return nil, err
		}
		wk, err := wrapKey(shared, eph.PublicKey().Bytes(), rc.AgreePub)
		if err != nil {
			return nil, err
		}
		waead, err := chacha20poly1305.New(wk)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		env.Recipients = append(env.Recipients, Wrapped{
			DeviceID: rc.DeviceID, EphPub: eph.PublicKey().Bytes(), Nonce: nonce,
			Key: waead.Seal(nil, nonce, msgKey, wrapAAD(env.SenderID, rc.DeviceID, context)),
		})
	}
	env.Sig = sender.Sign(env.signedBytes())
	return env, nil
}

// Open расшифровывает сообщение на устройстве me. senderCert — сертификат отправителя,
// ранее проверенный по реестру (State.Trusted); здесь проверяется подпись конверта.
func Open(env *Envelope, me *DeviceKey, senderCert Certificate) ([]byte, error) {
	if env.Version != MessageVersion {
		return nil, fmt.Errorf("%w: версия сообщения %d", ErrFormat, env.Version)
	}
	if senderCert.DeviceID != env.SenderID {
		return nil, fmt.Errorf("%w: отправитель не совпадает с сертификатом", ErrSignature)
	}
	if !ed25519.Verify(senderCert.SignPub, env.signedBytes(), env.Sig) {
		return nil, ErrSignature
	}
	var w *Wrapped
	for i := range env.Recipients {
		if env.Recipients[i].DeviceID == me.DeviceID() {
			w = &env.Recipients[i]
			break
		}
	}
	if w == nil {
		return nil, ErrNotForMe
	}
	eph, err := ecdh.X25519().NewPublicKey(w.EphPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	shared, err := me.agree.ECDH(eph)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	wk, err := wrapKey(shared, w.EphPub, me.AgreePub)
	if err != nil {
		return nil, err
	}
	waead, err := chacha20poly1305.New(wk)
	if err != nil {
		return nil, err
	}
	msgKey, err := waead.Open(nil, w.Nonce, w.Key, wrapAAD(env.SenderID, w.DeviceID, env.Context))
	if err != nil {
		return nil, ErrDecrypt
	}
	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, env.Nonce, env.Ciphertext, newEnc("syne-seal-body-v1").str(env.SenderID).bytes(env.Context).b)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
