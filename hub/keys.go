package hub

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// RootKey — корень доверия Hub. Создаётся один раз; после подписи сертификата
// первого устройства его нужно убрать с устройства и сохранить для восстановления
// (см. recovery.go). В повседневной работе не используется.
type RootKey struct {
	Pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func GenerateRootKey() (*RootKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &RootKey{Pub: pub, priv: priv}, nil
}

// RootKeyFromSeed восстанавливает корневой ключ из 32-байтного seed.
func RootKeyFromSeed(seed []byte) (*RootKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed должен быть %d байт", ErrFormat, ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &RootKey{Pub: priv.Public().(ed25519.PublicKey), priv: priv}, nil
}

func (r *RootKey) Seed() []byte { return r.priv.Seed() }

// HubID — идентификатор Hub: хэш публичного корневого ключа. Смена HubID у логина
// означает сброс идентичности, и собеседники должны об этом узнать.
func (r *RootKey) HubID() string { return HubIDOf(r.Pub) }

func HubIDOf(rootPub ed25519.PublicKey) string {
	h := sha256.Sum256(append([]byte("syne-hub-id-v1"), rootPub...))
	return hex.EncodeToString(h[:16])
}

// DeviceKey — ключи одного устройства. Приватные части с устройства не уходят.
type DeviceKey struct {
	SignPub  ed25519.PublicKey
	AgreePub []byte
	signPriv ed25519.PrivateKey
	agree    *ecdh.PrivateKey
}

func GenerateDeviceKey() (*DeviceKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	agree, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DeviceKey{SignPub: pub, AgreePub: agree.PublicKey().Bytes(), signPriv: priv, agree: agree}, nil
}

// Marshal / UnmarshalDeviceKey — хранение в защищённом хранилище ОС (Keychain и т. п.).
func (d *DeviceKey) Marshal() []byte {
	return append(append([]byte{}, d.signPriv.Seed()...), d.agree.Bytes()...)
}

func UnmarshalDeviceKey(raw []byte) (*DeviceKey, error) {
	if len(raw) != ed25519.SeedSize+32 {
		return nil, fmt.Errorf("%w: ключ устройства неверной длины", ErrFormat)
	}
	priv := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	agree, err := ecdh.X25519().NewPrivateKey(raw[ed25519.SeedSize:])
	if err != nil {
		return nil, err
	}
	return &DeviceKey{
		SignPub: priv.Public().(ed25519.PublicKey), AgreePub: agree.PublicKey().Bytes(),
		signPriv: priv, agree: agree,
	}, nil
}

func (d *DeviceKey) DeviceID() string { return DeviceIDOf(d.SignPub, d.AgreePub) }

func (d *DeviceKey) Sign(msg []byte) []byte { return ed25519.Sign(d.signPriv, msg) }

// DeviceIDOf — Device ID: хэш обоих публичных ключей, поэтому подменить один ключ
// при том же ID нельзя.
func DeviceIDOf(signPub ed25519.PublicKey, agreePub []byte) string {
	h := sha256.New()
	h.Write([]byte("syne-device-id-v1"))
	h.Write(signPub)
	h.Write(agreePub)
	return hex.EncodeToString(h.Sum(nil)[:16])
}
