package hub

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// ErrRecovery — неверный Recovery Key или повреждённая копия.
var ErrRecovery = errors.New("hub: не удалось восстановить корневой ключ")

// RecoveryCode — случайный код восстановления (32 байта), который пользователь хранит
// на бумаге/в менеджере паролей. Показывается один раз при создании Hub.
func NewRecoveryCode() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// WrapRoot шифрует seed корневого ключа кодом восстановления. Результат можно хранить
// где угодно (в т. ч. на сервере): без кода он бесполезен.
func WrapRoot(root *RootKey, code []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(code, salt, 1, 64*1024, 2, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, salt...), nonce...)
	return aead.Seal(out, nonce, root.Seed(), []byte("syne-root-recovery-v1")), nil
}

func UnwrapRoot(blob, code []byte) (*RootKey, error) {
	if len(blob) < 16+chacha20poly1305.NonceSize+16 {
		return nil, fmt.Errorf("%w: слишком короткая копия", ErrRecovery)
	}
	salt, nonce, ct := blob[:16], blob[16:16+chacha20poly1305.NonceSize], blob[16+chacha20poly1305.NonceSize:]
	key := argon2.IDKey(code, salt, 1, 64*1024, 2, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, ct, []byte("syne-root-recovery-v1"))
	if err != nil {
		return nil, ErrRecovery
	}
	return RootKeyFromSeed(seed)
}
