package hub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
)

// SafetyNumber — номер безопасности двух пользователей: 60 цифр (12 групп по 5),
// одинаковый у обоих. Пользователи сверяют его вживую или по другому каналу; при
// сбросе идентичности у одного из них номер меняется.
func SafetyNumber(loginA string, rootA ed25519.PublicKey, loginB string, rootB ed25519.PublicKey) string {
	a := safetyHalf(loginA, rootA)
	b := safetyHalf(loginB, rootB)
	if a > b {
		a, b = b, a
	}
	return a + " " + b
}

func safetyHalf(login string, root ed25519.PublicKey) string {
	h := sha256.Sum256(append([]byte("syne-safety-v1|"+login+"|"), root...))
	var groups []string
	for i := 0; i < 6; i++ {
		v := (uint32(h[i*4])<<24 | uint32(h[i*4+1])<<16 | uint32(h[i*4+2])<<8 | uint32(h[i*4+3])) % 100000
		groups = append(groups, fmt.Sprintf("%05d", v))
	}
	return strings.Join(groups, " ")
}

// PairCode — короткий код подтверждения регистрации устройства (6 цифр) из публичных
// ключей запроса: пользователь видит его на новом устройстве и сверяет с экраном
// поручителя. Сервер не может подменить ключи в запросе, не изменив код.
func (r CertRequest) PairCode() string {
	h := sha256.Sum256(newEnc("syne-pair-code-v1").str(r.Login).bytes(r.SignPub).bytes(r.AgreePub).str(r.Code).b)
	v := (uint32(h[0])<<16 | uint32(h[1])<<8 | uint32(h[2])) % 1000000
	return fmt.Sprintf("%06d", v)
}
