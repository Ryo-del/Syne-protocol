package hub

import (
	"bytes"
	"encoding/json"
)

// PayloadMagic — префикс поля payload сообщения Syne, зашифрованного на устройства
// (MessageVersion 2). Остальные сообщения (старая схема: ECDH identity-ключей) его не
// содержат — так клиент различает форматы в режиме совместимости. Префикс входит в
// подписываемый payload, поэтому подменить формат нельзя.
var PayloadMagic = []byte("syne:hub2:")

func EncodePayload(env *Envelope) ([]byte, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, PayloadMagic...), raw...), nil
}

// IsHubPayload — это сообщение в формате Hub?
func IsHubPayload(payload []byte) bool { return bytes.HasPrefix(payload, PayloadMagic) }

func DecodePayload(payload []byte) (*Envelope, error) {
	if !IsHubPayload(payload) {
		return nil, ErrFormat
	}
	var env Envelope
	if err := json.Unmarshal(payload[len(PayloadMagic):], &env); err != nil {
		return nil, ErrFormat
	}
	return &env, nil
}
