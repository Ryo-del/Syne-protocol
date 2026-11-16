// Package hub — Syne Key Hub: цепочка доверия устройств пользователя, подписанный
// журнал реестра, отзыв устройств, номера безопасности и шифрование сообщений на
// каждое устройство получателя (RFC v0.2, файл 06).
//
// Пакет не знает про сеть и хранилище: им пользуются Syne Server (основной реестр,
// проверка подписей), Syne Cloud (зеркало), Syne Study и Syne Mobile (устройства).
package hub

import (
	"encoding/binary"
	"errors"
)

// Version формата записей. Меняется при несовместимых изменениях.
const Version = 1

var (
	ErrFormat    = errors.New("hub: неверный формат")
	ErrSignature = errors.New("hub: неверная подпись")
)

// enc — каноническая сериализация: поля идут в фиксированном порядке, каждое с
// префиксом длины. Подпись считается по этим байтам, а не по JSON, поэтому порядок
// ключей и пробелы не влияют на проверку.
type enc struct{ b []byte }

func newEnc(domain string) *enc {
	e := &enc{}
	e.str(domain)
	return e
}

func (e *enc) u64(v uint64) *enc {
	e.b = binary.BigEndian.AppendUint64(e.b, v)
	return e
}

func (e *enc) bytes(v []byte) *enc {
	e.b = binary.BigEndian.AppendUint32(e.b, uint32(len(v)))
	e.b = append(e.b, v...)
	return e
}

func (e *enc) str(v string) *enc { return e.bytes([]byte(v)) }
