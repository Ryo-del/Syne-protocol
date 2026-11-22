package hub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// AttachPrefix — префикс тела сообщения-вложения внутри конверта (файл 13, раздел 4).
const AttachPrefix = "syne:att1:"

// Пределы разбора вложения.
const (
	MaxAttachJSON  = 32 << 10
	MaxThumb       = 16 << 10
	MaxThumbGroup  = 8 << 10
	maxAttachName  = 255
	AttachKindFile = "file"
	AttachKindPic  = "photo"
)

// Attachment — описание вложения. Лежит только внутри зашифрованного конверта: облако не видит
// ни имени, ни типа, ни ключа.
type Attachment struct {
	V       int    `json:"v"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Mime    string `json:"mime,omitempty"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Blob    string `json:"blob"`
	EncSize int64  `json:"enc_size"`
	Key     []byte `json:"key"`
	Chunk   int    `json:"chunk"`
	Caption string `json:"caption,omitempty"`
	Thumb   []byte `json:"thumb,omitempty"`
	W       int    `json:"w,omitempty"`
	H       int    `json:"h,omitempty"`
}

// IsAttachment — тело сообщения является вложением?
func IsAttachment(plaintext []byte) bool { return bytes.HasPrefix(plaintext, []byte(AttachPrefix)) }

// NewAttachment собирает описание по итогам SealBlob.
func NewAttachment(kind, name, mime string, key []byte, info BlobInfo) Attachment {
	return Attachment{V: 1, Kind: kind, Name: name, Mime: mime, Size: info.Size, SHA256: info.SHA256,
		Blob: info.BlobID, EncSize: info.EncSize, Key: key, Chunk: BlobChunk}
}

// Validate проверяет форму; maxSize > 0 — предел размера файла; thumbMax — предел миниатюры.
func (a *Attachment) Validate(maxSize int64, thumbMax int) error {
	bad := func(what string) error { return fmt.Errorf("%w: вложение: %s", ErrFormat, what) }
	switch {
	case a.V != 1:
		return bad("версия")
	case a.Kind != AttachKindFile && a.Kind != AttachKindPic:
		return bad("тип")
	case !validAttachName(a.Name):
		return bad("имя")
	case a.Size < 0 || (maxSize > 0 && a.Size > maxSize):
		return bad("размер")
	case !ValidBlobID(a.SHA256):
		return bad("sha256")
	case !ValidBlobID(a.Blob):
		return bad("blob")
	case len(a.Key) != BlobKeySize:
		return bad("ключ")
	case a.Chunk != BlobChunk:
		return bad("размер куска")
	case a.EncSize != BlobSize(a.Size):
		return bad("размер блоба")
	case len(a.Thumb) > thumbMax:
		return bad("миниатюра")
	case a.Kind != AttachKindPic && len(a.Thumb) > 0:
		return bad("миниатюра у файла")
	case len(a.Mime) > 127 || !utf8.ValidString(a.Caption):
		return bad("поля")
	}
	return nil
}

func validAttachName(n string) bool {
	if n == "" || len(n) > maxAttachName || !utf8.ValidString(n) || n == "." || n == ".." {
		return false
	}
	if strings.ContainsAny(n, "/\\") {
		return false
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// EncodeAttachment строит тело сообщения: префикс + JSON.
func EncodeAttachment(a Attachment) ([]byte, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxAttachJSON {
		return nil, fmt.Errorf("%w: вложение слишком большое", ErrFormat)
	}
	return append([]byte(AttachPrefix), raw...), nil
}

// DecodeAttachment разбирает тело сообщения. Размер файла и предел миниатюры проверяются
// вызывающим через Validate (они зависят от того, личная это беседа или группа).
func DecodeAttachment(plaintext []byte) (*Attachment, error) {
	if !IsAttachment(plaintext) {
		return nil, ErrFormat
	}
	raw := plaintext[len(AttachPrefix):]
	if len(raw) > MaxAttachJSON {
		return nil, fmt.Errorf("%w: вложение слишком большое", ErrFormat)
	}
	var a Attachment
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("%w: вложение", ErrFormat)
	}
	return &a, a.Validate(0, MaxThumb)
}
