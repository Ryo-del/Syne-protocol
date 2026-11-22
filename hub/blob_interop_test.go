package hub

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Совместимость вложений с Swift. Go создаёт векторы:
//   HUB_BLOB_OUT=/p/go.json go test ./hub -run TestGenerateBlobVectors
// Swift: HUB_BLOB_GO=/p/go.json HUB_BLOB_SWIFT_OUT=/p/swift.json swift test --filter BlobInterop
// Go читает ответ Swift: HUB_BLOB_SWIFT_IN=/p/swift.json go test ./hub -run TestSwiftBlobInterop

func blobPlain() []byte {
	b := make([]byte, 150_000) // три куска
	for i := range b {
		b[i] = byte(i * 7 % 251)
	}
	return b
}

type blobVectors struct {
	Key      []byte `json:"key"`
	Blob     []byte `json:"blob"`
	BlobID   string `json:"blob_id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Body     []byte `json:"body"`   // тело сообщения-вложения: "syne:att1:" + JSON
	Device   []byte `json:"device"` // ключ устройства (Marshal)
	DeviceID string `json:"device_id"`
	Login    string `json:"login"`
	Sig      struct {
		Domain string `json:"domain"`
		Size   int64  `json:"size"`
		TS     int64  `json:"ts"`
		Sig    []byte `json:"sig"`
	} `json:"sig"`
}

func TestGenerateBlobVectors(t *testing.T) {
	out := os.Getenv("HUB_BLOB_OUT")
	if out == "" {
		t.Skip("HUB_BLOB_OUT не задан")
	}
	key := bytes.Repeat([]byte{0x42}, BlobKeySize)
	var blob bytes.Buffer
	info, err := SealBlob(key, bytes.NewReader(blobPlain()), &blob)
	must(t, err)
	att := NewAttachment(AttachKindFile, "Отчёт.bin", "application/octet-stream", key, info)
	att.Caption = "из Go"
	body, err := EncodeAttachment(att)
	must(t, err)
	dev := detDevice(t, 50)
	v := blobVectors{Key: key, Blob: blob.Bytes(), BlobID: info.BlobID, SHA256: info.SHA256, Size: info.Size, Body: body,
		Device: dev.Marshal(), DeviceID: dev.DeviceID(), Login: "ivan@org7"}
	a := dev.SignBlob(DomainBlobPut, v.Login, info.BlobID, info.EncSize, time.Unix(1_800_000_000, 0))
	v.Sig.Domain, v.Sig.Size, v.Sig.TS, v.Sig.Sig = DomainBlobPut, info.EncSize, a.TS, a.Sig
	raw, err := json.Marshal(v)
	must(t, err)
	must(t, os.WriteFile(out, raw, 0o644))
}

type swiftBlobVectors struct {
	Blob   []byte `json:"blob"`
	BlobID string `json:"blob_id"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Body   []byte `json:"body"`
	Sig    struct {
		Login  string `json:"login"`
		Domain string `json:"domain"`
		Size   int64  `json:"size"`
		TS     int64  `json:"ts"`
		Sig    []byte `json:"sig"`
	} `json:"sig"`
	Device []byte `json:"device"`
}

func TestSwiftBlobInterop(t *testing.T) {
	in := os.Getenv("HUB_BLOB_SWIFT_IN")
	if in == "" {
		t.Skip("HUB_BLOB_SWIFT_IN не задан")
	}
	raw, err := os.ReadFile(in)
	must(t, err)
	var s swiftBlobVectors
	must(t, json.Unmarshal(raw, &s))
	key := bytes.Repeat([]byte{0x24}, BlobKeySize)
	// Блоб, зашифрованный Swift, читает Go.
	var plain bytes.Buffer
	info, err := OpenBlob(key, bytes.NewReader(s.Blob), &plain)
	must(t, err)
	if info.BlobID != s.BlobID || info.SHA256 != s.SHA256 || info.Size != s.Size || !bytes.Equal(plain.Bytes(), blobPlain()) {
		t.Fatalf("Go не прочитал блоб Swift: %+v", info)
	}
	// Описание вложения от Swift разбирается и проходит проверки.
	att, err := DecodeAttachment(s.Body)
	must(t, err)
	if att.Blob != info.BlobID || !bytes.Equal(att.Key, key) || att.EncSize != info.EncSize {
		t.Fatalf("описание вложения Swift не совпало: %+v", att)
	}
	// Подпись запроса блоба, поставленная Swift, проходит проверку.
	dev, err := UnmarshalDeviceKey(s.Device)
	must(t, err)
	cert := Certificate{Login: s.Sig.Login, DeviceID: dev.DeviceID(), SignPub: dev.SignPub}
	a := FetchAuth{DeviceID: dev.DeviceID(), TS: s.Sig.TS, Sig: s.Sig.Sig}
	must(t, VerifyBlob(s.Sig.Domain, a, s.Sig.Login, info.BlobID, s.Sig.Size, cert, time.Unix(s.Sig.TS, 0)))
}
