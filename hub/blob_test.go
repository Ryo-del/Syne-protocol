package hub

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func sealBytes(t *testing.T, key, data []byte) ([]byte, BlobInfo) {
	var out bytes.Buffer
	info, err := SealBlob(key, bytes.NewReader(data), &out)
	if err != nil {
		t.Fatal(err)
	}
	if int64(out.Len()) != info.EncSize || info.EncSize != BlobSize(int64(len(data))) {
		t.Fatalf("размер блоба %d, ожидалось %d", out.Len(), BlobSize(int64(len(data))))
	}
	return out.Bytes(), info
}

func TestBlobRoundtripSizes(t *testing.T) {
	key, _ := NewBlobKey()
	for _, n := range []int{0, 1, BlobChunk - 1, BlobChunk, BlobChunk + 1, 3 * BlobChunk, 3*BlobChunk + 17} {
		data := make([]byte, n)
		rand.Read(data)
		blob, info := sealBytes(t, key, data)
		var out bytes.Buffer
		got, err := OpenBlob(key, bytes.NewReader(blob), &out)
		if err != nil || !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("размер %d: %v", n, err)
		}
		if got.SHA256 != info.SHA256 || got.BlobID != info.BlobID || got.Size != int64(n) {
			t.Fatalf("размер %d: итоги не совпали %+v %+v", n, got, info)
		}
	}
}

func TestBlobTamperTruncateReorder(t *testing.T) {
	key, _ := NewBlobKey()
	data := make([]byte, 3*BlobChunk+100)
	rand.Read(data)
	blob, _ := sealBytes(t, key, data)
	open := func(b []byte, k []byte) error {
		_, err := OpenBlob(k, bytes.NewReader(b), &bytes.Buffer{})
		return err
	}
	if err := open(blob, key); err != nil {
		t.Fatal(err)
	}
	other, _ := NewBlobKey()
	if !errors.Is(open(blob, other), ErrDecrypt) {
		t.Fatal("чужой ключ должен давать отказ")
	}
	flipped := append([]byte{}, blob...)
	flipped[BlobHeader+500] ^= 1
	if !errors.Is(open(flipped, key), ErrDecrypt) {
		t.Fatal("изменённый байт должен давать отказ")
	}
	full := BlobChunk + blobTag
	// Усечение: отрезан последний кусок целиком — у нового последнего флаг last не тот.
	if err := open(blob[:BlobHeader+3*full], key); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("усечённый блоб должен давать отказ: %v", err)
	}
	// Отрезан кусок посреди последнего.
	if err := open(blob[:len(blob)-5], key); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("оборванный блоб: %v", err)
	}
	// Перестановка двух кусков.
	sw := append([]byte{}, blob...)
	a, b := BlobHeader, BlobHeader+full
	tmp := append([]byte{}, sw[a:a+full]...)
	copy(sw[a:a+full], sw[b:b+full])
	copy(sw[b:b+full], tmp)
	if !errors.Is(open(sw, key), ErrDecrypt) {
		t.Fatal("перестановка кусков должна давать отказ")
	}
	// Лишний хвост за последним куском.
	if open(append(append([]byte{}, blob...), 1, 2, 3), key) == nil {
		t.Fatal("лишние байты должны давать отказ")
	}
	if !errors.Is(open([]byte("мусор"), key), ErrFormat) {
		t.Fatal("мусор вместо блоба — ошибка формата")
	}
}

func TestAttachmentRoundtripAndValidation(t *testing.T) {
	key, _ := NewBlobKey()
	data := []byte("содержимое файла")
	_, info := sealBytes(t, key, data)
	a := NewAttachment(AttachKindFile, "Отчёт.txt", "text/plain", key, info)
	a.Caption = "смотри"
	raw, err := EncodeAttachment(a)
	if err != nil || !IsAttachment(raw) {
		t.Fatal(err)
	}
	got, err := DecodeAttachment(raw)
	if err != nil || got.Name != "Отчёт.txt" || got.Blob != info.BlobID || !bytes.Equal(got.Key, key) {
		t.Fatalf("%+v %v", got, err)
	}
	if err := got.Validate(10, MaxThumb); err == nil {
		t.Fatal("размер больше предела должен отклоняться")
	}
	bad := []func(*Attachment){
		func(x *Attachment) { x.Name = "../etc/passwd" },
		func(x *Attachment) { x.Name = "a\x00b" },
		func(x *Attachment) { x.Kind = "exe" },
		func(x *Attachment) { x.Key = x.Key[:16] },
		func(x *Attachment) { x.Blob = "XYZ" },
		func(x *Attachment) { x.EncSize++ },
		func(x *Attachment) { x.Chunk = 1024 },
		func(x *Attachment) { x.Thumb = []byte("x") }, // миниатюра у файла
	}
	for i, mut := range bad {
		x := a
		x.Key = append([]byte{}, a.Key...)
		mut(&x)
		if err := x.Validate(0, MaxThumb); !errors.Is(err, ErrFormat) {
			t.Fatalf("случай %d должен отклоняться: %v", i, err)
		}
	}
	p := NewAttachment(AttachKindPic, "p.jpg", "image/jpeg", key, info)
	p.Thumb = make([]byte, MaxThumbGroup+1)
	if p.Validate(0, MaxThumbGroup) == nil || p.Validate(0, MaxThumb) != nil {
		t.Fatal("предел миниатюры зависит от беседы")
	}
	if _, err := DecodeAttachment([]byte("обычный текст")); !errors.Is(err, ErrFormat) {
		t.Fatal("обычный текст не вложение")
	}
}

func TestBlobSignature(t *testing.T) {
	dev, _ := GenerateDeviceKey()
	cert := Certificate{Login: "a@org1", DeviceID: dev.DeviceID(), SignPub: dev.SignPub}
	id := "ab" + string(bytes.Repeat([]byte("0"), 62))
	now := time.Now()
	a := dev.SignBlob(DomainBlobPut, "a@org1", id, 1000, now)
	if err := VerifyBlob(DomainBlobPut, a, "a@org1", id, 1000, cert, now); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"другой размер": VerifyBlob(DomainBlobPut, a, "a@org1", id, 1001, cert, now),
		"другой домен":  VerifyBlob(DomainBlobGet, a, "a@org1", id, 1000, cert, now),
		"другой блоб":   VerifyBlob(DomainBlobPut, a, "a@org1", "cd"+id[2:], 1000, cert, now),
		"устарел":       VerifyBlob(DomainBlobPut, a, "a@org1", id, 1000, cert, now.Add(time.Hour)),
		"другой логин":  VerifyBlob(DomainBlobPut, a, "b@org1", id, 1000, cert, now),
	} {
		if err == nil {
			t.Fatalf("%s: подпись не должна проходить", name)
		}
	}
}
