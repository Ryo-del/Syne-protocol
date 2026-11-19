package hub

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Вложения Key Hub (файл 13): файл шифруется отдельным ключом потоково, зашифрованный блоб лежит
// в облаке, а ключ и описание — внутри зашифрованного сообщения (Attachment).

const (
	BlobMagic    = "SYNEBLB1"
	BlobChunk    = 64 << 10 // размер куска открытых данных
	BlobKeySize  = chacha20poly1305.KeySize
	BlobHeader   = 12 // magic(8) + chunk_size(4)
	blobTag      = chacha20poly1305.Overhead
	blobAADLabel = "syne-blob-chunk-v1"

	// Домены подписи запросов блобов устройством.
	DomainBlobPut = "syne-blob-put-v1"
	DomainBlobGet = "syne-blob-get-v1"
)

// BlobSize — размер зашифрованного блоба для файла в size байт.
func BlobSize(size int64) int64 {
	n := (size + BlobChunk - 1) / BlobChunk
	if n == 0 {
		n = 1 // пустой файл — один пустой кусок
	}
	return BlobHeader + n*blobTag + size
}

// NewBlobKey создаёт ключ файла (один на файл).
func NewBlobKey() ([]byte, error) {
	k := make([]byte, BlobKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// BlobInfo — итог шифрования или расшифровки.
type BlobInfo struct {
	Size    int64  // размер открытого файла
	SHA256  string // SHA-256 открытого файла, hex
	EncSize int64  // размер блоба
	BlobID  string // SHA-256 блоба, hex (идентификатор в облаке)
}

func chunkNonce(i uint32, last bool) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint32(n[7:11], i)
	if last {
		n[11] = 1
	}
	return n
}

// readFull читает до len(buf) байт; n < len(buf) значит, что поток закончился.
func readFull(r io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return n, nil
	}
	return n, err
}

// SealBlob шифрует поток r ключом key и пишет блоб в w. Весь файл в памяти не держится.
func SealBlob(key []byte, r io.Reader, w io.Writer) (BlobInfo, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return BlobInfo{}, fmt.Errorf("%w: ключ файла", ErrFormat)
	}
	blobHash, plainHash := sha256.New(), sha256.New()
	out := io.MultiWriter(w, blobHash)
	hdr := binary.BigEndian.AppendUint32([]byte(BlobMagic), BlobChunk)
	if _, err := out.Write(hdr); err != nil {
		return BlobInfo{}, err
	}
	info := BlobInfo{EncSize: BlobHeader}
	cur, next := make([]byte, BlobChunk), make([]byte, BlobChunk)
	n, err := readFull(r, cur)
	if err != nil {
		return BlobInfo{}, err
	}
	for i := uint32(0); ; i++ {
		m, err := 0, error(nil)
		if n == BlobChunk { // кусок полный: узнаём, есть ли за ним ещё данные
			if m, err = readFull(r, next); err != nil {
				return BlobInfo{}, err
			}
		}
		last := m == 0
		plainHash.Write(cur[:n])
		ct := aead.Seal(nil, chunkNonce(i, last), cur[:n], []byte(blobAADLabel))
		if _, err := out.Write(ct); err != nil {
			return BlobInfo{}, err
		}
		info.Size += int64(n)
		info.EncSize += int64(len(ct))
		if last {
			break
		}
		cur, next, n = next, cur, m
	}
	info.SHA256 = hex.EncodeToString(plainHash.Sum(nil))
	info.BlobID = hex.EncodeToString(blobHash.Sum(nil))
	return info, nil
}

// OpenBlob расшифровывает блоб из r и пишет открытый файл в w. Каждый кусок проверяется сразу, но
// усечение хвоста видно только в конце: пишите во временный файл и переименовывайте после успеха.
func OpenBlob(key []byte, r io.Reader, w io.Writer) (BlobInfo, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return BlobInfo{}, fmt.Errorf("%w: ключ файла", ErrFormat)
	}
	blobHash, plainHash := sha256.New(), sha256.New()
	tr := io.TeeReader(r, blobHash)
	hdr := make([]byte, BlobHeader)
	if n, err := readFull(tr, hdr); err != nil || n != BlobHeader ||
		string(hdr[:8]) != BlobMagic || binary.BigEndian.Uint32(hdr[8:]) != BlobChunk {
		return BlobInfo{}, fmt.Errorf("%w: заголовок блоба", ErrFormat)
	}
	info := BlobInfo{EncSize: BlobHeader}
	full := BlobChunk + blobTag
	cur, next := make([]byte, full), make([]byte, full)
	n, err := readFull(tr, cur)
	if err != nil {
		return BlobInfo{}, err
	}
	for i := uint32(0); ; i++ {
		m := 0
		if n == full {
			if m, err = readFull(tr, next); err != nil {
				return BlobInfo{}, err
			}
		}
		last := m == 0
		if n < blobTag {
			return BlobInfo{}, fmt.Errorf("%w: блоб оборван", ErrDecrypt)
		}
		pt, err := aead.Open(nil, chunkNonce(i, last), cur[:n], []byte(blobAADLabel))
		if err != nil {
			return BlobInfo{}, fmt.Errorf("%w: кусок %d", ErrDecrypt, i)
		}
		plainHash.Write(pt)
		if _, err := w.Write(pt); err != nil {
			return BlobInfo{}, err
		}
		info.Size += int64(len(pt))
		info.EncSize += int64(n)
		if last {
			break
		}
		cur, next, n = next, cur, m
	}
	info.SHA256 = hex.EncodeToString(plainHash.Sum(nil))
	info.BlobID = hex.EncodeToString(blobHash.Sum(nil))
	return info, nil
}

// ── подпись запросов блобов ──

func blobBytes(domain, login, blobID string, size int64, ts int64) []byte {
	return newEnc(domain).str(login).str(blobID).u64(uint64(size)).u64(uint64(ts)).b
}

// SignBlob подписывает запрос к блобу (домен DomainBlobPut или DomainBlobGet). size — размер блоба
// при загрузке, при скачивании 0.
func (d *DeviceKey) SignBlob(domain, login, blobID string, size int64, now time.Time) FetchAuth {
	ts := now.Unix()
	return FetchAuth{DeviceID: d.DeviceID(), TS: ts, Sig: d.Sign(blobBytes(domain, login, blobID, size, ts))}
}

// VerifyBlob проверяет подпись запроса блоба; cert — сертификат a.DeviceID из реестра login.
func VerifyBlob(domain string, a FetchAuth, login, blobID string, size int64, cert Certificate, now time.Time) error {
	if cert.Login != login || cert.DeviceID != a.DeviceID {
		return fmt.Errorf("%w: устройство не из реестра %s", ErrSignature, login)
	}
	if d := now.Sub(time.Unix(a.TS, 0)); d > FetchWindow || d < -FetchWindow {
		return fmt.Errorf("%w: метка времени вне окна", ErrSignature)
	}
	if !ed25519.Verify(cert.SignPub, blobBytes(domain, login, blobID, size, a.TS), a.Sig) {
		return ErrSignature
	}
	return nil
}

// ValidBlobID — 64 hex-символа нижнего регистра.
func ValidBlobID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
