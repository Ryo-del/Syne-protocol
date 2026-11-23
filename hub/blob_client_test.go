package hub

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCloud — облако с блобами: проверяет подпись устройства, ведёт докачку.
type fakeCloud struct {
	t        *testing.T
	f        *fixture
	mu       sync.Mutex
	data     map[string][]byte
	done     map[string]bool
	size     map[string]int64 // размер блоба, объявленный при старте загрузки
	puts     int
	inboxGot *InboxPost
}

func (fc *fakeCloud) auth(r *http.Request, domain, login, id string, size int64) bool {
	ts, _ := strconv.ParseInt(r.Header.Get("X-Hub-Ts"), 10, 64)
	sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Hub-Sig"))
	a := FetchAuth{DeviceID: r.Header.Get("X-Hub-Device"), TS: ts, Sig: sig}
	cert := fc.f.log.State().Devices[fc.f.study.DeviceID()].Cert
	return VerifyBlob(domain, a, login, id, size, cert, t0) == nil
}

func (fc *fakeCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/hub/")
	switch {
	case r.Method == "POST" && path == "inbox":
		var p InboxPost
		_ = json.NewDecoder(r.Body).Decode(&p)
		fc.inboxGot = &p
		reply(200, map[string]bool{"ok": true})
	case r.Method == "POST" && path == "blobs":
		var b struct {
			From, Blob string
			Size       int64
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if !fc.auth(r, DomainBlobPut, b.From, b.Blob, b.Size) {
			reply(403, map[string]string{"error": "forbidden"})
			return
		}
		fc.size[b.Blob] = b.Size
		reply(200, map[string]any{"received": len(fc.data[b.Blob]), "complete": fc.done[b.Blob]})
	case r.Method == "PUT" && strings.HasPrefix(path, "blobs/"):
		id := strings.TrimPrefix(path, "blobs/")
		login := r.URL.Query().Get("from")
		off, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		body, _ := io.ReadAll(r.Body)
		if !fc.auth(r, DomainBlobPut, login, id, fc.size[id]) {
			reply(403, map[string]string{"error": "forbidden"})
			return
		}
		if off != int64(len(fc.data[id])) {
			reply(409, map[string]any{"error": "offset_mismatch", "received": len(fc.data[id])})
			return
		}
		fc.puts++
		fc.data[id] = append(fc.data[id], body...)
		reply(200, map[string]any{"received": len(fc.data[id])})
	case r.Method == "POST" && strings.HasSuffix(path, "/complete"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "blobs/"), "/complete")
		fc.done[id] = true
		reply(200, map[string]bool{"ok": true})
	case r.Method == "GET" && strings.HasPrefix(path, "blobs/"):
		id := strings.TrimPrefix(path, "blobs/")
		if !fc.auth(r, DomainBlobGet, r.URL.Query().Get("login"), id, 0) {
			reply(403, map[string]string{"error": "forbidden"})
			return
		}
		if !fc.done[id] {
			reply(404, map[string]string{"error": "not_found"})
			return
		}
		_, _ = w.Write(fc.data[id])
	default:
		reply(404, map[string]string{"error": "not_found"})
	}
}

func newTestClient(t *testing.T, srv string, f *fixture) *Client {
	c := NewClient(nil, Blobber{}, "Study")
	c.login, c.cloudURL, c.dev, c.state = "ivan@school1", srv, f.study, StateReady
	c.now = func() time.Time { return t0 }
	return c
}

func sealRandom(t *testing.T, n int) (key, plain, blob []byte, info BlobInfo) {
	plain = make([]byte, n)
	_, _ = rand.Read(plain)
	key, err := NewBlobKey()
	must(t, err)
	var buf bytes.Buffer
	info, err = SealBlob(key, bytes.NewReader(plain), &buf)
	must(t, err)
	return key, plain, buf.Bytes(), info
}

func TestBlobUploadDownloadRoundTrip(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	fc := &fakeCloud{t: t, f: f, data: map[string][]byte{}, done: map[string]bool{}, size: map[string]int64{}}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	c := newTestClient(t, srv.URL, f)

	key, plain, blob, info := sealRandom(t, 5<<20) // больше одной части (4 МБ)
	if err := c.BlobUpload(context.Background(), bytes.NewReader(blob), info); err != nil {
		t.Fatal(err)
	}
	if fc.puts < 2 || !fc.done[info.BlobID] {
		t.Fatalf("ожидали несколько частей и завершение: puts=%d done=%v", fc.puts, fc.done[info.BlobID])
	}
	rc, err := c.BlobDownload(context.Background(), info.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var out bytes.Buffer
	got, err := OpenBlob(key, rc, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != info.SHA256 || !bytes.Equal(out.Bytes(), plain) {
		t.Fatal("скачанный файл не совпал с исходным")
	}
}

func TestBlobUploadResumes(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	_, _, blob, info := sealRandom(t, 6<<20)
	fc := &fakeCloud{t: t, f: f, data: map[string][]byte{info.BlobID: append([]byte(nil), blob[:blobUploadChunk]...)}, done: map[string]bool{}, size: map[string]int64{}}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	c := newTestClient(t, srv.URL, f)
	if err := c.BlobUpload(context.Background(), bytes.NewReader(blob), info); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fc.data[info.BlobID], blob) {
		t.Fatal("после докачки блоб в облаке отличается")
	}
	if fc.puts != 1 {
		t.Fatalf("первую часть повторно слать не нужно: puts=%d", fc.puts)
	}
}

func TestBlobDownloadRejectsBadID(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	c := newTestClient(t, "http://127.0.0.1:1", f)
	if _, err := c.BlobDownload(context.Background(), "../../etc/passwd"); !errors.Is(err, ErrFormat) {
		t.Fatalf("ожидали ErrFormat, получили %v", err)
	}
}

func TestBlobNeedsReadyDevice(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	c := newTestClient(t, "http://127.0.0.1:1", f)
	c.state = StateAwaiting
	_, info := func() (int, BlobInfo) { _, _, _, i := sealRandom(t, 10); return 0, i }()
	if err := c.BlobUpload(context.Background(), bytes.NewReader(nil), info); !errors.Is(err, ErrNotReady) {
		t.Fatalf("ожидали ErrNotReady, получили %v", err)
	}
}

func TestPostToInboxCarriesBlobs(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	fc := &fakeCloud{t: t, f: f, data: map[string][]byte{}, done: map[string]bool{}, size: map[string]int64{}}
	srv := httptest.NewServer(fc)
	defer srv.Close()
	c := newTestClient(t, srv.URL, f)
	id := strings.Repeat("ab", 32)
	if err := c.PostToInboxBlobs(context.Background(), "petya@school1", &Envelope{}, "m1", []string{id}); err != nil {
		t.Fatal(err)
	}
	if fc.inboxGot == nil || len(fc.inboxGot.Blobs) != 1 || fc.inboxGot.Blobs[0] != id {
		t.Fatalf("блоб не попал в запрос доставки: %+v", fc.inboxGot)
	}
}
