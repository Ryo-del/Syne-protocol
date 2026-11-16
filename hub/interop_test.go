package hub

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Векторы совместимости с реализациями на других языках (Swift для iOS).
//
//	HUB_VECTORS_OUT=/путь/vectors.json go test ./hub -run TestGenerateInteropVectors
//	HUB_SWIFT_IN=/путь/swift.json     go test ./hub -run TestSwiftInterop
//
// Ключи детерминированы, поэтому вектор воспроизводим.

func seeded(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func detDevice(t *testing.T, b byte) *DeviceKey {
	d, err := UnmarshalDeviceKey(append(seeded(b), seeded(b+100)...))
	must(t, err)
	return d
}

type vectors struct {
	Login    string `json:"login"`
	RootSeed []byte `json:"root_seed"`
	RootPub  []byte `json:"root_pub"`
	HubID    string `json:"hub_id"`
	Devices  map[string]struct {
		Raw []byte `json:"raw"`
		ID  string `json:"id"`
	} `json:"devices"`
	Entries     []Entry  `json:"entries"`
	Head        Head     `json:"head"`
	Active      []string `json:"active"`
	Revoked     []string `json:"revoked"`
	CertRequest struct {
		Req      CertRequest `json:"req"`
		PairCode string      `json:"pair_code"`
	} `json:"cert_request"`
	Safety struct {
		LoginA, LoginB string
		RootA, RootB   []byte
		Number         string
	} `json:"safety"`
	Fetch struct {
		Login string `json:"login"`
		After int64  `json:"after"`
		TS    int64  `json:"ts"`
		By    string `json:"by"`
		Sig   []byte `json:"sig"`
	} `json:"fetch"`
	PeerEntries      []Entry `json:"peer_entries"`       // реестр petya@org7 (устройство seed 40)
	PeerResetEntries []Entry `json:"peer_reset_entries"` // он же после сброса идентичности (новый Hub)
	Envelope         struct {
		Plaintext []byte    `json:"plaintext"`
		Context   []byte    `json:"context"`
		Sender    string    `json:"sender"`
		Open      string    `json:"open_with"` // чьим ключом открывать
		Env       *Envelope `json:"env"`
	} `json:"envelope"`
}

func TestGenerateInteropVectors(t *testing.T) {
	out := os.Getenv("HUB_VECTORS_OUT")
	if out == "" {
		t.Skip("HUB_VECTORS_OUT не задан")
	}
	var v vectors
	v.Login = "ivan@org7"
	root, err := RootKeyFromSeed(seeded(1))
	must(t, err)
	v.RootSeed, v.RootPub, v.HubID = root.Seed(), root.Pub, root.HubID()

	study, phone, tablet := detDevice(t, 10), detDevice(t, 20), detDevice(t, 30)
	v.Devices = map[string]struct {
		Raw []byte `json:"raw"`
		ID  string `json:"id"`
	}{}
	for name, d := range map[string]*DeviceKey{"study": study, "phone": phone, "tablet": tablet} {
		v.Devices[name] = struct {
			Raw []byte `json:"raw"`
			ID  string `json:"id"`
		}{d.Marshal(), d.DeviceID()}
	}

	at := time.Unix(1_800_000_000, 0)
	l, err := NewLog(root, v.Login, NewCertRequest(v.Login, "Syne Study", study, ""), "", at, DefaultPolicy())
	must(t, err)
	add := func(by, d *DeviceKey, name string) {
		c, err := by.Endorse(l.State().HubID, NewCertRequest(v.Login, name, d, "x"), at, 0)
		must(t, err)
		must(t, l.AddDevice(c))
	}
	add(study, phone, "iPhone")
	add(phone, tablet, "iPad")
	r := NewRevocation(l.State().HubID, tablet.DeviceID(), l.HeadHash(), false, at)
	r.Sign(study)
	must(t, l.Revoke(r))
	v.Entries, v.Head = l.Entries, l.State().Head
	for _, c := range l.State().ActiveDevices(at) {
		v.Active = append(v.Active, c.DeviceID)
	}
	v.Revoked = []string{tablet.DeviceID()}

	v.CertRequest.Req = NewCertRequest("petya@org7", "Телефон Пети", phone, "abc123")
	v.CertRequest.PairCode = v.CertRequest.Req.PairCode()

	other, _ := RootKeyFromSeed(seeded(2))
	v.Safety.LoginA, v.Safety.LoginB, v.Safety.RootA, v.Safety.RootB = "ivan@org7", "petya@org7", root.Pub, other.Pub
	v.Safety.Number = SafetyNumber("ivan@org7", root.Pub, "petya@org7", other.Pub)

	fa := phone.SignFetch(v.Login, 42, time.Unix(1_800_000_100, 0))
	v.Fetch.Login, v.Fetch.After, v.Fetch.TS, v.Fetch.By, v.Fetch.Sig = v.Login, 42, fa.TS, fa.DeviceID, fa.Sig

	// Конверт от Study Ивана: читают iPhone Ивана и (чужой) Петя.
	pdev := detDevice(t, 40)
	proot, _ := RootKeyFromSeed(seeded(3))
	plog, err := NewLog(proot, "petya@org7", NewCertRequest("petya@org7", "PC", pdev, ""), "", at, DefaultPolicy())
	must(t, err)
	rcpts := append(l.State().ActiveDevices(at), plog.State().ActiveDevices(at)...)
	v.PeerEntries = plog.Entries
	proot2, _ := RootKeyFromSeed(seeded(4))
	plog2, err := NewLog(proot2, "petya@org7", NewCertRequest("petya@org7", "New PC", detDevice(t, 50), ""), proot.HubID(), at, DefaultPolicy())
	must(t, err)
	v.PeerResetEntries = plog2.Entries
	v.Envelope.Plaintext = []byte("Привет из Go: проверка совместимости ✓")
	v.Envelope.Context = []byte("chat:ivan:petya")
	env, err := Seal(v.Envelope.Plaintext, v.Envelope.Context, study, rcpts)
	must(t, err)
	v.Envelope.Env, v.Envelope.Sender, v.Envelope.Open = env, study.DeviceID(), "phone"

	raw, err := json.MarshalIndent(v, "", " ")
	must(t, err)
	must(t, os.WriteFile(out, raw, 0o644))
}

type swiftVectors struct {
	Plaintext []byte    `json:"plaintext"`
	Context   []byte    `json:"context"`
	SenderRaw []byte    `json:"sender_raw"` // seed устройства-отправителя (Swift)
	Env       *Envelope `json:"env"`
	Fetch     struct {
		Login string `json:"login"`
		After int64  `json:"after"`
		TS    int64  `json:"ts"`
		Sig   []byte `json:"sig"`
	} `json:"fetch"`
	CertRequest struct {
		Req      CertRequest `json:"req"`
		PairCode string      `json:"pair_code"`
	} `json:"cert_request"`
}

func TestSwiftInterop(t *testing.T) {
	in := os.Getenv("HUB_SWIFT_IN")
	if in == "" {
		t.Skip("HUB_SWIFT_IN не задан")
	}
	raw, err := os.ReadFile(in)
	must(t, err)
	var s swiftVectors
	must(t, json.Unmarshal(raw, &s))

	// Swift-устройство (ключи из seed) подписало конверт; Go-устройство получателя его читает.
	sender, err := UnmarshalDeviceKey(s.SenderRaw)
	must(t, err)
	cert := Certificate{Version: Version, Login: "ivan@org7", DeviceID: sender.DeviceID(), SignPub: sender.SignPub, AgreePub: sender.AgreePub}
	goDev := detDevice(t, 40)
	pt, err := Open(s.Env, goDev, cert)
	if err != nil || !bytes.Equal(pt, s.Plaintext) {
		t.Fatalf("Go не прочитал конверт Swift: %q %v", pt, err)
	}
	// Запрос входящих, подписанный Swift.
	fa := FetchAuth{DeviceID: sender.DeviceID(), TS: s.Fetch.TS, Sig: s.Fetch.Sig}
	must(t, VerifyFetch(fa, s.Fetch.Login, s.Fetch.After, cert, time.Unix(s.Fetch.TS, 0)))
	// Код сопряжения и подпись ключей совпадают.
	if s.CertRequest.Req.PairCode() != s.CertRequest.PairCode {
		t.Fatalf("PairCode: Go %s, Swift %s", s.CertRequest.Req.PairCode(), s.CertRequest.PairCode)
	}
	_ = ed25519.PublicKeySize
}
