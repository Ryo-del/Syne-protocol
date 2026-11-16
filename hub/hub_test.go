package hub

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

type fixture struct {
	root  *RootKey
	study *DeviceKey
	log   *Log
}

func newFixture(t *testing.T, pol Policy) *fixture {
	t.Helper()
	root, err := GenerateRootKey()
	must(t, err)
	study, err := GenerateDeviceKey()
	must(t, err)
	l, err := NewLog(root, "ivan@school1", NewCertRequest("ivan@school1", "Study", study, "x"), "", t0, pol)
	must(t, err)
	return &fixture{root, study, l}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) addDevice(t *testing.T, name string, by *DeviceKey) *DeviceKey {
	t.Helper()
	d, err := GenerateDeviceKey()
	must(t, err)
	cert, err := by.Endorse(f.log.State().HubID, NewCertRequest("ivan@school1", name, d, "1"), t0, 0)
	must(t, err)
	must(t, f.log.AddDevice(cert))
	return d
}

func TestChainOfTrust(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	phone := f.addDevice(t, "iPhone", f.study)
	tablet := f.addDevice(t, "iPad", phone) // поручитель — телефон, не Study
	st := f.log.State()
	for _, d := range []*DeviceKey{f.study, phone, tablet} {
		if _, err := st.Trusted(d.DeviceID(), t0); err != nil {
			t.Fatalf("%s: %v", d.DeviceID(), err)
		}
	}
	// Журнал после сериализации и полной перепроверки даёт то же состояние.
	l2, err := LoadLog(f.log.Entries, DefaultPolicy())
	must(t, err)
	if l2.State().Head != st.Head || len(l2.State().ActiveDevices(t0)) != 3 {
		t.Fatal("состояние после LoadLog отличается")
	}
}

func TestRejectsUntrustedIssuer(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	stranger, _ := GenerateDeviceKey()
	d, _ := GenerateDeviceKey()
	cert, err := stranger.Endorse(f.log.State().HubID, NewCertRequest("ivan@school1", "Evil", d, "1"), t0, 0)
	must(t, err)
	if err := f.log.AddDevice(cert); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("ожидали ErrUntrusted, получили %v", err)
	}
	if len(f.log.Entries) != 1 {
		t.Fatal("недопустимая запись попала в журнал")
	}
}

func TestRejectsForeignRootAndTamperedCert(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	otherRoot, _ := GenerateRootKey()
	d, _ := GenerateDeviceKey()
	cert, _ := otherRoot.IssueFirstDevice(NewCertRequest("ivan@school1", "x", d, "1"), t0, 0)
	cert.HubID = f.log.State().HubID
	if err := f.log.AddDevice(cert); !errors.Is(err, ErrSignature) {
		t.Fatalf("чужой корень: %v", err)
	}
	// Подмена ключа в сертификате ломает device_id.
	good, _ := f.study.Endorse(f.log.State().HubID, NewCertRequest("ivan@school1", "ok", d, "1"), t0, 0)
	other, _ := GenerateDeviceKey()
	good.AgreePub = other.AgreePub
	if err := f.log.AddDevice(good); !errors.Is(err, ErrFormat) {
		t.Fatalf("подмена ключа: %v", err)
	}
}

func TestTamperedLogDetected(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	f.addDevice(t, "iPhone", f.study)
	f.addDevice(t, "iPad", f.study)
	// Сервер скрывает среднюю запись.
	cut := []Entry{f.log.Entries[0], f.log.Entries[2]}
	if _, err := LoadLog(cut, DefaultPolicy()); !errors.Is(err, ErrChain) {
		t.Fatalf("пропуск записи: %v", err)
	}
	// Сервер меняет содержимое записи.
	mod := append([]Entry(nil), f.log.Entries...)
	mod[1].Payload = append([]byte(nil), mod[2].Payload...)
	if _, err := LoadLog(mod, DefaultPolicy()); !errors.Is(err, ErrChain) {
		t.Fatalf("подмена записи: %v", err)
	}
}

func TestRevocation(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	phone := f.addDevice(t, "iPhone", f.study)

	// Сам себя отозвать нельзя.
	r := NewRevocation(f.log.State().HubID, phone.DeviceID(), f.log.HeadHash(), false, t0)
	r.Sign(phone)
	if err := f.log.Revoke(r); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("самоотзыв: %v", err)
	}
	// Study отзывает телефон.
	r = NewRevocation(f.log.State().HubID, phone.DeviceID(), f.log.HeadHash(), false, t0)
	r.Sign(f.study)
	must(t, f.log.Revoke(r))
	if _, err := f.log.State().Trusted(phone.DeviceID(), t0); !errors.Is(err, ErrDeviceRevok) {
		t.Fatalf("после отзыва: %v", err)
	}
	// Отозванный не может поручиться за новое устройство.
	d, _ := GenerateDeviceKey()
	cert, _ := phone.Endorse(f.log.State().HubID, NewCertRequest("ivan@school1", "x", d, "1"), t0, 0)
	if err := f.log.AddDevice(cert); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("поручитель отозван: %v", err)
	}
	// Подпись отзыва нельзя применить в другом месте журнала (повтор).
	stale := NewRevocation(f.log.State().HubID, f.study.DeviceID(), "deadbeef", false, t0)
	stale.Sign(phone)
	if err := f.log.Revoke(stale); err == nil {
		t.Fatal("устаревший отзыв принят")
	}
}

func TestRevocationThresholdAndRoot(t *testing.T) {
	f := newFixture(t, Policy{RevokeSignatures: 2})
	phone := f.addDevice(t, "iPhone", f.study)
	tablet := f.addDevice(t, "iPad", f.study)
	id := f.log.State().HubID

	one := NewRevocation(id, tablet.DeviceID(), f.log.HeadHash(), false, t0)
	one.Sign(f.study)
	if err := f.log.Revoke(one); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("одной подписи мало: %v", err)
	}
	dup := NewRevocation(id, tablet.DeviceID(), f.log.HeadHash(), false, t0)
	dup.Sign(f.study)
	dup.Sign(f.study) // одно и то же устройство дважды не считается
	if err := f.log.Revoke(dup); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("дубль подписи: %v", err)
	}
	two := NewRevocation(id, tablet.DeviceID(), f.log.HeadHash(), false, t0)
	two.Sign(f.study)
	two.Sign(phone)
	must(t, f.log.Revoke(two))

	// Корневой ключ достаточен один.
	rr := NewRevocation(id, phone.DeviceID(), f.log.HeadHash(), false, t0)
	rr.SignRoot(f.root)
	must(t, f.log.Revoke(rr))
}

func TestCascadeRevocation(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	phone := f.addDevice(t, "iPhone", f.study)
	tablet := f.addDevice(t, "iPad", phone)
	r := NewRevocation(f.log.State().HubID, phone.DeviceID(), f.log.HeadHash(), true, t0)
	r.Sign(f.study)
	must(t, f.log.Revoke(r))
	if _, err := f.log.State().Trusted(tablet.DeviceID(), t0); !errors.Is(err, ErrDeviceRevok) {
		t.Fatalf("каскад не сработал: %v", err)
	}
	if _, err := f.log.State().Trusted(f.study.DeviceID(), t0); err != nil {
		t.Fatal("Study не должен пострадать")
	}
}

func TestExpiry(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	d, _ := GenerateDeviceKey()
	cert, _ := f.study.Endorse(f.log.State().HubID, NewCertRequest("ivan@school1", "temp", d, "1"), t0, time.Hour)
	must(t, f.log.AddDevice(cert))
	if _, err := f.log.State().Trusted(d.DeviceID(), t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.log.State().Trusted(d.DeviceID(), t0.Add(2*time.Hour)); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("срок не проверен: %v", err)
	}
}

func TestSealOpenMultiDevice(t *testing.T) {
	// Ivan: Study + iPhone. Petya: один компьютер.
	f := newFixture(t, DefaultPolicy())
	phone := f.addDevice(t, "iPhone", f.study)
	proot, _ := GenerateRootKey()
	pdev, _ := GenerateDeviceKey()
	plog, err := NewLog(proot, "petya@school1", NewCertRequest("petya@school1", "Study", pdev, "x"), "", t0, DefaultPolicy())
	must(t, err)

	senderCert := f.log.State().Devices[f.study.DeviceID()].Cert
	rcpts := append(plog.State().ActiveDevices(t0), f.log.State().ActiveDevices(t0)...) // получатель + свои устройства
	env, err := Seal([]byte("привет"), []byte("chat-1"), f.study, rcpts)
	must(t, err)

	for name, d := range map[string]*DeviceKey{"Петя": pdev, "iPhone Ивана": phone, "Study Ивана": f.study} {
		pt, err := Open(env, d, senderCert)
		if err != nil || string(pt) != "привет" {
			t.Fatalf("%s: %q %v", name, pt, err)
		}
	}
	// Посторонний не читает.
	eve, _ := GenerateDeviceKey()
	if _, err := Open(env, eve, senderCert); !errors.Is(err, ErrNotForMe) {
		t.Fatalf("посторонний: %v", err)
	}
	// Шифртекст не содержит открытого текста.
	if contains(env.Ciphertext, []byte("привет")) {
		t.Fatal("открытый текст в шифртексте")
	}
}

func TestSealTamperAndSpoof(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	pdev, _ := GenerateDeviceKey()
	proot, _ := GenerateRootKey()
	plog, _ := NewLog(proot, "petya@school1", NewCertRequest("petya@school1", "Study", pdev, "x"), "", t0, DefaultPolicy())
	pcerts := plog.State().ActiveDevices(t0)
	senderCert := f.log.State().Devices[f.study.DeviceID()].Cert

	env, _ := Seal([]byte("секрет"), []byte("c1"), f.study, pcerts)

	bad := *env
	bad.Ciphertext = append([]byte(nil), env.Ciphertext...)
	bad.Ciphertext[0] ^= 1
	if _, err := Open(&bad, pdev, senderCert); !errors.Is(err, ErrSignature) {
		t.Fatalf("порча шифртекста: %v", err)
	}
	// Подмена контекста (перенос сообщения в другой чат) тоже ломает подпись.
	moved := *env
	moved.Context = []byte("c2")
	if _, err := Open(&moved, pdev, senderCert); !errors.Is(err, ErrSignature) {
		t.Fatalf("смена контекста: %v", err)
	}
	// Конверт, подписанный другим устройством, но выданный за Study.
	mallory, _ := GenerateDeviceKey()
	fake, _ := Seal([]byte("fake"), []byte("c1"), mallory, pcerts)
	fake.SenderID = senderCert.DeviceID
	if _, err := Open(fake, pdev, senderCert); !errors.Is(err, ErrSignature) {
		t.Fatalf("подделка отправителя: %v", err)
	}
}

func contains(h, n []byte) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if string(h[i:i+len(n)]) == string(n) {
			return true
		}
	}
	return false
}

func TestTrustStore(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	ts := NewTrustStore()
	if ts.Observe("ivan@school1", f.log) != ChangeNew {
		t.Fatal("первый контакт")
	}
	old := append([]Entry(nil), f.log.Entries...)
	f.addDevice(t, "iPhone", f.study)
	if ts.Observe("ivan@school1", f.log) != ChangeNone {
		t.Fatal("нормальное обновление")
	}
	// Откат: сервер показывает старую версию.
	lOld, _ := LoadLog(old, DefaultPolicy())
	if ts.Observe("ivan@school1", lOld) != ChangeRollback {
		t.Fatal("откат не замечен")
	}
	// Развилка: та же длина, другая запись.
	f2 := newFixture(t, DefaultPolicy())
	_ = f2
	root2, _ := GenerateRootKey()
	dev2, _ := GenerateDeviceKey()
	reset, err := NewLog(root2, "ivan@school1", NewCertRequest("ivan@school1", "NewPC", dev2, "x"), f.log.State().HubID, t0, DefaultPolicy())
	must(t, err)
	if ts.Observe("ivan@school1", reset) != ChangeReset {
		t.Fatal("сброс идентичности не замечен")
	}
	if reset.State().PrevHubID != f.log.State().HubID {
		t.Fatal("prev_hub_id не записан")
	}
	ts.AcceptReset("ivan@school1", reset)
	if ts.Observe("ivan@school1", reset) != ChangeNone {
		t.Fatal("после подтверждения должно быть тихо")
	}
}

func TestSafetyNumberSymmetricAndChanges(t *testing.T) {
	a, _ := GenerateRootKey()
	b, _ := GenerateRootKey()
	b2, _ := GenerateRootKey()
	n1 := SafetyNumber("a@s", a.Pub, "b@s", b.Pub)
	if n1 != SafetyNumber("b@s", b.Pub, "a@s", a.Pub) {
		t.Fatal("номер должен быть одинаков у обоих")
	}
	if n1 == SafetyNumber("a@s", a.Pub, "b@s", b2.Pub) {
		t.Fatal("после сброса номер обязан поменяться")
	}
	if len(n1) != 2*(6*5+5)+1 {
		t.Fatalf("формат: %q", n1)
	}
}

func TestRecovery(t *testing.T) {
	root, _ := GenerateRootKey()
	code, _ := NewRecoveryCode()
	blob, err := WrapRoot(root, code)
	must(t, err)
	got, err := UnwrapRoot(blob, code)
	must(t, err)
	if got.HubID() != root.HubID() {
		t.Fatal("другой корень")
	}
	wrong, _ := NewRecoveryCode()
	if _, err := UnwrapRoot(blob, wrong); !errors.Is(err, ErrRecovery) {
		t.Fatalf("чужой код: %v", err)
	}
}

func TestDeviceKeyRoundTripAndPairCode(t *testing.T) {
	d, _ := GenerateDeviceKey()
	d2, err := UnmarshalDeviceKey(d.Marshal())
	must(t, err)
	if d2.DeviceID() != d.DeviceID() {
		t.Fatal("ключ не восстановился")
	}
	req := NewCertRequest("a@s", "ph", d, "abc")
	other, _ := GenerateDeviceKey()
	forged := NewCertRequest("a@s", "ph", other, "abc")
	if req.PairCode() == forged.PairCode() {
		t.Fatal("подмена ключей должна менять код")
	}
}

func TestInboxAuth(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	cert := f.log.State().Devices[f.study.DeviceID()].Cert
	pdev, _ := GenerateDeviceKey()
	proot, _ := GenerateRootKey()
	plog, _ := NewLog(proot, "petya@school1", NewCertRequest("petya@school1", "S", pdev, "x"), "", t0, DefaultPolicy())
	env, err := Seal([]byte("hi"), []byte("c"), f.study, plog.State().ActiveDevices(t0))
	must(t, err)
	p := &InboxPost{From: "ivan@school1", To: "petya@school1", Envelope: env, MsgID: "m1"}
	must(t, VerifyPost(p, cert))

	// Чужой сертификат / подделанный отправитель / порча подписи.
	other, _ := GenerateDeviceKey()
	ocert, _ := f.study.Endorse(f.log.State().HubID, NewCertRequest("ivan@school1", "o", other, "x"), t0, 0)
	if err := VerifyPost(p, ocert); !errors.Is(err, ErrSignature) {
		t.Fatalf("чужой сертификат: %v", err)
	}
	bad := *p
	e2 := *env
	e2.Ciphertext = append([]byte(nil), env.Ciphertext...)
	e2.Ciphertext[0] ^= 1
	bad.Envelope = &e2
	if err := VerifyPost(&bad, cert); !errors.Is(err, ErrSignature) {
		t.Fatalf("порча: %v", err)
	}
	lie := *p
	lie.From = "petya@school1" // выдаёт себя за другого
	if err := VerifyPost(&lie, cert); !errors.Is(err, ErrSignature) {
		t.Fatalf("ложный отправитель: %v", err)
	}

	// Запрос входящих: подпись привязана к логину, after и времени.
	a := f.study.SignFetch("ivan@school1", 5, t0)
	must(t, VerifyFetch(a, "ivan@school1", 5, cert, t0.Add(time.Minute)))
	if err := VerifyFetch(a, "ivan@school1", 6, cert, t0); !errors.Is(err, ErrSignature) {
		t.Fatalf("другой after: %v", err)
	}
	if err := VerifyFetch(a, "petya@school1", 5, cert, t0); !errors.Is(err, ErrSignature) {
		t.Fatalf("чужие входящие: %v", err)
	}
	if err := VerifyFetch(a, "ivan@school1", 5, cert, t0.Add(time.Hour)); !errors.Is(err, ErrSignature) {
		t.Fatalf("повтор через час: %v", err)
	}
}
