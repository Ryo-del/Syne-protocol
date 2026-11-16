package hub

import (
	"errors"
	"testing"
	"time"
)

// Документ «Device Trust & Holding»: привязанное (Bound) и доверенное (Trusted) устройство.

func (f *fixture) addBound(t *testing.T, name string, by *DeviceKey) *DeviceKey {
	t.Helper()
	d, _ := GenerateDeviceKey()
	cert, err := by.Endorse(f.log.State().HubID, NewCertRequest("ivan@school1", name, d, "1"), t0, 0, false)
	must(t, err)
	must(t, f.log.AddDevice(cert))
	return d
}

func TestBoundDeviceCannotApproveOrRevokeOrPromote(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	phone := f.addBound(t, "iPhone", f.study) // «Да»: обычное привязанное
	id := f.log.State().HubID

	if st := f.log.State(); st.Devices[phone.DeviceID()].Trusted || st.CanApprove(phone.DeviceID(), t0) == nil {
		t.Fatal("устройство после «Да» не должно быть доверенным")
	}
	// Привязанное устройство читает и пишет сообщения (оно активно) ...
	if _, err := f.log.State().Active(phone.DeviceID(), t0); err != nil {
		t.Fatal(err)
	}
	// ... но не может поручиться за другое устройство.
	desktop, _ := GenerateDeviceKey()
	cert, err := phone.Endorse(id, NewCertRequest("ivan@school1", "Desktop", desktop, "2"), t0, 0, false)
	must(t, err)
	if err := f.log.AddDevice(cert); !errors.Is(err, ErrNotTrustedDevice) {
		t.Fatalf("поручитель Bound: %v", err)
	}
	// Не может отозвать другое устройство.
	r := NewRevocation(id, f.study.DeviceID(), f.log.HeadHash(), false, t0)
	r.Sign(phone)
	if err := f.log.Revoke(r); !errors.Is(err, ErrNotTrustedDevice) {
		t.Fatalf("отзыв Bound: %v", err)
	}
	// Не может повысить сам себя или другое устройство.
	p := NewPromotion(id, phone.DeviceID(), f.log.HeadHash(), t0)
	phone.SignPromotion(p)
	if err := f.log.Promote(p); err == nil {
		t.Fatal("устройство повысило само себя")
	}
	if len(f.log.Entries) != 2 {
		t.Fatalf("в журнал попало лишнее: %d", len(f.log.Entries))
	}
}

func TestPromoteGivesApproveRights(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	phone := f.addBound(t, "iPhone", f.study)
	id := f.log.State().HubID

	// Доверенное устройство передаёт доверие через настройки.
	p := NewPromotion(id, phone.DeviceID(), f.log.HeadHash(), t0)
	f.study.SignPromotion(p)
	must(t, f.log.Promote(p))
	if err := f.log.State().CanApprove(phone.DeviceID(), t0); err != nil {
		t.Fatal(err)
	}
	// Теперь телефон подтверждает Desktop как обычное устройство.
	desktop, _ := GenerateDeviceKey()
	cert, _ := phone.Endorse(id, NewCertRequest("ivan@school1", "Desktop", desktop, "2"), t0, 0, false)
	must(t, f.log.AddDevice(cert))
	if f.log.State().Devices[desktop.DeviceID()].Trusted {
		t.Fatal("Desktop после обычного подтверждения не должен стать доверенным автоматически")
	}
	// Повторно повысить нельзя, устаревшая подпись тоже, отозванное — тоже.
	again := NewPromotion(id, phone.DeviceID(), f.log.HeadHash(), t0)
	f.study.SignPromotion(again)
	if err := f.log.Promote(again); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("повторное повышение: %v", err)
	}
	stale := NewPromotion(id, desktop.DeviceID(), "deadbeef", t0)
	f.study.SignPromotion(stale)
	if err := f.log.Promote(stale); !errors.Is(err, ErrChain) {
		t.Fatalf("устаревшая подпись: %v", err)
	}
	r := NewRevocation(id, desktop.DeviceID(), f.log.HeadHash(), false, t0)
	r.Sign(f.study)
	must(t, f.log.Revoke(r))
	pr := NewPromotion(id, desktop.DeviceID(), f.log.HeadHash(), t0)
	f.study.SignPromotion(pr)
	if err := f.log.Promote(pr); !errors.Is(err, ErrDeviceRevok) {
		t.Fatalf("повышение отозванного: %v", err)
	}
	// Полная перепроверка журнала даёт то же состояние (клиенты не доверяют присланному).
	l2, err := LoadLog(f.log.Entries, DefaultPolicy())
	must(t, err)
	if !l2.State().Devices[phone.DeviceID()].Trusted {
		t.Fatal("после перепроверки статус Trusted потерян")
	}
}

func TestTrustedFlagCannotBeForgedInCertificate(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	d, _ := GenerateDeviceKey()
	cert, _ := f.study.Endorse(f.log.State().HubID, NewCertRequest("ivan@school1", "x", d, "1"), t0, 0, false)
	cert.Trusted = true // облако или посторонний «повышает» устройство, правя сертификат
	if err := f.log.AddDevice(cert); !errors.Is(err, ErrSignature) {
		t.Fatalf("подделка флага Trusted: %v", err)
	}
	// Корневой ключ выдаёт доверенное устройство (восстановление).
	cert2, err := f.root.IssueFirstDevice(NewCertRequest("ivan@school1", "after recovery", d, "1"), t0, 0)
	must(t, err)
	must(t, f.log.AddDevice(cert2))
	if err := f.log.State().CanApprove(d.DeviceID(), t0); err != nil {
		t.Fatalf("восстановленное по коду устройство должно быть доверенным: %v", err)
	}
}

func TestSignedRequest(t *testing.T) {
	d, _ := GenerateDeviceKey()
	now := time.Now()
	r := NewSignedRequest("ivan@school1", "iPhone", TypeIOS, d, "abc", now)
	must(t, r.Verify(now))
	if r.ExpiresAt-r.CreatedAt != int64((48 * time.Hour).Seconds()) {
		t.Fatal("срок запроса должен быть 48 часов")
	}
	// Подмена имени, ключа или срока ломает подпись самого устройства.
	for name, mod := range map[string]func(*CertRequest){
		"имя":  func(x *CertRequest) { x.Name = "iPhone администратора" },
		"срок": func(x *CertRequest) { x.ExpiresAt += 3600 },
		"тип":  func(x *CertRequest) { x.Type = TypeDesktop },
		"ключ": func(x *CertRequest) { o, _ := GenerateDeviceKey(); x.AgreePub = o.AgreePub },
	} {
		bad := r
		mod(&bad)
		if err := bad.Verify(now); !errors.Is(err, ErrSignature) {
			t.Fatalf("подмена (%s): %v", name, err)
		}
	}
	if err := r.Verify(now.Add(49 * time.Hour)); !errors.Is(err, ErrFormat) {
		t.Fatalf("просроченный запрос: %v", err)
	}
	wrongType := NewSignedRequest("ivan@school1", "x", "toaster", d, "abc", now)
	if err := wrongType.Verify(now); !errors.Is(err, ErrFormat) {
		t.Fatalf("неизвестный тип: %v", err)
	}
	// Тип попадает в сертификат и подпись.
	f := newFixture(t, DefaultPolicy())
	cert, err := f.study.Endorse(f.log.State().HubID, NewSignedRequest("ivan@school1", "iPhone", TypeIOS, d, "abc", now), now, 0, false)
	must(t, err)
	if cert.DeviceType != TypeIOS {
		t.Fatal("тип устройства потерян")
	}
}

func TestBindingAndRejectSignatures(t *testing.T) {
	f := newFixture(t, DefaultPolicy())
	cert := f.log.State().Devices[f.study.DeviceID()].Cert
	b := f.study.SignBinding("ivan@school1", "acct-123", t0)
	must(t, VerifyBinding(b, cert, t0.Add(time.Minute)))
	other := b
	other.AccountID = "acct-evil" // облако подменяет аккаунт
	if err := VerifyBinding(other, cert, t0); !errors.Is(err, ErrSignature) {
		t.Fatalf("подмена аккаунта: %v", err)
	}
	if err := VerifyBinding(b, cert, t0.Add(time.Hour)); !errors.Is(err, ErrSignature) {
		t.Fatalf("устаревшая связь: %v", err)
	}
	rj := f.study.SignReject("ivan@school1", "req-1", "dev-x", t0)
	must(t, VerifyReject(rj, cert, t0))
	rj.RequestID = "req-2"
	if err := VerifyReject(rj, cert, t0); !errors.Is(err, ErrSignature) {
		t.Fatalf("подмена запроса в отказе: %v", err)
	}
	// Запрос списка ожидающих подписан в своём домене и не годится как запрос входящих.
	a := f.study.SignAction(DomainRequestsFetch, "ivan@school1", 0, t0)
	must(t, VerifyAction(DomainRequestsFetch, a, "ivan@school1", 0, cert, t0))
	if err := VerifyFetch(a, "ivan@school1", 0, cert, t0); !errors.Is(err, ErrSignature) {
		t.Fatalf("подпись из другого домена принята: %v", err)
	}
}
