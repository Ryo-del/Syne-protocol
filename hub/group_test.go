package hub

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestGroupRosterSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	r, err := SignRoster(priv, "org7", 3, "Группа 1", []string{"b@org7", "a@org7", "b@org7"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Members) != 2 || r.Members[0] != "a@org7" || !r.HasMember("b@org7") || r.HasMember("c@org7") {
		t.Fatalf("состав: %+v", r.Members)
	}
	if err := VerifyRoster(pub, r, now.Add(time.Minute)); err != nil {
		t.Fatalf("честный состав: %v", err)
	}
	// Подмена состава (облако дописало участника) ломает подпись.
	forged := r
	forged.Members = append(append([]string{}, r.Members...), "evil@org7")
	if err := VerifyRoster(pub, forged, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("подмена состава: %v", err)
	}
	// Другое название или группа — тоже другая подпись.
	renamed := r
	renamed.Group = 4
	if err := VerifyRoster(pub, renamed, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("подмена группы: %v", err)
	}
	// Чужой ключ сервера.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyRoster(other, r, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("чужой ключ: %v", err)
	}
	// Протухший состав: исключённый участник не должен получать новые сообщения.
	if err := VerifyRoster(pub, r, now.Add(RosterMaxAge+time.Minute)); !errors.Is(err, ErrFormat) {
		t.Fatalf("устаревший состав: %v", err)
	}
	// Неканонический порядок отвергается (две разные записи одного состава).
	bad := r
	bad.Members = []string{"b@org7", "a@org7"}
	if err := VerifyRoster(pub, bad, now); !errors.Is(err, ErrFormat) {
		t.Fatalf("порядок: %v", err)
	}
}
