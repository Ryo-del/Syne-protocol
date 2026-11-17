package hub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// Состав группы, подписанный сервером колледжа.
//
// Групповое сообщение шифруется на устройства всех участников, поэтому тот, кто отправляет (телефон),
// должен знать актуальный состав. Брать его на слово у облака нельзя: облако могло бы дописать в список
// чужого человека и получить копии сообщений. Поэтому состав подписывает сервер колледжа (его ключ
// клиент запоминает при первом получении и дальше сверяет), а подпись действует недолго: исключённый из
// группы человек перестаёт получать новые сообщения, как только прежний состав «протухает».

// GroupRoster — состав одной группы на момент At.
type GroupRoster struct {
	Org     string   `json:"org"`     // организация (суффикс логинов после @)
	Group   int64    `json:"group"`   // номер группы на сервере колледжа
	Name    string   `json:"name"`    // название для людей
	Members []string `json:"members"` // login@org, по возрастанию, без повторов
	At      int64    `json:"at"`      // unix-секунды подписи
	Sig     []byte   `json:"sig"`     // подпись сервера колледжа
}

// DomainGroupRoster — домен подписи (отделяет её от подписей другого назначения).
const DomainGroupRoster = "syne-group-roster-v1"

// RosterMaxAge — как долго подписанный состав считается актуальным. Облако получает свежую подпись
// заметно чаще (RosterRefresh), поэтому честный клиент всегда укладывается в этот срок.
const (
	RosterMaxAge  = 15 * time.Minute
	RosterRefresh = 5 * time.Minute
)

// NormalizeMembers сортирует и убирает повторы (подпись считается от канонического порядка).
func NormalizeMembers(members []string) []string {
	seen := make(map[string]struct{}, len(members))
	out := make([]string, 0, len(members))
	for _, m := range members {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func (r *GroupRoster) signedBytes() []byte {
	e := newEnc(DomainGroupRoster).str(r.Org).u64(uint64(r.Group)).str(r.Name).u64(uint64(r.At)).u64(uint64(len(r.Members)))
	for _, m := range r.Members {
		e.str(m)
	}
	return e.b
}

// SignRoster строит и подписывает состав ключом сервера колледжа. Участники приводятся к каноническому виду.
func SignRoster(priv ed25519.PrivateKey, org string, group int64, name string, members []string, now time.Time) (GroupRoster, error) {
	if org == "" || group == 0 {
		return GroupRoster{}, fmt.Errorf("%w: состав группы", ErrFormat)
	}
	r := GroupRoster{Org: org, Group: group, Name: name, Members: NormalizeMembers(members), At: now.Unix()}
	if len(r.Members) == 0 || len(r.Members) > MaxGroupMembers {
		return GroupRoster{}, fmt.Errorf("%w: число участников группы", ErrFormat)
	}
	for _, m := range r.Members {
		if !ValidLogin(m) {
			return GroupRoster{}, fmt.Errorf("%w: участник %q", ErrFormat, m)
		}
	}
	r.Sig = ed25519.Sign(priv, r.signedBytes())
	return r, nil
}

// VerifyRoster проверяет подпись сервера колледжа, свежесть и каноничность списка. pub — запомненный ключ
// сервера. Возвращает ErrSignature, если подпись не сошлась, и ErrFormat — если состав некорректен или устарел.
func VerifyRoster(pub ed25519.PublicKey, r GroupRoster, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize || r.Org == "" || r.Group == 0 || len(r.Members) == 0 || len(r.Members) > MaxGroupMembers {
		return fmt.Errorf("%w: состав группы", ErrFormat)
	}
	for i, m := range r.Members {
		if !ValidLogin(m) || (i > 0 && r.Members[i-1] >= m) {
			return fmt.Errorf("%w: список участников", ErrFormat)
		}
	}
	if !ed25519.Verify(pub, r.signedBytes(), r.Sig) {
		return ErrSignature
	}
	age := now.Sub(time.Unix(r.At, 0))
	if age > RosterMaxAge || age < -FetchWindow {
		return fmt.Errorf("%w: состав группы устарел", ErrFormat)
	}
	return nil
}

// RosterKeyID — короткий отпечаток ключа сервера колледжа (его можно сверить глазами).
func RosterKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// HasMember сообщает, входит ли login@org в состав.
func (r GroupRoster) HasMember(login string) bool {
	i := sort.SearchStrings(r.Members, login)
	return i < len(r.Members) && r.Members[i] == login
}
