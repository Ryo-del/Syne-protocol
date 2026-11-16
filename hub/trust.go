package hub

import "sync"

// Pin — запомненная вершина реестра собеседника (TOFU: доверие при первом контакте).
type Pin struct {
	HubID string `json:"hub_id"`
	Head  Head   `json:"head"`
}

// ChangeKind — что обнаружил клиент при проверке реестра собеседника.
type ChangeKind string

const (
	ChangeNone     ChangeKind = ""
	ChangeNew      ChangeKind = "new"      // первый контакт, Hub запомнен
	ChangeReset    ChangeKind = "reset"    // у логина другой Hub: сброс идентичности
	ChangeRollback ChangeKind = "rollback" // реестр откатился назад
	ChangeFork     ChangeKind = "fork"     // история разошлась с запомненной
)

// TrustStore хранит запомненные вершины по логину и сообщает об опасных изменениях.
// Хранение на диск — забота клиента (Marshal через Pins/SetPins).
type TrustStore struct {
	mu   sync.Mutex
	pins map[string]Pin
}

func NewTrustStore() *TrustStore { return &TrustStore{pins: map[string]Pin{}} }

func (t *TrustStore) Pins() map[string]Pin {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]Pin, len(t.pins))
	for k, v := range t.pins {
		out[k] = v
	}
	return out
}

func (t *TrustStore) SetPins(p map[string]Pin) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pins = map[string]Pin{}
	for k, v := range p {
		t.pins[k] = v
	}
}

// Observe проверяет присланный журнал логина. Если всё в порядке, запоминает новую
// вершину. При ChangeReset/Rollback/Fork вершина НЕ обновляется, пока пользователь не
// подтвердит (AcceptReset): сообщения такому собеседнику стоит сопровождать
// предупреждением.
func (t *TrustStore) Observe(login string, l *Log) ChangeKind {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := l.State()
	cur := st.Head
	old, ok := t.pins[login]
	if !ok {
		t.pins[login] = Pin{HubID: st.HubID, Head: cur}
		return ChangeNew
	}
	if old.HubID != st.HubID {
		return ChangeReset
	}
	switch err := l.CheckAgainst(old.Head); err {
	case nil:
		t.pins[login] = Pin{HubID: st.HubID, Head: cur}
		return ChangeNone
	case ErrRollback:
		return ChangeRollback
	default:
		return ChangeFork
	}
}

// AcceptReset принимает новый Hub логина после подтверждения пользователем
// (например, после сверки номера безопасности).
func (t *TrustStore) AcceptReset(login string, l *Log) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := l.State()
	t.pins[login] = Pin{HubID: st.HubID, Head: st.Head}
}
