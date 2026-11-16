package hub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

type EntryKind string

const (
	KindGenesis EntryKind = "genesis" // создание Hub: корневой ключ и первое устройство
	KindAdd     EntryKind = "add"     // сертификат нового устройства
	KindRevoke  EntryKind = "revoke"  // отзыв устройства
	KindPromote EntryKind = "promote" // повышение привязанного устройства до доверенного
)

var (
	ErrChain            = errors.New("hub: разрыв или подмена цепочки реестра")
	ErrUntrusted        = errors.New("hub: устройство не доверено")
	ErrNotAllowed       = errors.New("hub: действие не разрешено политикой")
	ErrRollback         = errors.New("hub: реестр откатился назад")
	ErrFork             = errors.New("hub: реестр разошёлся с известной копией")
	ErrUnknownHub       = errors.New("hub: неизвестный Hub")
	ErrNoDevice         = errors.New("hub: устройство не найдено")
	ErrDeviceRevok      = errors.New("hub: устройство отозвано")
	ErrNotTrustedDevice = errors.New("hub: устройство привязано, но не доверенное: подтверждать устройства оно не может")
)

// Genesis — содержимое первой записи.
type Genesis struct {
	Login     string      `json:"login"`
	RootPub   []byte      `json:"root_pub"`
	PrevHubID string      `json:"prev_hub_id,omitempty"` // при сбросе идентичности — прежний Hub
	Cert      Certificate `json:"cert"`
}

// Promotion — подписанное повышение привязанного устройства до доверенного («Сделать доверенным»
// в настройках). Подписывает доверенное устройство (не повышаемое) или Root Key. PrevHash
// привязывает подпись к месту в журнале, как и у отзыва.
type Promotion struct {
	Version  int       `json:"v"`
	HubID    string    `json:"hub_id"`
	DeviceID string    `json:"device_id"`
	PrevHash string    `json:"prev_hash"`
	At       int64     `json:"at"`
	Sig      Signature `json:"sig"`
}

func (p *Promotion) signedBytes() []byte {
	return newEnc("syne-hub-promote-v1").u64(uint64(p.Version)).str(p.HubID).str(p.DeviceID).str(p.PrevHash).u64(uint64(p.At)).b
}

// NewPromotion готовит повышение; подпись добавляет SignPromotion.
func NewPromotion(hubID, deviceID, prevHash string, at time.Time) *Promotion {
	return &Promotion{Version: Version, HubID: hubID, DeviceID: deviceID, PrevHash: prevHash, At: at.Unix()}
}

func (d *DeviceKey) SignPromotion(p *Promotion) {
	p.Sig = Signature{Signer: d.DeviceID(), Sig: d.Sign(p.signedBytes())}
}

// Signature — подпись под отзывом: устройством либо корневым ключом.
type Signature struct {
	Signer string `json:"signer"` // DeviceID или IssuerRoot
	Sig    []byte `json:"sig"`
}

// Revocation — подписанная запись «устройство отозвано». PrevHash привязывает её к
// конкретному месту в журнале, чтобы подпись нельзя было переиспользовать позже.
type Revocation struct {
	Version  int         `json:"v"`
	HubID    string      `json:"hub_id"`
	DeviceID string      `json:"device_id"`
	Cascade  bool        `json:"cascade"` // отозвать и всё, что это устройство поручило
	PrevHash string      `json:"prev_hash"`
	At       int64       `json:"at"`
	Sigs     []Signature `json:"sigs"`
}

func (r *Revocation) signedBytes() []byte {
	c := uint64(0)
	if r.Cascade {
		c = 1
	}
	return newEnc("syne-hub-revoke-v1").u64(uint64(r.Version)).str(r.HubID).str(r.DeviceID).
		u64(c).str(r.PrevHash).u64(uint64(r.At)).b
}

// NewRevocation готовит отзыв; подписи добавляются Sign / SignRoot.
func NewRevocation(hubID, deviceID, prevHash string, cascade bool, at time.Time) *Revocation {
	return &Revocation{Version: Version, HubID: hubID, DeviceID: deviceID, Cascade: cascade, PrevHash: prevHash, At: at.Unix()}
}

func (r *Revocation) Sign(d *DeviceKey) {
	r.Sigs = append(r.Sigs, Signature{Signer: d.DeviceID(), Sig: d.Sign(r.signedBytes())})
}

func (r *Revocation) SignRoot(k *RootKey) {
	r.Sigs = append(r.Sigs, Signature{Signer: IssuerRoot, Sig: ed25519.Sign(k.priv, r.signedBytes())})
}

// Entry — запись журнала реестра. Hash связывает записи в цепочку: изменить, убрать
// или переставить запись незаметно нельзя.
type Entry struct {
	Seq      uint64    `json:"seq"`
	PrevHash string    `json:"prev_hash"`
	Kind     EntryKind `json:"kind"`
	Payload  []byte    `json:"payload"` // точные байты: по ним считается хэш; в JSON — base64
	Hash     string    `json:"hash"`
}

func entryHash(seq uint64, prev string, kind EntryKind, payload []byte) string {
	h := sha256.Sum256(newEnc("syne-hub-entry-v1").u64(seq).str(prev).str(string(kind)).bytes(payload).b)
	return hex.EncodeToString(h[:])
}

// Head — «версия Hub»: по ней сервер, облако и клиенты сверяют, что видят один реестр.
type Head struct {
	HubID string `json:"hub_id"`
	Seq   uint64 `json:"seq"`
	Hash  string `json:"hash"`
}

// Policy — настраиваемые правила (решения владельца, пункт 0.1 фронта работ).
type Policy struct {
	// RevokeSignatures — сколько разных доверенных устройств должны подписать отзыв.
	// Подпись корневого ключа достаточна всегда. Минимум 1.
	RevokeSignatures int
}

func DefaultPolicy() Policy { return Policy{RevokeSignatures: 1} }

func (p Policy) need() int { return max(1, p.RevokeSignatures) }

// DeviceState — устройство в разобранном реестре.
type DeviceState struct {
	Cert      Certificate
	Revoked   bool
	RevokedAt int64
	AddedSeq  uint64
	// Trusted — действующее право подтверждать новые устройства: из сертификата либо из promote.
	Trusted bool
}

// State — результат проверки и разбора журнала.
type State struct {
	Login     string
	HubID     string
	PrevHubID string
	RootPub   ed25519.PublicKey
	Devices   map[string]*DeviceState
	Head      Head
	Policy    Policy
}

// Active возвращает сертификат, если устройство сейчас действует (привязано или доверенное, не
// отозвано, срок не истёк): такое устройство читает и пишет сообщения. Иначе — ошибка с причиной.
func (s *State) Active(deviceID string, now time.Time) (*Certificate, error) {
	d, ok := s.Devices[deviceID]
	if !ok {
		return nil, ErrNoDevice
	}
	if d.Revoked {
		return nil, ErrDeviceRevok
	}
	if d.Cert.Expired(now) {
		return nil, fmt.Errorf("%w: срок сертификата истёк", ErrUntrusted)
	}
	return &d.Cert, nil
}

// CanApprove — действует ли устройство И является ли оно доверенным (может подтверждать
// новые устройства, повышать и отзывать). Обычное привязанное устройство — ErrNotTrustedDevice.
func (s *State) CanApprove(deviceID string, now time.Time) error {
	if _, err := s.Active(deviceID, now); err != nil {
		return err
	}
	if !s.Devices[deviceID].Trusted {
		return ErrNotTrustedDevice
	}
	return nil
}

// ActiveDevices — действующие устройства, по порядку добавления.
func (s *State) ActiveDevices(now time.Time) []Certificate {
	var out []*DeviceState
	for _, d := range s.Devices {
		if !d.Revoked && !d.Cert.Expired(now) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AddedSeq < out[j].AddedSeq })
	res := make([]Certificate, len(out))
	for i, d := range out {
		res[i] = d.Cert
	}
	return res
}

// Replay с нуля проверяет весь журнал: хэши, подписи, права поручителей. Любая
// ошибка означает, что реестру верить нельзя.
func Replay(entries []Entry, pol Policy) (*State, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: пустой журнал", ErrChain)
	}
	var s *State
	prev := ""
	for i := range entries {
		e := &entries[i]
		if e.Seq != uint64(i+1) || e.PrevHash != prev || e.Hash != entryHash(e.Seq, e.PrevHash, e.Kind, e.Payload) {
			return nil, fmt.Errorf("%w: запись %d", ErrChain, i+1)
		}
		if i == 0 {
			if e.Kind != KindGenesis {
				return nil, fmt.Errorf("%w: первая запись не genesis", ErrChain)
			}
			st, err := applyGenesis(e, pol)
			if err != nil {
				return nil, err
			}
			s = st
		} else if err := s.apply(e); err != nil {
			return nil, fmt.Errorf("запись %d: %w", e.Seq, err)
		}
		prev = e.Hash
		s.Head = Head{HubID: s.HubID, Seq: e.Seq, Hash: e.Hash}
	}
	return s, nil
}

func applyGenesis(e *Entry, pol Policy) (*State, error) {
	var g Genesis
	if err := json.Unmarshal(e.Payload, &g); err != nil {
		return nil, fmt.Errorf("%w: genesis: %v", ErrFormat, err)
	}
	if len(g.RootPub) != ed25519.PublicKeySize || !ValidLogin(g.Login) {
		return nil, fmt.Errorf("%w: genesis", ErrFormat)
	}
	root := ed25519.PublicKey(g.RootPub)
	hubID := HubIDOf(root)
	c := g.Cert
	if err := c.checkShape(); err != nil {
		return nil, err
	}
	if c.IssuedBy != IssuerRoot || c.HubID != hubID || c.Login != g.Login || !c.Trusted {
		return nil, fmt.Errorf("%w: сертификат первого устройства", ErrFormat)
	}
	if !ed25519.Verify(root, c.signedBytes(), c.Sig) {
		return nil, ErrSignature
	}
	return &State{
		Login: g.Login, HubID: hubID, PrevHubID: g.PrevHubID, RootPub: root, Policy: pol,
		Devices: map[string]*DeviceState{c.DeviceID: {Cert: c, AddedSeq: e.Seq, Trusted: true}},
	}, nil
}

func (s *State) apply(e *Entry) error {
	switch e.Kind {
	case KindAdd:
		var c Certificate
		if err := json.Unmarshal(e.Payload, &c); err != nil {
			return fmt.Errorf("%w: %v", ErrFormat, err)
		}
		return s.applyAdd(c, e.Seq)
	case KindRevoke:
		var r Revocation
		if err := json.Unmarshal(e.Payload, &r); err != nil {
			return fmt.Errorf("%w: %v", ErrFormat, err)
		}
		return s.applyRevoke(r, e.PrevHash)
	case KindPromote:
		var p Promotion
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return fmt.Errorf("%w: %v", ErrFormat, err)
		}
		return s.applyPromote(p, e.PrevHash)
	}
	return fmt.Errorf("%w: тип записи %q", ErrFormat, e.Kind)
}

func (s *State) applyAdd(c Certificate, seq uint64) error {
	if err := c.checkShape(); err != nil {
		return err
	}
	if c.HubID != s.HubID || c.Login != s.Login {
		return fmt.Errorf("%w: сертификат от другого Hub", ErrFormat)
	}
	if _, dup := s.Devices[c.DeviceID]; dup {
		return fmt.Errorf("%w: устройство уже есть", ErrNotAllowed)
	}
	if c.IssuedBy == IssuerRoot {
		if !ed25519.Verify(s.RootPub, c.signedBytes(), c.Sig) {
			return ErrSignature
		}
	} else {
		issuer, ok := s.Devices[c.IssuedBy]
		if !ok || issuer.Revoked {
			return fmt.Errorf("%w: поручитель %s", ErrUntrusted, c.IssuedBy)
		}
		if !issuer.Trusted {
			return fmt.Errorf("%w: поручитель %s", ErrNotTrustedDevice, c.IssuedBy)
		}
		if !ed25519.Verify(issuer.Cert.SignPub, c.signedBytes(), c.Sig) {
			return ErrSignature
		}
	}
	s.Devices[c.DeviceID] = &DeviceState{Cert: c, AddedSeq: seq, Trusted: c.Trusted}
	return nil
}

func (s *State) applyRevoke(r Revocation, prevHash string) error {
	if r.Version != Version || r.HubID != s.HubID || r.PrevHash != prevHash {
		return fmt.Errorf("%w: отзыв не относится к этому месту журнала", ErrChain)
	}
	target, ok := s.Devices[r.DeviceID]
	if !ok {
		return ErrNoDevice
	}
	msg := r.signedBytes()
	signers := map[string]bool{}
	rootSigned := false
	for _, sg := range r.Sigs {
		if sg.Signer == IssuerRoot {
			if !ed25519.Verify(s.RootPub, msg, sg.Sig) {
				return ErrSignature
			}
			rootSigned = true
			continue
		}
		d, ok := s.Devices[sg.Signer]
		if !ok || d.Revoked || sg.Signer == r.DeviceID {
			return fmt.Errorf("%w: подписант %s", ErrUntrusted, sg.Signer)
		}
		if !d.Trusted {
			return fmt.Errorf("%w: подписант %s", ErrNotTrustedDevice, sg.Signer)
		}
		if !ed25519.Verify(d.Cert.SignPub, msg, sg.Sig) {
			return ErrSignature
		}
		signers[sg.Signer] = true
	}
	if !rootSigned && len(signers) < s.Policy.need() {
		return fmt.Errorf("%w: нужно подписей устройств: %d", ErrNotAllowed, s.Policy.need())
	}
	s.revokeDevice(target, r.At, r.Cascade)
	return nil
}

func (s *State) applyPromote(p Promotion, prevHash string) error {
	if p.Version != Version || p.HubID != s.HubID || p.PrevHash != prevHash {
		return fmt.Errorf("%w: повышение не относится к этому месту журнала", ErrChain)
	}
	target, ok := s.Devices[p.DeviceID]
	if !ok {
		return ErrNoDevice
	}
	if target.Revoked {
		return ErrDeviceRevok
	}
	if target.Trusted {
		return fmt.Errorf("%w: устройство уже доверенное", ErrNotAllowed)
	}
	msg := p.signedBytes()
	if p.Sig.Signer == IssuerRoot {
		if !ed25519.Verify(s.RootPub, msg, p.Sig.Sig) {
			return ErrSignature
		}
	} else {
		d, ok := s.Devices[p.Sig.Signer]
		if !ok || d.Revoked || p.Sig.Signer == p.DeviceID {
			return fmt.Errorf("%w: подписант %s", ErrUntrusted, p.Sig.Signer)
		}
		if !d.Trusted {
			return fmt.Errorf("%w: подписант %s", ErrNotTrustedDevice, p.Sig.Signer)
		}
		if !ed25519.Verify(d.Cert.SignPub, msg, p.Sig.Sig) {
			return ErrSignature
		}
	}
	target.Trusted = true
	return nil
}

func (s *State) revokeDevice(d *DeviceState, at int64, cascade bool) {
	if d.Revoked {
		return
	}
	d.Revoked, d.RevokedAt = true, at
	if !cascade {
		return
	}
	for _, o := range s.Devices {
		if o.Cert.IssuedBy == d.Cert.DeviceID {
			s.revokeDevice(o, at, true)
		}
	}
}

// Log — журнал реестра с добавлением записей. Используется сервером (основной
// реестр, проверяет подписи, сам ничего не подписывает) и клиентами при сборке
// локальной копии.
type Log struct {
	Entries []Entry
	Policy  Policy
	state   *State
}

// NewLog создаёт Hub: корневой ключ подписывает первое устройство. prevHubID —
// прежний Hub при сбросе идентичности (иначе пусто).
func NewLog(root *RootKey, login string, req CertRequest, prevHubID string, at time.Time, pol Policy) (*Log, error) {
	cert, err := root.IssueFirstDevice(req, at, 0)
	if err != nil {
		return nil, err
	}
	l := &Log{Policy: pol}
	if err := l.append(KindGenesis, Genesis{Login: login, RootPub: root.Pub, PrevHubID: prevHubID, Cert: cert}); err != nil {
		return nil, err
	}
	return l, nil
}

// LoadLog проверяет готовый журнал целиком.
func LoadLog(entries []Entry, pol Policy) (*Log, error) {
	st, err := Replay(entries, pol)
	if err != nil {
		return nil, err
	}
	return &Log{Entries: append([]Entry(nil), entries...), Policy: pol, state: st}, nil
}

func (l *Log) State() *State { return l.state }

func (l *Log) HeadHash() string {
	if len(l.Entries) == 0 {
		return ""
	}
	return l.Entries[len(l.Entries)-1].Hash
}

// append добавляет запись, проверяя её тем же кодом, что и Replay: некорректную запись
// в журнал не пускаем. Состояние обновляется только если запись принята.
func (l *Log) append(kind EntryKind, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e := Entry{Seq: uint64(len(l.Entries) + 1), PrevHash: l.HeadHash(), Kind: kind, Payload: raw}
	e.Hash = entryHash(e.Seq, e.PrevHash, e.Kind, e.Payload)
	candidate := append(append([]Entry(nil), l.Entries...), e)
	st, err := Replay(candidate, l.Policy)
	if err != nil {
		return err
	}
	l.Entries, l.state = candidate, st
	return nil
}

// AddDevice принимает сертификат нового устройства.
func (l *Log) AddDevice(c Certificate) error { return l.append(KindAdd, c) }

// Revoke принимает отзыв. r должен быть создан через NewRevocation с PrevHash =
// l.HeadHash() и подписан нужным числом устройств.
func (l *Log) Revoke(r *Revocation) error { return l.append(KindRevoke, r) }

// Promote принимает повышение устройства до доверенного.
func (l *Log) Promote(p *Promotion) error { return l.append(KindPromote, p) }

// CheckAgainst сравнивает реестр с ранее известной вершиной (pin): откат назад и
// расхождение истории обнаруживаются.
func (l *Log) CheckAgainst(known Head) error {
	if known.HubID != "" && known.HubID != l.state.HubID {
		return ErrUnknownHub
	}
	if known.Seq == 0 {
		return nil
	}
	if uint64(len(l.Entries)) < known.Seq {
		return ErrRollback
	}
	if l.Entries[known.Seq-1].Hash != known.Hash {
		return ErrFork
	}
	return nil
}
