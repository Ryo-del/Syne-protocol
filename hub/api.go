package hub

// APIVersion — версия API реестра (protocol_version из фронта работ, п. 3.11).
// Сервер отвечает ErrCodeUnsupported, если клиент новее, а старые клиенты Hub не
// используют вовсе — режим совместимости: пока у собеседника нет Hub, действует схема 1.
const APIVersion = 1

// Операции потока.
const (
	OpInfo      = "info"       // свой login@org и открыт ли сброс идентичности
	OpCreate    = "create"     // создать Hub (genesis)
	OpRegistry  = "registry"   // получить журнал по логину
	OpHead      = "head"       // только вершина
	OpRequest   = "request"    // запросить регистрацию устройства
	OpPending   = "pending"    // свои ожидающие запросы
	OpApprove   = "approve"    // подтвердить: приложить сертификат
	OpReject    = "reject"     // отклонить запрос
	OpRevoke    = "revoke"     // отозвать устройство
	OpRecovery  = "recovery"   // получить/сохранить зашифрованную копию Root Key
	OpPutBackup = "put_backup" // сохранить зашифрованную копию Root Key
	OpPutDevice = "put_device" // сохранить зашифрованный blob устройства Study (ключ устройства, закладки доверия)
	OpGetDevice = "get_device" // получить его
)

// Коды ошибок (поле Code в ответе).
const (
	ErrCodeUnauthorized = "unauthorized"
	ErrCodeBadRequest   = "bad_request"
	ErrCodeInvalid      = "invalid"   // запись не прошла проверку подписей/цепочки
	ErrCodeExists       = "exists"    // Hub уже создан
	ErrCodeNotFound     = "not_found" // у логина нет Hub
	ErrCodeConflict     = "conflict"  // журнал изменился, повторите с новым PrevHash
	ErrCodeLimit        = "limit"     // слишком много ожидающих запросов
	ErrCodeResetNeeded  = "reset_needed"
	ErrCodeUnsupported  = "unsupported"
	ErrCodeInternal     = "internal"
)

// Request — запрос к реестру. Аутентификация — сессия сервера (SessionID) либо, для
// запросов через облако, подпись лицензии на стороне облака.
type Request struct {
	Version   int    `json:"v"`
	SessionID string `json:"session_id,omitempty"`
	Op        string `json:"op"`
	Login     string `json:"login,omitempty"` // чей реестр (для registry/head); для остальных — владелец сессии

	Genesis    *Entry       `json:"genesis,omitempty"`    // create
	Req        *CertRequest `json:"req,omitempty"`        // request
	Cert       *Certificate `json:"cert,omitempty"`       // approve
	Revocation *Revocation  `json:"revocation,omitempty"` // revoke
	DeviceID   string       `json:"device_id,omitempty"`  // reject
	Backup     []byte       `json:"backup,omitempty"`     // put_backup
	Blob       []byte       `json:"blob,omitempty"`       // put_device
	After      uint64       `json:"after,omitempty"`      // registry: только записи с seq > After
}

// PendingRequest — запрос на регистрацию, ожидающий подтверждения.
type PendingRequest struct {
	Req       CertRequest `json:"req"`
	PairCode  string      `json:"pair_code"`
	CreatedAt int64       `json:"created_at"`
	ExpiresAt int64       `json:"expires_at"`
	Via       string      `json:"via,omitempty"` // "cloud" | "server"
}

// Response — ответ реестра.
type Response struct {
	OK        bool             `json:"ok"`
	Code      string           `json:"code,omitempty"`
	Error     string           `json:"error,omitempty"`
	Entries   []Entry          `json:"entries,omitempty"`
	Head      *Head            `json:"head,omitempty"`
	Pending   []PendingRequest `json:"pending,omitempty"`
	Backup    []byte           `json:"backup,omitempty"`
	Blob      []byte           `json:"blob,omitempty"`
	Login     string           `json:"login,omitempty"`      // info: login@org владельца сессии
	CloudURL  string           `json:"cloud_url,omitempty"`  // info: адрес Syne Cloud (Hub-входящие), если настроен
	ResetOpen bool             `json:"reset_open,omitempty"` // info: администратор открыл сброс идентичности
}

// MirrorPush — то, что сервер колледжа отправляет облаку (зеркало реестра).
type MirrorPush struct {
	Login   string  `json:"login"`
	Entries []Entry `json:"entries"` // журнал целиком или хвост после Head облака
	From    uint64  `json:"from"`    // seq первой записи в Entries (1 — с начала)
}

// MirrorHeads — вершины, которые облако уже имеет (ответ на push и на запрос сверки).
type MirrorHeads struct {
	Heads map[string]Head `json:"heads"`
}
