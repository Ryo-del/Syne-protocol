package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

// FilesStreamProtocol — единый libp2p-протокол файлового менеджера.
const FilesStreamProtocol = lpprotocol.ID("/syne/files/1.0.0")

// Роли пользователей (поле users.role на сервере).
const (
	RoleStudent = "student"
	RoleTeacher = "teacher"
)

// Action — право доступа к файлу или папке.
//
// Соответствие пунктам меню:
//   - rename требует edit, duplicate требует copy;
//   - paste покрывает всё, что добавляет содержимое в папку: создать файл,
//     создать папку, вставить, загрузка с рабочего стола, перенос.
type Action string

const (
	ActionView     Action = "view"
	ActionDownload Action = "download"
	ActionCopy     Action = "copy"
	ActionSend     Action = "send"
	ActionEdit     Action = "edit"
	ActionPaste    Action = "paste"

	ActionDelete Action = "delete"
)

// AllActions — порядок, в котором права показываются в диалоге.
var AllActions = []Action{
	ActionView,
	ActionDownload,
	ActionCopy,
	ActionSend,
	ActionEdit,
	ActionPaste,
	ActionDelete,
}

func (a Action) Valid() bool {
	switch a {
	case ActionView, ActionDownload, ActionCopy, ActionSend, ActionEdit, ActionPaste, ActionDelete:
		return true
	}
	return false
}

// AppliesToFile — paste настраивается только на папках.
func (a Action) AppliesToFile() bool { return a.Valid() && a != ActionPaste }

// Mode — кому разрешено действие.
type Mode string

const (
	ModeAll      Mode = "all"      // разрешить всем
	ModeContacts Mode = "contacts" // только контактам владельца
	ModeSelected Mode = "selected" // выделенным пользователям
	ModeNone     Mode = "none"     // запретить всем
)

func (m Mode) Valid() bool {
	switch m {
	case ModeAll, ModeContacts, ModeSelected, ModeNone:
		return true
	}
	return false
}

// ACLRule — правило для диалога «Настроить права».
// Inherited=true: правило не задано на самом элементе, а унаследовано от папки
// выше (или это значение по умолчанию «запретить всем»).
type ACLRule struct {
	Action    Action   `json:"action"`
	Mode      Mode     `json:"mode"`
	Users     []string `json:"users,omitempty"` // логины, только для ModeSelected
	Inherited bool     `json:"inherited"`
}

// FileEntry — элемент списка папки.
type FileEntry struct {
	Name      string `json:"name"` // для корня чужой папки — «Фамилия Имя» владельца
	Path      string `json:"path"` // относительно папки владельца, разделитель "/"
	IsDir     bool   `json:"is_dir"`
	Size      int64  `json:"size"`
	ModTime   int64  `json:"mod_time"`          // unix ms
	Owner     string `json:"owner"`             // логин владельца папки
	OwnerName string `json:"owner_name"`        // «Фамилия Имя» владельца
	Snippet   string `json:"snippet,omitempty"` // search: строка с совпадением в содержимом
	// Can — что разрешено текущему пользователю (для серых пунктов меню).
	// Ключи: настраиваемые действия плюс производные CapOpen, CapRename,
	// CapDuplicate.
	Can map[Action]bool `json:"can,omitempty"`
}

// Производные возможности для FileEntry.Can (отдельно не настраиваются).
const (
	CapOpen      Action = "open"      // view и файл .txt
	CapRename    Action = "rename"    // edit (для файлов только .txt) или владелец/преподаватель
	CapDuplicate Action = "duplicate" // copy на элементе и paste в его папке
)

// QuotaInfo — индикатор занятого места.
type QuotaInfo struct {
	UsedBytes  int64 `json:"used_bytes"`
	LimitBytes int64 `json:"limit_bytes"`
	Unlimited  bool  `json:"unlimited"`
}

// Коды ошибок файлового протокола.
const (
	FilesErrUnauthorized   = "unauthorized"
	FilesErrForbidden      = "forbidden"
	FilesErrNotFound       = "not_found"
	FilesErrExists         = "exists"
	FilesErrQuota          = "quota_exceeded"
	FilesErrInvalidPath    = "invalid_path"
	FilesErrInvalidRequest = "invalid_request"
	FilesErrConflict       = "conflict"
	FilesErrInternal       = "internal"
	FilesOpBlockedPut      = "blocked_put"
)

// FilesMaxFrame — максимальный размер JSON-кадра ответа (списки папок бывают большими).
// Клиент читает ответ через ReadFramedMessageMax(stream, FilesMaxFrame).
const FilesMaxFrame uint32 = 16 << 20

// Операции. Этап 2а: всё, кроме помеченного «этап 2б».
const (
	FilesOpListOwners  = "list_owners" // папки других пользователей, видимые мне («Сервер»)
	FilesOpList        = "list"
	FilesOpStat        = "stat"
	FilesOpMkdir       = "mkdir"  // owner/path — родитель, name — имя
	FilesOpCreate      = "create" // пустой файл: owner/path — родитель, name — имя
	FilesOpRename      = "rename" // owner/path — элемент, name — новое имя
	FilesOpDelete      = "delete"
	FilesOpPaste       = "paste"     // копирование: owner/path — источник, dest_owner/dest_path — папка
	FilesOpDuplicate   = "duplicate" // копия рядом с оригиналом
	FilesOpRulesGet    = "rules_get"
	FilesOpRuleSet     = "rule_set"
	FilesOpRuleClear   = "rule_clear"
	FilesOpQuota       = "quota"
	FilesOpFavAdd      = "fav_add"
	FilesOpFavRemove   = "fav_remove"
	FilesOpFavList     = "fav_list"
	FilesOpUIGet       = "ui_get"
	FilesOpUIPut       = "ui_put"
	FilesOpContactsPut = "contacts_put"

	// Этап 2б (потоковые операции, поиск, отправка).
	FilesOpRead        = "read"
	FilesOpWrite       = "write"
	FilesOpUpload      = "upload"
	FilesOpDownload    = "download"
	FilesOpDownloadDir = "download_dir"
	FilesOpSearch      = "search"
	FilesOpSend        = "send"
)

// Что делать при совпадении имени (FilesRequest.OnConflict).
// Пустое значение — вернуть ошибку FilesErrExists.
const (
	ConflictRename  = "rename"  // «имя (1).txt»
	ConflictReplace = "replace" // заменить (нужно право удаления существующего)
	ConflictSkip    = "skip"    // ничего не делать
)

// FilesRequest — запрос (JSON-кадр). Заполняются только поля нужной операции.
type FilesRequest struct {
	Op        string `json:"op"`
	SessionID string `json:"session_id"`

	Owner string `json:"owner,omitempty"` // чья папка; пусто — своя
	Path  string `json:"path,omitempty"`  // относительно папки владельца
	Name  string `json:"name,omitempty"`  // новое имя (mkdir, create, rename)

	DestOwner  string `json:"dest_owner,omitempty"` // paste, send; пусто — своя
	DestPath   string `json:"dest_path,omitempty"`
	OnConflict string `json:"on_conflict,omitempty"`

	Action Action   `json:"action,omitempty"` // rule_set, rule_clear
	Mode   Mode     `json:"mode,omitempty"`
	Users  []string `json:"users,omitempty"`

	Size        int64 `json:"size,omitempty"`          // upload, write (этап 2б)
	BaseModTime int64 `json:"base_mod_time,omitempty"` // write: версия, с которой начали правку

	Query   string `json:"query,omitempty"` // search (этап 2б)
	Content bool   `json:"content,omitempty"`
	Limit   int    `json:"limit,omitempty"`

	Data     string   `json:"data,omitempty"`     // ui_put: JSON настроек интерфейса
	Contacts []string `json:"contacts,omitempty"` // contacts_put: логины контактов
	Blocked  []string `json:"blocked,omitempty"`  // blocked_put: логины заблокированных
}

type FilesResponse struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`

	Ready bool `json:"ready,omitempty"` // upload/write: сервер готов принять байты

	Entry     *FileEntry  `json:"entry,omitempty"`
	Entries   []FileEntry `json:"entries,omitempty"`
	Truncated bool        `json:"truncated,omitempty"` // список обрезан по лимиту
	Rules     []ACLRule   `json:"rules,omitempty"`
	Quota     *QuotaInfo  `json:"quota,omitempty"`
	Data      string      `json:"data,omitempty"`    // ui_get
	Skipped   int         `json:"skipped,omitempty"` // paste, upload: сколько элементов пропущено
}
