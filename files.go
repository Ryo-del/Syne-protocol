package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

// FilesStreamProtocol — единый libp2p-протокол файлового менеджера.
// Сами запросы и ответы добавляются на этапе 2; здесь только общий словарь.
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
	ActionDelete   Action = "delete"
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
	Name    string `json:"name"`
	Path    string `json:"path"` // относительно папки владельца, разделитель "/"
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mod_time"` // unix ms
	// Can — что разрешено текущему пользователю (для серых пунктов меню).
	Can map[Action]bool `json:"can,omitempty"`
}

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
)
