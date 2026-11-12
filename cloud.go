package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

// Cloud — связь школьного сервера с Syne Cloud.
//
// Ученик привязывает облачный аккаунт в Syne Study: проходит вход в браузере
// (OAuth 2.0 + PKCE) и передаёт серверу refresh-токен (CloudOpLink). Дальше
// токен хранит только сервер:
//   - сервер сам зеркалирует папку ученика в облако и обратно, в том числе
//     когда ученик не в сети;
//   - Syne Study ничего не хранит на компьютере, поэтому за коротким
//     access-токеном он обращается к серверу (CloudOpToken) и с ним ходит в
//     облако напрямую — так чаты объединяются с облачными;
//   - сервер знает, какой облачный аккаунт у какого пользователя
//     (CloudOpResolve), чтобы сопоставлять собеседников.
const CloudStreamProtocol = lpprotocol.ID("/syne/cloud/1.0.0")

const (
	CloudOpStatus  = "cloud_status"
	CloudOpLink    = "cloud_link"
	CloudOpUnlink  = "cloud_unlink"
	CloudOpToken   = "cloud_token"
	CloudOpResolve = "cloud_resolve"
	CloudOpSyncNow = "cloud_sync_now"
)

const CloudTypeResponse = "cloud_response"

// Коды ошибок CloudResponse.Code.
const (
	CloudErrUnauthorized = "unauthorized"
	CloudErrNotLinked    = "not_linked"     // аккаунт не привязан
	CloudErrLinkExpired  = "link_expired"   // облако отозвало вход, нужно привязать заново
	CloudErrAlreadyUsed  = "already_linked" // этот облачный аккаунт привязан к другому пользователю
	CloudErrDisabled     = "disabled"       // на сервере не настроен адрес облака
	CloudErrUnavailable  = "unavailable"    // облако недоступно, повторить позже
	CloudErrInvalid      = "invalid_request"
)

type CloudRequest struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	// cloud_link: refresh-токен, полученный Syne Study при входе в облако.
	RefreshToken string `json:"refresh_token,omitempty"`
	// cloud_resolve: логины школьного сервера и/или id облачных аккаунтов.
	Users    []string `json:"users,omitempty"`
	CloudIDs []string `json:"cloud_ids,omitempty"`
}

// CloudAccount — соответствие пользователя сервера и облачного аккаунта.
type CloudAccount struct {
	Login       string `json:"login"` // логин на школьном сервере
	CloudUserID string `json:"cloud_user_id"`
}

type CloudStatus struct {
	Enabled     bool   `json:"enabled"`   // на сервере задан адрес облака
	CloudURL    string `json:"cloud_url"` // куда Syne Study отправляет на вход
	Linked      bool   `json:"linked"`
	CloudUserID string `json:"cloud_user_id,omitempty"`
	CloudLogin  string `json:"cloud_login,omitempty"`
	CloudName   string `json:"cloud_name,omitempty"`
	// Состояние зеркалирования файлов.
	Syncing    bool   `json:"syncing,omitempty"`
	LastSyncAt int64  `json:"last_sync_at,omitempty"` // unix ms последней успешной синхронизации
	LastError  string `json:"last_error,omitempty"`
}

type CloudResponse struct {
	Type   string       `json:"type"`
	OK     bool         `json:"ok"`
	Code   string       `json:"code,omitempty"`
	Error  string       `json:"error,omitempty"`
	Status *CloudStatus `json:"status,omitempty"`
	// cloud_token
	AccessToken string `json:"access_token,omitempty"`
	ExpiresAt   int64  `json:"expires_at,omitempty"` // unix ms
	// cloud_resolve
	Accounts []CloudAccount `json:"accounts,omitempty"`
}
