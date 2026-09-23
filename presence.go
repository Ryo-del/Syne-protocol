package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

// PresenceUser — данные о человеке, которые сервер держит и рассылает,
// пока тот в сети. PeerID нужен, чтобы можно было открыть чат сразу по
// клику в nearby-списке, не спрашивая пользователя об адресе.
type PresenceUser struct {
	UserID string `json:"user_id"`
	PeerID string `json:"peer_id"`
	FName  string `json:"fname"`
	SName  string `json:"sname"`
}

type PresenceOnline struct {
	Type   string `json:"type"`
	UserID string `json:"user_id"`
	PeerID string `json:"peer_id"`
	FName  string `json:"fname"`
	SName  string `json:"sname"`
}

type PresenceSnapshot struct {
	Type  string         `json:"type"`
	Users []PresenceUser `json:"users"`
}

type PresenceUpdate struct {
	Type   string       `json:"type"`
	User   PresenceUser `json:"user"`
	Status string       `json:"status"`
}

const (
	PresenceTypeOnline   = "presence_online"
	PresenceTypeSnapshot = "presence_snapshot"
	PresenceTypeUpdate   = "presence_update"
)

const (
	PresenceStatusOnline  = "online"
	PresenceStatusOffline = "offline"
)

const PresenceStreamProtocol = lpprotocol.ID("/syne/presence/1.0.0")
