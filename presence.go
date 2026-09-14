package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

type PresenceOnline struct {
	Type   string `json:"type"`
	UserID string `json:"user_id"`
}

type PresenceSnapshot struct {
	Type  string   `json:"type"`
	Users []string `json:"users"`
}

type PresenceUpdate struct {
	Type   string `json:"type"`
	UserID string `json:"user_id"`
	Status string `json:"status"`
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
