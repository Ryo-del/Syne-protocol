package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

type WhoAmIRequest struct {
	Type string `json:"type"`
}

type WhoAmIResponse struct {
	Type   string `json:"type"`
	UserID string `json:"user_id"`
	FName  string `json:"fname"`
	SName  string `json:"sname"`
}

const (
	WhoAmITypeRequest  = "whoami_request"
	WhoAmITypeResponse = "whoami_response"
)

const WhoAmIStreamProtocol = lpprotocol.ID("/syne/whoami/1.0.0")
