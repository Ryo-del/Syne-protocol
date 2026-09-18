package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

type GetIdentityKeyRequest struct {
	Type string `json:"type"`
}

type GetIdentityKeyResponse struct {
	Type              string `json:"type"`
	IdentityPublicKey []byte `json:"identity_public_key"`
}

const (
	IdentityKeyTypeRequest  = "identity_key_request"
	IdentityKeyTypeResponse = "identity_key_response"
)

const IdentityKeyStreamProtocol = lpprotocol.ID("/syne/identity-key/1.0.0")
