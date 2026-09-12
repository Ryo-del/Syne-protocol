package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

type RegisterRequest struct {
	Type               string `json:"type"`
	FName              string `json:"fname"`
	SName              string `json:"sname"`
	Login              string `json:"login"`
	PasswordHash       []byte `json:"password_hash"`
	PasswordSalt       []byte `json:"password_salt"`
	LoginKeySalt       []byte `json:"login_key_salt"`
	EncryptedMasterKey []byte `json:"encrypted_master_key"`
}

type RegisterSuccess struct {
	Type string `json:"type"`
}

type RegisterFailure struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type LoginRequest struct {
	Type  string `json:"type"`
	Login string `json:"login"`
}

type LoginChallenge struct {
	Type         string `json:"type"`
	PasswordSalt []byte `json:"password_salt"`
	LoginKeySalt []byte `json:"login_key_salt"`
}

type LoginVerify struct {
	Type         string `json:"type"`
	Login        string `json:"login"`
	PasswordHash []byte `json:"password_hash"`
}

type LoginSuccess struct {
	Type               string `json:"type"`
	FName              string `json:"fname"`
	SName              string `json:"sname"`
	SessionID          string `json:"session_id"`
	EncryptedMasterKey []byte `json:"encrypted_master_key"`
}

type LoginFailure struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

const (
	AuthTypeRegisterRequest = "register_request"
	AuthTypeRegisterSuccess = "register_success"
	AuthTypeRegisterFailure = "register_failure"

	AuthTypeLoginRequest   = "login_request"
	AuthTypeLoginChallenge = "login_challenge"
	AuthTypeLoginVerify    = "login_verify"
	AuthTypeLoginSuccess   = "login_success"
	AuthTypeLoginFailure   = "login_failure"
)

const AuthStreamProtocol = lpprotocol.ID("/syne/auth/1.0.0")
