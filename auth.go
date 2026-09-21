package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

type RegisterRequest struct {
	Type                 string `json:"type"`
	FName                string `json:"fname"`
	SName                string `json:"sname"`
	Role                 string `json:"role"`
	Login                string `json:"login"`
	PasswordHash         []byte `json:"password_hash"`
	PasswordSalt         []byte `json:"password_salt"`
	LoginKeySalt         []byte `json:"login_key_salt"`
	EncryptedMasterKey   []byte `json:"encrypted_master_key"`
	IdentityPublicKey    []byte `json:"identity_public_key"`
	EncryptedIdentityKey []byte `json:"encrypted_identity_key"`
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
	Type                 string `json:"type"`
	SessionID            string `json:"session_id"`
	FName                string `json:"fname"`
	SName                string `json:"sname"`
	EncryptedMasterKey   []byte `json:"encrypted_master_key"`
	IdentityPublicKey    []byte `json:"identity_public_key"`
	EncryptedIdentityKey []byte `json:"encrypted_identity_key"`
}

type LoginFailure struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// Claim* — активация аккаунта, созданного лаборантом (login + claimCode),
// и одновременное задание собственного пароля учеником.
type ClaimRequest struct {
	Type                 string `json:"type"`
	Login                string `json:"login"`
	ClaimCode            string `json:"claim_code"`
	PasswordHash         []byte `json:"password_hash"`
	PasswordSalt         []byte `json:"password_salt"`
	LoginKeySalt         []byte `json:"login_key_salt"`
	EncryptedMasterKey   []byte `json:"encrypted_master_key"`
	IdentityPublicKey    []byte `json:"identity_public_key"`
	EncryptedIdentityKey []byte `json:"encrypted_identity_key"`
}

type ClaimSuccess struct {
	Type                 string `json:"type"`
	SessionID            string `json:"session_id"`
	FName                string `json:"fname"`
	SName                string `json:"sname"`
	EncryptedMasterKey   []byte `json:"encrypted_master_key"`
	IdentityPublicKey    []byte `json:"identity_public_key"`
	EncryptedIdentityKey []byte `json:"encrypted_identity_key"`
}

type ClaimFailure struct {
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

	AuthTypeClaimRequest = "claim_request"
	AuthTypeClaimSuccess = "claim_success"
	AuthTypeClaimFailure = "claim_failure"
)

const AuthStreamProtocol = lpprotocol.ID("/syne/auth/1.0.0")
