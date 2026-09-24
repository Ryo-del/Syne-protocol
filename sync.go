package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

	lpprotocol "github.com/libp2p/go-libp2p/core/protocol"
)

// Sync — единственный канал клиент <-> сервер для данных пользователя:
//   - vault: зашифрованный master key'ем клиента слепок всех данных
//     (история, контакты, чёрный список). Сервер видит только blob.
//   - mailbox: подписанные и зашифрованные сообщения для тех, кто офлайн.
//   - key_lookup: публичный identity-ключ другого пользователя (нужен, чтобы
//     зашифровать сообщение даже когда адресат офлайн).
const SyncStreamProtocol = lpprotocol.ID("/syne/sync/1.0.0")

// Vault может быть большим — лимит выше, чем DefaultReadLimit.
const SyncMaxFrame uint32 = 64 * 1024 * 1024

const (
	SyncOpVaultGet     = "vault_get"
	SyncOpVaultPut     = "vault_put"
	SyncOpKeyLookup    = "key_lookup"
	SyncOpMailboxPush  = "mailbox_push"
	SyncOpMailboxFetch = "mailbox_fetch"
	SyncOpMailboxAck   = "mailbox_ack"
	SyncOpLogout       = "logout"
)

const SyncTypeResponse = "sync_response"

type SyncRequest struct {
	Type      string  `json:"type"`
	SessionID string  `json:"session_id"`
	UserID    string  `json:"user_id,omitempty"` // key_lookup / mailbox_push: чей ключ / кому
	Data      []byte  `json:"data,omitempty"`    // vault_put / mailbox_push
	IDs       []int64 `json:"ids,omitempty"`     // mailbox_ack
}

type MailboxItem struct {
	ID   int64  `json:"id"`
	Data []byte `json:"data"`
}

type SyncResponse struct {
	Type              string        `json:"type"`
	OK                bool          `json:"ok"`
	Error             string        `json:"error,omitempty"`
	Exists            bool          `json:"exists,omitempty"`
	Data              []byte        `json:"data,omitempty"`
	FName             string        `json:"fname,omitempty"`
	SName             string        `json:"sname,omitempty"`
	IdentityPublicKey []byte        `json:"identity_public_key,omitempty"`
	Items             []MailboxItem `json:"items,omitempty"`
}

// ReadFramedMessageMax — как ReadFramedMessage, но с явным лимитом размера.
func ReadFramedMessageMax(r io.Reader, max uint32) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length > max {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
