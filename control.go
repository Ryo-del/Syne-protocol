package protocol

import (
	"encoding/json"
	"time"

	lpprotocol "github.com/libp2p/go-libp2p/core/protocol"
)

type Hello struct {
	PeerID          string `json:"peer_id"`
	ProtocolVersion uint8  `json:"protocol_version"`
	Timestamp       int64  `json:"timestamp"`
	ClientVersion   string `json:"client_version,omitempty"`
}

// ClientVersion is updated with the client release build and is sent in the server handshake.
var ClientVersion = "0.1.0-dev"

type Welcome struct {
	Type          string `json:"type"`
	ServerID      string `json:"server_id"`
	ServerVersion string `json:"server_version"`
	Timestamp     int64  `json:"timestamp"`
	ClientUpdate  *ClientUpdate `json:"client_update,omitempty"`
	HTTPPort      int    `json:"http_port,omitempty"`
}

type ClientUpdate struct {
	Version string `json:"version"`
	Name string `json:"name"`
	SHA256 string `json:"sha256"`
	Size int64 `json:"size"`
	Signature string `json:"signature"`
	DownloadPath string `json:"download_path"`
	DownloadURL string `json:"download_url,omitempty"`
	ReleaseNotes string `json:"release_notes,omitempty"`
}
type Reject struct {
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Timestamp int64  `json:"timestamp"`
}
type controlEnvelope struct {
	Type string `json:"type"`
}

const (
	StreamProtocol            = lpprotocol.ID("/syne/control/1.0.0")
	DefaultReadDeadline       = 5 * time.Second
	DefaultReadLimit    int64 = 256 * 1024
)
const (
	ControlTypeWelcome = "welcome"
	ControlTypeReject  = "reject"
)

func MarshalHello(h Hello) ([]byte, error) {
	return json.Marshal(h)
}

func MarshalJSON[T any](v T) ([]byte, error) {
	return json.Marshal(v)
}

func UnmarshalJSON[T any](data []byte) (T, error) {
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		var zero T
		return zero, err
	}
	return v, nil
}

func PeekType(data []byte) (string, error) {
	var e controlEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		return "", err
	}
	return e.Type, nil
}
