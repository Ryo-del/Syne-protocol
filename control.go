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
}

type Welcome struct {
	Type          string `json:"type"`
	ServerID      string `json:"server_id"`
	ServerVersion string `json:"server_version"`
	Timestamp     int64  `json:"timestamp"`
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

func UnmarshalHello(data []byte) (Hello, error) {
	var h Hello
	if err := json.Unmarshal(data, &h); err != nil {
		return Hello{}, err
	}
	return h, nil
}

func MarshalWelcome(w Welcome) ([]byte, error) {
	return json.Marshal(w)
}

func UnmarshalWelcome(data []byte) (Welcome, error) {
	var w Welcome
	if err := json.Unmarshal(data, &w); err != nil {
		return Welcome{}, err
	}
	return w, nil
}

func MarshalReject(r Reject) ([]byte, error) {
	return json.Marshal(r)
}
func UnmarshalReject(data []byte) (Reject, error) {
	var r Reject
	if err := json.Unmarshal(data, &r); err != nil {
		return Reject{}, err
	}
	return r, nil
}

func PeekControlType(data []byte) (string, error) {
	var e controlEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		return "", err
	}
	return e.Type, nil
}
