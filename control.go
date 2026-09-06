package protocol

import "encoding/json"

type Hello struct {
	PeerID          string `json:"peer_id"`
	ProtocolVersion uint8  `json:"protocol_version"`
	Timestamp       int64  `json:"timestamp"`
}

type Welcome struct {
	ServerID      string `json:"server_id"`
	ServerVersion string `json:"server_version"`
	Timestamp     int64  `json:"timestamp"`
}

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
