package protocol

import (
	"testing"
	"time"
)

func TestWelcomeMarshalUnmarshal(t *testing.T) {
	original := Welcome{
		ServerID:      "1",
		ServerVersion: "1",
		Timestamp:     time.Now().UnixMilli(),
	}

	data, err := MarshalJSON(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	result, err := UnmarshalJSON[Welcome](data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result != original {
		t.Fatalf("got %+v, want %+v", result, original)
	}
}

func TestHelloMarshalUnmarshal(t *testing.T) {
	original := Hello{
		PeerID:          "1",
		ProtocolVersion: ProtocolVersion,
		Timestamp:       time.Now().UnixMilli(),
	}

	data, err := MarshalHello(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	result, err := UnmarshalJSON[Hello](data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result != original {
		t.Fatalf("got %+v, want %+v", result, original)
	}
}
