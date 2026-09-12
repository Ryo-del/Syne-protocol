package protocol

import (
	"bytes"
	"testing"
)

func TestFramedMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	original := []byte("hello, framed world")

	if err := WriteFramedMessage(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := ReadFramedMessage(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(result, original) {
		t.Fatalf("got %q, want %q", result, original)
	}
}
