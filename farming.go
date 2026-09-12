package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

func WriteFramedMessage(w io.Writer, data []byte) error {
	lenght := uint32(len(data))

	if err := binary.Write(w, binary.BigEndian, lenght); err != nil {
		return err
	}

	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

func ReadFramedMessage(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)

	if length > uint32(DefaultReadLimit) {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}
