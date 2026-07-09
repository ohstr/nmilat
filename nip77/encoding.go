package nip77

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
)

// ToBytes encodes the message to binary format
func (msg *Message) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(msg.ProtocolVersion)

	lastTimestamp := uint64(0)

	for _, r := range msg.Ranges {
		// Encode Bound
		// Bound := <encodedTimestamp (Varint)> <length (Varint)> <idPrefix (Byte)>*

		// encodedTimestamp = 1 + offset (if not infinity)
		// offset = timestamp - lastTimestamp
		var encodedTimestamp uint64
		if r.UpperBound.Timestamp == InfiniteTimestamp {
			encodedTimestamp = 0
		} else {
			offset := r.UpperBound.Timestamp - lastTimestamp
			encodedTimestamp = 1 + offset
			lastTimestamp = r.UpperBound.Timestamp
		}
		buf.Write(encodeVarint(encodedTimestamp))

		// ID Prefix
		buf.Write(encodeVarint(uint64(len(r.UpperBound.IDPrefix))))
		buf.Write(r.UpperBound.IDPrefix)

		// Mode — single byte per the reference implementation
		buf.WriteByte(byte(r.Mode))

		// Payload
		// Mode 0: Skip (empty)
		// Mode 1: Fingerprint (16 bytes)
		// Mode 2: IdList := <length (Varint)> <ids (Id)>*

		switch r.Mode {
		case 0: // Skip
			// nothing
		case 1: // Fingerprint
			if len(r.Payload) != 16 {
				return nil, fmt.Errorf("invalid fingerprint length: %d", len(r.Payload))
			}
			buf.Write(r.Payload)
		case 2: // IdList
			// Payload in struct is raw bytes? Or we should have a better struct?
			// Let's assume Payload holds the raw bytes of IdList content (excluding length prefix? No, let's say Payload IS the content)
			// Wait, for Mode 2, we probably want to construct it properly.
			// Re-reading Negentropy.go struct: Payload []byte.
			// For Mode 2, let's assume Payload includes the Varint Length + IDs?
			// Or better, let's make `Range` struct smarter?
			// For now, let's assume Payload is pre-encoded for Mode 2.
			buf.Write(r.Payload)
		default:
			return nil, fmt.Errorf("unknown mode: %d", r.Mode)
		}
	}

	return buf.Bytes(), nil
}

// FromBytes decodes the message from binary format
func FromBytes(data []byte) (*Message, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("message too short")
	}

	msg := &Message{
		ProtocolVersion: data[0],
	}

	if msg.ProtocolVersion != ProtocolVersion1 {
		// Spec says: "If a server receives a message with a protocol version that it cannot handle, it should reply with a single byte containing the highest protocol version it supports"
		// We are implementing server/relay side logic mostly, but also client logic for tests.
		// For now, allow it, but caller checks.
		// actually, return error
		return nil, fmt.Errorf("unsupported protocol version: %x", msg.ProtocolVersion)
	}

	buf := bytes.NewReader(data[1:])
	lastTimestamp := uint64(0)

	for buf.Len() > 0 {
		r := Range{}

		// Bound
		encodedTimestamp, err := decodeReaderVarint(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read timestamp: %w", err)
		}

		if encodedTimestamp == 0 {
			r.UpperBound.Timestamp = InfiniteTimestamp
		} else {
			offset := encodedTimestamp - 1
			r.UpperBound.Timestamp = lastTimestamp + offset
			lastTimestamp = r.UpperBound.Timestamp
		}

		prefixLen, err := decodeReaderVarint(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to read prefix len: %w", err)
		}

		r.UpperBound.IDPrefix = make([]byte, prefixLen)
		if _, err := io.ReadFull(buf, r.UpperBound.IDPrefix); err != nil {
			return nil, fmt.Errorf("failed to read prefix: %w", err)
		}

		// Mode — single byte
		modeByte, err := buf.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read mode: %w", err)
		}
		r.Mode = int(modeByte)

		// Payload
		switch r.Mode {
		case 0: // Skip
			// empty
		case 1: // Fingerprint
			r.Payload = make([]byte, 16)
			if _, err := io.ReadFull(buf, r.Payload); err != nil {
				return nil, fmt.Errorf("failed to read fingerprint: %w", err)
			}
		case 2: // IdList
			// Read Length (Varint)
			// Then Read Length * 32 bytes
			// But we need to peek/buffer?
			// Wait, logic says: IdList := <length (Varint)> <ids (Id)>*
			// We can decode the varint to know how many IDs, then read them.
			// But we want to store them in Payload or parsed?
			// Let's parse them if we can, but `Range` struct has `Payload []byte`.
			// Let's store the raw bytes of IdList (Length+IDs) in Payload for now,
			// or change Range struct.
			// To keep it simple, let's decode the length, then read the bytes, and put everything in Payload.

			// We need to read the Varint again *without consuming*? No, we consume it.
			// But `Payload` field should probably be `IDs []string` or something?
			// `negentropy.go` defined `Payload []byte`.

			// Let's decode the length to know how much to read.
			// The length varint is part of the payload.

			// Hack: Read varint bytes.
			// io.ByteScanner?

			lengthVal, n, err := readVarintBytes(buf) // Custom helper needed
			if err != nil {
				return nil, err
			}

			idsLen := lengthVal * 32
			idsBytes := make([]byte, idsLen)
			if _, err := io.ReadFull(buf, idsBytes); err != nil {
				return nil, err
			}

			// Reconstruct payload
			r.Payload = make([]byte, 0, int(n)+int(idsLen))
			// We need the bytes of the varint we just read.
			// Since readVarintBytes return val and bytes count 'n', we can re-encode 'val'
			r.Payload = append(r.Payload, encodeVarint(lengthVal)...)
			r.Payload = append(r.Payload, idsBytes...)

		default:
			return nil, fmt.Errorf("unknown mode: %d", r.Mode)
		}

		msg.Ranges = append(msg.Ranges, r)
	}

	return msg, nil
}

// decodeReaderVarint reads a MSB-first varint from an io.ByteReader.
func decodeReaderVarint(r interface{ ReadByte() (byte, error) }) (uint64, error) {
	var res uint64
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		res = (res << 7) | uint64(b&0x7F)
		if (b & 0x80) == 0 {
			return res, nil
		}
	}
}

// readVarintBytes reads a MSB-first varint and returns its value and byte count.
func readVarintBytes(r interface{ ReadByte() (byte, error) }) (uint64, int, error) {
	var res uint64
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		res = (res << 7) | uint64(b&0x7F)
		if (b & 0x80) == 0 {
			return res, i + 1, nil
		}
	}
}

// Hex wrappers
func (msg *Message) ToHex() (string, error) {
	b, err := msg.ToBytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func FromHex(h string) (*Message, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return FromBytes(b)
}
