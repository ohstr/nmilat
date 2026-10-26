package credcodec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

// TLV types of a connection string (NIP-CASH §The Cash Hub Connection,
// §Connection Signatures; NIP-CO's cashorder1 and NIP-CW's circlehub1 share them).
const (
	TLVPubkey      uint8 = 0
	TLVRelay       uint8 = 1
	TLVSecret      uint8 = 2
	TLVLabel       uint8 = 3
	TLVHubIdentity uint8 = 4
	TLVSignature   uint8 = 5
	TLVChain       uint8 = 6
)

const (
	keyLen = 32
	sigLen = 65
	// MaxChainLen bounds a chain name.
	MaxChainLen = 32
)

var (
	// ErrConnUnsigned is a connection string whose TLV 4 or 5 is missing, repeated
	// or of the wrong length.
	ErrConnUnsigned = errors.New("connection string is not signed: TLV 4 and 5 are required")
	// ErrChainName is a TLV 6 that is missing, repeated or not a valid chain name.
	ErrChainName = errors.New("connection string carries no valid chain name (TLV 6)")
	// ErrBlankRelayHint is an empty or whitespace-only relay hint an encoder was
	// asked to write.
	ErrBlankRelayHint = errors.New("relay hint is empty")
	// ErrNonASCIIRelayHint is a relay hint with a non-ASCII byte.
	ErrNonASCIIRelayHint = errors.New("relay hint is not ASCII")
)

// ValidChainName reports a chain name of 1 to 32 bytes of a-z, 0-9 and '-'.
func ValidChainName(s string) bool {
	if len(s) < 1 || len(s) > MaxChainLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// Conn is a decoded connection string. Pubkey and HubIdentity are 64 lowercase
// hex; Relays are kept exactly as encoded; HasLabel distinguishes an absent TLV 3
// from an empty one.
type Conn struct {
	Pubkey      string
	Relays      []string
	Secret      string
	Label       string
	HasLabel    bool
	HubIdentity string
	Signature   []byte
	Chain       string
}

// EmittedRelays are the hints an encoder writes: the non-blank ones, in order.
func EmittedRelays(relays []string) []string {
	var out []string
	for _, r := range relays {
		if !IsBlankHint(r) {
			out = append(out, r)
		}
	}
	return out
}

// EncodeConn writes c under hrp in ascending type order: 0, 1..., 2, 3, 4, 5, 6.
// It skips blank hints, refuses non-ASCII or over-long ones and a connection with
// no usable hint, an empty label with HasLabel, and an unsigned or malformed 4/5/6.
func EncodeConn(hrp string, c Conn) (string, error) {
	pubkey, err := keyBytes(c.Pubkey, "pubkey")
	if err != nil {
		return "", err
	}
	secret, err := keyBytes(c.Secret, "secret")
	if err != nil {
		return "", err
	}
	identity, err := keyBytes(c.HubIdentity, "hub identity")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrConnUnsigned, err)
	}
	if len(c.Signature) != sigLen {
		return "", fmt.Errorf("%w: signature is %d bytes, want %d", ErrConnUnsigned, len(c.Signature), sigLen)
	}
	if !ValidChainName(c.Chain) {
		return "", fmt.Errorf("%w: %q", ErrChainName, c.Chain)
	}
	relays := EmittedRelays(c.Relays)
	if len(relays) == 0 {
		return "", errors.New("a connection needs at least one non-empty relay url, or nobody can reach the hub")
	}
	for _, r := range relays {
		if !IsASCII(r) {
			return "", fmt.Errorf("%w: %q", ErrNonASCIIRelayHint, r)
		}
		if len(r) > MaxTLVValueLen {
			return "", fmt.Errorf("relay url exceeds %d bytes: %q", MaxTLVValueLen, r)
		}
	}
	if c.HasLabel && c.Label == "" {
		return "", errors.New("an encoder never emits an empty label")
	}
	if len(c.Label) > MaxTLVValueLen {
		return "", fmt.Errorf("label exceeds %d bytes", MaxTLVValueLen)
	}

	buf := &bytes.Buffer{}
	WriteTLV(buf, TLVPubkey, pubkey)
	for _, r := range relays {
		WriteTLV(buf, TLVRelay, []byte(r))
	}
	WriteTLV(buf, TLVSecret, secret)
	if c.Label != "" {
		WriteTLV(buf, TLVLabel, []byte(c.Label))
	}
	WriteTLV(buf, TLVHubIdentity, identity)
	WriteTLV(buf, TLVSignature, c.Signature)
	WriteTLV(buf, TLVChain, []byte(c.Chain))
	return EncodeBech32(hrp, buf.Bytes())
}

// DecodeConn parses a connection string of HRP wantHRP. It refuses a missing
// 0/2/4/5/6, a wrong-length 0/2/4/5, a malformed 6, a repeated single field, no
// usable relay hint and truncated data, and ignores a type above 6. It never
// verifies the signature.
func DecodeConn(s, wantHRP string) (Conn, error) {
	hrp, data, err := DecodeBech32(s)
	if err != nil {
		return Conn{}, err
	}
	if hrp != wantHRP {
		return Conn{}, fmt.Errorf("unexpected hrp %q, want %q", hrp, wantHRP)
	}
	var c Conn
	seen := map[uint8]bool{}
	for curr := 0; curr < len(data); {
		typ, value, ok := ReadTLV(data[curr:])
		if !ok {
			return Conn{}, fmt.Errorf("truncated TLV entry at offset %d", curr)
		}
		curr += 2 + len(value)
		if typ != TLVRelay && typ <= TLVChain {
			if seen[typ] {
				switch typ {
				case TLVHubIdentity, TLVSignature:
					return Conn{}, fmt.Errorf("%w: TLV %d repeated", ErrConnUnsigned, typ)
				case TLVChain:
					return Conn{}, fmt.Errorf("%w: repeated", ErrChainName)
				}
				return Conn{}, fmt.Errorf("duplicate TLV %d entry", typ)
			}
			seen[typ] = true
		}
		switch typ {
		case TLVPubkey:
			if len(value) != keyLen {
				return Conn{}, fmt.Errorf("pubkey must be %d bytes, got %d", keyLen, len(value))
			}
			c.Pubkey = hex.EncodeToString(value)
		case TLVRelay:
			c.Relays = append(c.Relays, string(value))
		case TLVSecret:
			if len(value) != keyLen {
				return Conn{}, fmt.Errorf("secret must be %d bytes, got %d", keyLen, len(value))
			}
			c.Secret = hex.EncodeToString(value)
		case TLVLabel:
			c.Label, c.HasLabel = string(value), true
		case TLVHubIdentity:
			if len(value) != keyLen {
				return Conn{}, fmt.Errorf("%w: hub identity is %d bytes, want %d", ErrConnUnsigned, len(value), keyLen)
			}
			c.HubIdentity = hex.EncodeToString(value)
		case TLVSignature:
			if len(value) != sigLen {
				return Conn{}, fmt.Errorf("%w: signature is %d bytes, want %d", ErrConnUnsigned, len(value), sigLen)
			}
			c.Signature = append([]byte(nil), value...)
		case TLVChain:
			if !ValidChainName(string(value)) {
				return Conn{}, fmt.Errorf("%w: %q", ErrChainName, value)
			}
			c.Chain = string(value)
		}
	}
	switch {
	case !seen[TLVPubkey]:
		return Conn{}, errors.New("missing pubkey")
	case !seen[TLVSecret]:
		return Conn{}, errors.New("missing secret")
	case !seen[TLVHubIdentity]:
		return Conn{}, fmt.Errorf("%w: missing hub identity", ErrConnUnsigned)
	case !seen[TLVSignature]:
		return Conn{}, fmt.Errorf("%w: missing signature", ErrConnUnsigned)
	case !seen[TLVChain]:
		return Conn{}, fmt.Errorf("%w: missing", ErrChainName)
	case CountUsableHints(c.Relays) == 0:
		return Conn{}, errors.New("connection carries no usable relay url, so the hub is unreachable")
	}
	return c, nil
}

func keyBytes(s, field string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid %s hex: %w", field, err)
	}
	if len(b) != keyLen {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", field, keyLen, len(b))
	}
	return b, nil
}
