package nipcw

import (
	"bytes"
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// NIP-CW §The Circle Wallet Hub Connection: 0 and 2 exactly once at 32 bytes, at
// most one label, a usable relay, no truncated entry. Each case breaks one rule;
// every string has a valid checksum, so only the TLV parser decides.
func TestDecodeCircleHubConnection_TLVRules(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	secret := bytes.Repeat([]byte{0x33}, 32)
	url := []byte("wss://r.example")
	type tlv struct {
		typ   byte
		value []byte
	}
	for _, tc := range []struct {
		name    string
		entries []tlv
		raw     []byte
		wantErr string
	}{
		{"missing pubkey", []tlv{{1, url}, {2, secret}}, nil, "missing wallet pubkey"},
		{"missing secret", []tlv{{0, key}, {1, url}}, nil, "missing secret"},
		{"duplicate pubkey", []tlv{{0, key}, {0, key}, {1, url}, {2, secret}}, nil, "duplicate wallet pubkey"},
		{"duplicate secret", []tlv{{0, key}, {1, url}, {2, secret}, {2, secret}}, nil, "duplicate secret"},
		{"duplicate label", []tlv{{0, key}, {1, url}, {2, secret}, {3, []byte("a")}, {3, []byte("b")}}, nil, "duplicate label"},
		{"short pubkey", []tlv{{0, key[:31]}, {1, url}, {2, secret}}, nil, "wallet pubkey must be"},
		{"long secret", []tlv{{0, key}, {1, url}, {2, append(secret, 0)}}, nil, "secret must be"},
		{"no relay", []tlv{{0, key}, {2, secret}}, nil, "no usable relay"},
		{"truncated entry", []tlv{{0, key}, {1, url}}, []byte{2, 32, 1, 2, 3}, "truncated TLV"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			for _, e := range tc.entries {
				buf.WriteByte(e.typ)
				buf.WriteByte(byte(len(e.value)))
				buf.Write(e.value)
			}
			buf.Write(tc.raw)
			bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
			if err != nil {
				t.Fatal(err)
			}
			s, err := bech32.Encode(CircleHubConnectionHRP, bits5)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeCircleHubConnection(s); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
