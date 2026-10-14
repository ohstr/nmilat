package nipcash

import (
	"bytes"
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

type tlv struct {
	typ   byte
	value []byte
}

// encodeTLVs builds a bech32 string from raw TLV entries, with a valid checksum, so
// a decoder's own TLV rules are what accept or refuse it. raw is appended as-is,
// for a truncated tail.
func encodeTLVs(t *testing.T, hrp string, entries []tlv, raw ...byte) string {
	t.Helper()
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteByte(e.typ)
		buf.WriteByte(byte(len(e.value)))
		buf.Write(e.value)
	}
	buf.Write(raw)
	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := bech32.Encode(hrp, bits5)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var (
	fixKey    = bytes.Repeat([]byte{0x22}, 32)
	fixSecret = bytes.Repeat([]byte{0x33}, 32)
	fixURL    = []byte("wss://r.example")
)

// The structural rules shared by the cash token and the cashhub1 connection
// (NIP-CASH §The Cash Token, §The Cash Hub Connection): 0 and 2 exactly once at 32
// bytes, a usable relay, and no truncated entry. Each case breaks one rule.
var sharedTLVCases = []struct {
	name    string
	entries []tlv
	raw     []byte
	wantErr string
}{
	{"missing pubkey", []tlv{{1, fixURL}, {2, fixSecret}}, nil, "missing wallet pubkey"},
	{"missing secret", []tlv{{0, fixKey}, {1, fixURL}}, nil, "missing secret"},
	{"duplicate pubkey", []tlv{{0, fixKey}, {0, fixKey}, {1, fixURL}, {2, fixSecret}}, nil, "duplicate wallet pubkey"},
	{"duplicate secret", []tlv{{0, fixKey}, {1, fixURL}, {2, fixSecret}, {2, fixSecret}}, nil, "duplicate secret"},
	{"short pubkey", []tlv{{0, fixKey[:31]}, {1, fixURL}, {2, fixSecret}}, nil, "wallet pubkey must be"},
	{"long secret", []tlv{{0, fixKey}, {1, fixURL}, {2, append(fixSecret, 0)}}, nil, "secret must be"},
	{"no relay", []tlv{{0, fixKey}, {2, fixSecret}}, nil, "no usable relay"},
	{"only blank relays", []tlv{{0, fixKey}, {1, []byte(" ")}, {2, fixSecret}}, nil, "no usable relay"},
	// The entry claims 32 bytes and carries 3. The checksum is valid, so only the
	// TLV parser can catch it.
	{"truncated entry", []tlv{{0, fixKey}, {1, fixURL}}, []byte{2, 32, 1, 2, 3}, "truncated TLV"},
}

func TestDecode_TLVRules(t *testing.T) {
	for _, tc := range sharedTLVCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(encodeTLVs(t, "lokicash", tc.entries, tc.raw...))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestDecodeCashHubConnection_TLVRules(t *testing.T) {
	for _, tc := range sharedTLVCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeCashHubConnection(encodeTLVs(t, CashHubConnectionHRP, tc.entries, tc.raw...))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
	dupLabel := []tlv{{0, fixKey}, {1, fixURL}, {2, fixSecret}, {3, []byte("a")}, {3, []byte("b")}}
	if _, err := DecodeCashHubConnection(encodeTLVs(t, CashHubConnectionHRP, dupLabel)); err == nil || !strings.Contains(err.Error(), "duplicate label") {
		t.Fatalf("duplicate label: err = %v", err)
	}
}

// NIP-CASH §The Cash Token: identity_required (type 3) is at most one byte, 0 or 1.
func TestDecode_IdentityRequiredRules(t *testing.T) {
	base := []tlv{{0, fixKey}, {1, fixURL}, {2, fixSecret}}
	for name, tc := range map[string]struct {
		extra   []tlv
		wantErr string
	}{
		"two bytes": {[]tlv{{3, []byte{0, 1}}}, "identity_required must be 1 byte"},
		"value 2":   {[]tlv{{3, []byte{2}}}, "must be 0 or 1"},
		"duplicate": {[]tlv{{3, []byte{1}}, {3, []byte{1}}}, "duplicate identity_required"},
	} {
		_, err := Decode(encodeTLVs(t, "lokicash", append(append([]tlv{}, base...), tc.extra...)))
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.wantErr)
		}
	}
}

// NIP-CASH §The Cash Token: a lone, duplicated or wrong-length type 5 or 6 is NO
// VALID PROVENANCE and the rest decodes normally, never a decode failure.
func TestDecode_AnomalousProvenanceIsDroppedNotFatal(t *testing.T) {
	base := []tlv{{0, fixKey}, {1, fixURL}, {2, fixSecret}}
	sig := bytes.Repeat([]byte{1}, 65)
	amt := []byte{0, 0, 0, 0, 0, 0, 0x52, 0x08}
	for name, extra := range map[string][]tlv{
		"signature alone":       {{5, sig}},
		"amount alone":          {{6, amt}},
		"short signature":       {{5, sig[:64]}, {6, amt}},
		"short amount":          {{5, sig}, {6, amt[:7]}},
		"duplicate signature":   {{5, sig}, {5, sig}, {6, amt}},
		"duplicate amount":      {{5, sig}, {6, amt}, {6, amt}},
		"short hub group alone": {{5, sig}, {6, amt}, {7, []byte{1, 2, 3}}},
	} {
		tok, err := Decode(encodeTLVs(t, "lokicash", append(append([]tlv{}, base...), extra...)))
		if err != nil {
			t.Errorf("%s: decode failed: %v", name, err)
			continue
		}
		if name == "short hub group alone" {
			if !tok.HasProvenance() || tok.HubGroup != nil {
				t.Errorf("%s: provenance=%v hubGroup=%x, want provenance kept and no hub group", name, tok.HasProvenance(), tok.HubGroup)
			}
			continue
		}
		if tok.HasProvenance() {
			t.Errorf("%s: kept provenance from an anomalous pair", name)
		}
	}
}

// NIP-CASH §The Cash Token: the encoder refuses a mint signature that is not 65
// bytes, so it never writes what decoders must discard.
func TestEncode_RefusesWrongLengthMintSignature(t *testing.T) {
	amount := uint64(1000)
	_, err := Encode(Token{HRP: "lokicash", WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t),
		RelayURLs: []string{"wss://r.example"}, MintSignature: make([]byte, 64), AttestedAmountMillis: &amount})
	if err == nil || !strings.Contains(err.Error(), "mint signature must be") {
		t.Fatalf("err = %v, want the 65-byte refusal", err)
	}
}
