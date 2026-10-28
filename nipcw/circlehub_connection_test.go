package nipcw

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/internal/credcodec"
	"github.com/ohstr/nmilat/nipcash"
)

// The spec's circlehub1 example (NIP-CW §The Circle Wallet Hub Connection), K-CWH-1.
const (
	kcwhString = "circlehub1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzyq" +
		"szzg3rysjjvfeg9y4zktpd9chnqvfjxv6r2d3h8qun5weu85lr7qcng9jxzfmnyprxzmtfd3ujqsmfwf3kcegyypumuen7l8wthtz45p3ftn" +
		"58pvrs9xlumvkuu2xet8egzkcklqtesp2pruz886khdq7pmdm0v9uyc5pmnlsp34xme8djme07vp9elacp0edw2nx04n8ldyhuufvsr90xye" +
		"vlpynnq7v0tfsn6mts8ypjs7c9agzmqcrky6t5vdhkjms0uy6sx"
	kcwhPubkey   = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	kcwhIdentity = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	kcwhSig      = "1f0473ead7683c1db76f61784c503b9fe018d4dbc9db2de5fe604b9ff7017e5ae54ccfaccff692fce2590195e62659f092730798f5a613d6d703903287b05ea05b"
	kcwhText     = "circle-hub:v1:bitcoin:" + kcwhPubkey + ":" + kcwhIdentity +
		":16c4c4164c27d448128dabf8052dddd5b30c61904b7b7c1b85e1486c37b7a500" +
		":c7c2b59bc693ccb3290c0a51e5c3114e49d382ba14d374ad9b1a17ffdb1750c1"
	key1 = "0000000000000000000000000000000000000000000000000000000000000001"
	key2 = "0000000000000000000000000000000000000000000000000000000000000002"
	key3 = "0000000000000000000000000000000000000000000000000000000000000003"
)

func kcwhSecret() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0x20 + i)
	}
	return hex.EncodeToString(b)
}

func kcwh(t *testing.T, signer string) CircleHubConnection {
	t.Helper()
	c := CircleHubConnection{Pubkey: kcwhPubkey, Relays: []string{"wss://relay.example.com"}, Secret: kcwhSecret(),
		Label: "Ada's Family Circle", HasLabel: true, HubIdentity: kcwhIdentity, Chain: "bitcoin"}
	sign, err := nipcash.LocalChainSigner(signer, "bitcoin")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(mustText(t, c))
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = sig
	return c
}

func mustText(t *testing.T, c CircleHubConnection) string {
	t.Helper()
	s, err := nipcash.ConnSignedText(c.Fields())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// T12-22, K-CWH-1: the spec's signed text, digest, TLV 5 and 375-character string;
// SignCircleHubConnection reproduces TLV 5.
func TestKCWH1_SpecCircleHubConnection(t *testing.T) {
	c := kcwh(t, key1)
	if text := mustText(t, c); text != kcwhText {
		t.Fatalf("signed text = %q", text)
	}
	prefix, _ := nipcash.ChainSignedMessagePrefix("bitcoin")
	first := sha256.Sum256([]byte(prefix + kcwhText))
	second := sha256.Sum256(first[:])
	if d := hex.EncodeToString(second[:]); d != "7c945cb9b96fd8a62c973c42661e572ed186026a012cd7d4882c2eccc1cf1356" {
		t.Errorf("digest = %s", d)
	}
	sign, _ := nipcash.LocalChainSigner(key1, "bitcoin")
	signed, err := SignCircleHubConnection(CircleHubConnection{Pubkey: kcwhPubkey, Relays: []string{"", "wss://relay.example.com"},
		Secret: kcwhSecret(), Label: "Ada's Family Circle", HasLabel: true, HubIdentity: kcwhIdentity, Chain: "bitcoin"}, sign, kcwhIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(signed.Signature); got != kcwhSig {
		t.Fatalf("TLV 5 = %s, want %s", got, kcwhSig)
	}
	s, err := EncodeCircleHubConnection(signed)
	if err != nil {
		t.Fatal(err)
	}
	if s != kcwhString || len(s) != 375 {
		t.Fatalf("encoded = %s (%d chars), want the spec string", s, len(s))
	}
	d, err := DecodeCircleHubConnection(kcwhString)
	if err != nil {
		t.Fatal(err)
	}
	if d.Pubkey != kcwhPubkey || d.HubIdentity != kcwhIdentity || d.Chain != "bitcoin" || d.Label != "Ada's Family Circle" ||
		!d.HasLabel || d.Secret != kcwhSecret() || !bytes.Equal(d.Signature, signed.Signature) ||
		!slices.Equal(d.Relays, []string{"wss://relay.example.com"}) {
		t.Fatalf("decoded = %+v", d)
	}
	if err := d.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if up, err := DecodeCircleHubConnection(nipcash.QRForm(kcwhString)); err != nil || up.Verify() != nil {
		t.Fatalf("uppercase: %v", err)
	}
	if _, err := SignCircleHubConnection(d, sign, strings.Repeat("ab", 32)); !errors.Is(err, nipcash.ErrSignerMismatch) {
		t.Fatalf("expected key mismatch: %v", err)
	}
}

// K-CWH-2: refusals, and K-CSIG-1's circlehub1 row (signed by key 2 over key 1's
// TLV 4: decodes, unverified).
func TestKCWH2_Refusals(t *testing.T) {
	c := kcwh(t, key1)
	pub, _ := hex.DecodeString(c.Pubkey)
	sec, _ := hex.DecodeString(c.Secret)
	id, _ := hex.DecodeString(c.HubIdentity)
	tlv := func(typ uint8, v []byte) []byte { var b bytes.Buffer; credcodec.WriteTLV(&b, typ, v); return b.Bytes() }
	build := func(skip uint8, extra ...[]byte) string {
		var buf bytes.Buffer
		for _, e := range []struct {
			typ uint8
			v   []byte
		}{{0, pub}, {1, []byte(c.Relays[0])}, {2, sec}, {3, []byte(c.Label)}, {4, id}, {5, c.Signature}, {6, []byte(c.Chain)}} {
			if e.typ != skip {
				credcodec.WriteTLV(&buf, e.typ, e.v)
			}
		}
		for _, x := range extra {
			buf.Write(x)
		}
		s, err := credcodec.EncodeBech32(CircleHubConnectionHRP, buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for name, s := range map[string]string{
		"no TLV 4":       build(4),
		"no TLV 5":       build(5),
		"no TLV 6":       build(6),
		"31-byte TLV 4":  build(4, tlv(4, id[:31])),
		"TLV 6 bit_coin": build(6, tlv(6, []byte("bit_coin"))),
		"TLV 4 twice":    build(99, tlv(4, id)),
		"no TLV 0":       build(0),
		"no TLV 2":       build(2),
		"label twice":    build(99, tlv(3, []byte("x"))),
		"no relay":       build(1),
		"wrong hrp":      kchLike(t, c),
	} {
		if _, err := DecodeCircleHubConnection(s); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// A type above 6 is ignored and outside the signature.
	d, err := DecodeCircleHubConnection(build(99, tlv(9, []byte("anything"))))
	if err != nil || d.Verify() != nil {
		t.Fatalf("TLV 9: %v / %v", err, d.Verify())
	}
	// K-CSIG-1: signed by key 2 with TLV 4 still key 1's.
	forged := kcwh(t, key2)
	s, err := EncodeCircleHubConnection(forged)
	if err != nil {
		t.Fatal(err)
	}
	d, err = DecodeCircleHubConnection(s)
	if err != nil {
		t.Fatalf("an unverified string still decodes: %v", err)
	}
	if err := d.Verify(); !errors.Is(err, nipcash.ErrConnUnverified) || !errors.Is(err, nipcash.ErrConnSignerMismatch) {
		t.Fatalf("Verify = %v", err)
	}
	// The encoder refuses an unsigned connection.
	unsigned := c
	unsigned.Signature = nil
	if _, err := EncodeCircleHubConnection(unsigned); err == nil {
		t.Error("an unsigned connection was encoded")
	}
}

func kchLike(t *testing.T, c CircleHubConnection) string {
	t.Helper()
	s, err := nipcash.EncodeCashHubConnection(nipcash.CashHubConnection(c))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func FuzzDecodeCircleHubConnection(f *testing.F) {
	f.Add(kcwhString)
	f.Fuzz(func(t *testing.T, s string) {
		c, err := DecodeCircleHubConnection(s)
		if err != nil {
			return
		}
		back, err := EncodeCircleHubConnection(c)
		if err != nil {
			t.Fatalf("decoded but cannot re-encode: %v", err)
		}
		if _, err := DecodeCircleHubConnection(back); err != nil {
			t.Fatalf("re-encoded string does not decode: %v", err)
		}
	})
}
