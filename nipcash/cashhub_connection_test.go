package nipcash

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/internal/credcodec"
)

// The spec's cashhub1 example (NIP-CASH §The Cash Hub Connection), K-CH-1.
const (
	kch1String = "cashhub1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzyqsz" +
		"zg3rysjjvfeg9y4zktpd9chnqvfjxv6r2d3h8qun5weu85lr7qcsg9kxjcm9yaejqsmpwd5zqjr4vgzzq7d7vel0nh9m4326qc54e6rskpcz" +
		"n07dktww9rv4nu5ptvt0s9ucq4q377sfr0m7hp53amvskrznsqm50ld4vpkxdm3ddl852cszj7hrs4yg2lfx9693az8l4qhk3mex6v67va8s" +
		"ae5q2epsph453eyy9d45zvqsvpmzd96xxmmfdcvlu0w2"
	kchPubkey   = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	kchIdentity = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	kchSig      = "1f7a091bf7eb8691eed90b0c53803747fdb5606c66ee2d6fcf45620297ae38548857d262e8b1e88ffa82f68ef26d335e674f0ee680564300deb48e4842b6b41301"
	kchText     = "cash-hub:v1:bitcoin:" + kchPubkey + ":" + kchIdentity +
		":16c4c4164c27d448128dabf8052dddd5b30c61904b7b7c1b85e1486c37b7a500" +
		":b5d2b9a2a7f9519d7367521d3a125f882cc34bbcc6f2844aed18533f5f724294"
	key1 = "0000000000000000000000000000000000000000000000000000000000000001"
)

func kchSecret() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0x20 + i)
	}
	return hex.EncodeToString(b)
}

func kch1(t *testing.T, label bool) CashHubConnection {
	t.Helper()
	c := CashHubConnection{Pubkey: kchPubkey, Relays: []string{"wss://relay.example.com"}, Secret: kchSecret(),
		HubIdentity: kchIdentity, Chain: "bitcoin"}
	if label {
		c.Label, c.HasLabel = "Alice's Cash Hub", true
	}
	sign, err := LocalChainSigner(key1, "bitcoin")
	if err != nil {
		t.Fatal(err)
	}
	c, err = SignCashHubConnection(c, sign, kchIdentity)
	if err != nil {
		t.Fatalf("SignCashHubConnection: %v", err)
	}
	return c
}

// K-CH-1: the spec's signed text, digest, TLV 5 and 368-character string.
func TestKCH1_SpecCashHubConnection(t *testing.T) {
	c := kch1(t, true)
	text, err := ConnSignedText(c.Fields())
	if err != nil || text != kchText {
		t.Fatalf("signed text = %q (%v), want %q", text, err, kchText)
	}
	if d := hex.EncodeToString(doubleSHA256([]byte(LndSignedMessagePrefix + text))); d != "c4976825128c4be05a7c553d29852f9611667832eb6d2c096417cd7a6c8817dd" {
		t.Errorf("digest = %s", d)
	}
	if got := hex.EncodeToString(c.Signature); got != kchSig {
		t.Errorf("TLV 5 = %s, want %s", got, kchSig)
	}
	s, err := EncodeCashHubConnection(c)
	if err != nil {
		t.Fatal(err)
	}
	if s != kch1String || len(s) != 368 {
		t.Fatalf("encoded = %s (%d chars), want the spec string", s, len(s))
	}
	d, err := DecodeCashHubConnection(kch1String)
	if err != nil {
		t.Fatal(err)
	}
	if d.Pubkey != kchPubkey || d.HubIdentity != kchIdentity || d.Chain != "bitcoin" || d.Label != "Alice's Cash Hub" ||
		!d.HasLabel || d.Secret != kchSecret() || !bytes.Equal(d.Signature, c.Signature) {
		t.Fatalf("decoded = %+v", d)
	}
	if err := d.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// K-CH-2: without TLV 3 the text ends with ":", and the string is 339 characters;
// an empty TLV 3 hashes as sha256("") and is never emitted.
func TestKCH2_NoLabel(t *testing.T) {
	c := kch1(t, false)
	text, _ := ConnSignedText(c.Fields())
	if !strings.HasSuffix(text, ":") {
		t.Errorf("text %q does not end with ':'", text)
	}
	if d := hex.EncodeToString(doubleSHA256([]byte(LndSignedMessagePrefix + text))); d != "bd39cc19f477bb273774acdef3ed94f8b8a7f9954bb6363a913d6200c48d5c73" {
		t.Errorf("digest = %s", d)
	}
	sig := hex.EncodeToString(c.Signature)
	if !strings.HasPrefix(sig, "1fde47e8") || !strings.HasSuffix(sig, "964c") {
		t.Errorf("TLV 5 = %s, want 1fde47e8…964c", sig)
	}
	s, err := EncodeCashHubConnection(c)
	if err != nil || len(s) != 339 {
		t.Fatalf("encoded %d chars (%v), want 339", len(s), err)
	}

	empty := c
	empty.HasLabel, empty.Label = true, ""
	text, _ = ConnSignedText(empty.Fields())
	if !strings.HasSuffix(text, ":e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Errorf("an empty label hashes as sha256(\"\"): %q", text)
	}
	if _, err := EncodeCashHubConnection(empty); err == nil {
		t.Error("an empty label was emitted")
	}
	sign, _ := LocalChainSigner(key1, "bitcoin")
	if _, err := SignCashHubConnection(empty, sign, kchIdentity); err == nil {
		t.Error("an empty label was signed")
	}
}

// T03: the decoder refuses a missing, repeated or malformed TLV 4/5/6 and keeps
// what the spec keeps; a type above 6 is ignored and outside the signature.
func TestDecodeCashHubConnection_Refusals(t *testing.T) {
	c := kch1(t, true)
	pub, _ := hex.DecodeString(c.Pubkey)
	sec, _ := hex.DecodeString(c.Secret)
	id, _ := hex.DecodeString(c.HubIdentity)
	build := func(skip uint8, extra ...[]byte) string {
		var buf bytes.Buffer
		entries := []struct {
			typ uint8
			v   []byte
		}{{0, pub}, {1, []byte(c.Relays[0])}, {2, sec}, {3, []byte(c.Label)}, {4, id}, {5, c.Signature}, {6, []byte(c.Chain)}}
		for _, e := range entries {
			if e.typ != skip {
				credcodec.WriteTLV(&buf, e.typ, e.v)
			}
		}
		for _, x := range extra {
			buf.Write(x)
		}
		s, err := credcodec.EncodeBech32(CashHubConnectionHRP, buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	tlv := func(typ uint8, v []byte) []byte { var b bytes.Buffer; credcodec.WriteTLV(&b, typ, v); return b.Bytes() }

	cases := map[string]struct {
		s    string
		want error
	}{
		"no TLV 4":        {build(4), ErrConnUnsigned},
		"no TLV 5":        {build(5), ErrConnUnsigned},
		"no TLV 6":        {build(6), ErrChainName},
		"31-byte TLV 4":   {build(4, tlv(4, id[:31])), ErrConnUnsigned},
		"TLV 4 twice":     {build(99, tlv(4, id)), ErrConnUnsigned},
		"64-byte TLV 5":   {build(5, tlv(5, c.Signature[:64])), ErrConnUnsigned},
		"TLV 6 bit_coin":  {build(6, tlv(6, []byte("bit_coin"))), ErrChainName},
		"TLV 6 empty":     {build(6, tlv(6, nil)), ErrChainName},
		"TLV 6 twice":     {build(99, tlv(6, []byte("bitcoin"))), ErrChainName},
		"no TLV 0":        {build(0), nil},
		"no TLV 2":        {build(2), nil},
		"label twice":     {build(99, tlv(3, []byte("x"))), nil},
		"label not UTF-8": {build(3, tlv(3, []byte{0xff, 0xfe})), nil},
		"empty relay set": {"", nil},
	}
	for name, tc := range cases {
		if tc.s == "" {
			continue
		}
		_, err := DecodeCashHubConnection(tc.s)
		if err == nil {
			t.Errorf("%s: decoded", name)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// A type above 6 is ignored, and the signature still verifies (K-CSIG-1).
	d, err := DecodeCashHubConnection(build(99, tlv(9, []byte("anything"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(); err != nil {
		t.Errorf("TLV 9 changed the signature: %v", err)
	}
	// An empty TLV 3 decodes with HasLabel and hashes as sha256("").
	var buf bytes.Buffer
	for _, e := range [][2]any{} {
		_ = e
	}
	credcodec.WriteTLV(&buf, 0, pub)
	credcodec.WriteTLV(&buf, 1, []byte(c.Relays[0]))
	credcodec.WriteTLV(&buf, 2, sec)
	credcodec.WriteTLV(&buf, 3, nil)
	credcodec.WriteTLV(&buf, 4, id)
	credcodec.WriteTLV(&buf, 5, c.Signature)
	credcodec.WriteTLV(&buf, 6, []byte("bitcoin"))
	s, _ := credcodec.EncodeBech32(CashHubConnectionHRP, buf.Bytes())
	d, err = DecodeCashHubConnection(s)
	if err != nil || !d.HasLabel || d.Label != "" {
		t.Fatalf("empty TLV 3: %+v %v", d, err)
	}
}

// T03-28 (XQ-43): the uppercase string decodes to the same fields and verifies; a
// mixed-case one is ErrMixedCase.
func TestCashHubConnection_Case(t *testing.T) {
	up, err := DecodeCashHubConnection(QRForm(kch1String))
	if err != nil {
		t.Fatal(err)
	}
	if up.Pubkey != kchPubkey || up.Verify() != nil {
		t.Fatalf("uppercase: %+v", up)
	}
	mixed := []byte(kch1String)
	for i := 0; i < len(mixed); i += 2 {
		mixed[i] = byte(strings.ToUpper(string(mixed[i]))[0])
	}
	if _, err := DecodeCashHubConnection(string(mixed)); !errors.Is(err, ErrMixedCase) {
		t.Fatalf("mixed case: %v, want ErrMixedCase", err)
	}
}

// K-CSIG-1 (cashhub1 rows; the cashorder1 rows join with nipCO): an unknown chain
// is unverified with ErrChainNoPrefix; a changed TLV 6 or label, or a signature by
// another key, is ErrConnSignerMismatch.
func TestKCSIG1_Unverified(t *testing.T) {
	c := kch1(t, true)
	other := c
	other.Chain = "bitcoin-x"
	if err := other.Verify(); !errors.Is(err, ErrConnUnverified) || !errors.Is(err, ErrChainNoPrefix) {
		t.Errorf("bitcoin-x: %v", err)
	}
	relabeled := c
	relabeled.Label = "Bob's cash counter"
	if err := relabeled.Verify(); !errors.Is(err, ErrConnUnverified) || !errors.Is(err, ErrConnSignerMismatch) {
		t.Errorf("relabelled: %v", err)
	}
	key2 := strings.Repeat("0", 63) + "2"
	sign2, _ := LocalChainSigner(key2, "bitcoin")
	sig, err := sign2(mustText(t, c.Fields()))
	if err != nil {
		t.Fatal(err)
	}
	forged := c
	forged.Signature = sig
	if err := forged.Verify(); !errors.Is(err, ErrConnSignerMismatch) {
		t.Errorf("key 2 over key 1's TLV 4: %v", err)
	}
	if _, err := SignCashHubConnection(c, sign2, kchIdentity); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("signing with the wrong node: %v", err)
	}
}

// K-CHAIN-1.
func TestKCHAIN1_ValidChainName(t *testing.T) {
	for _, s := range []string{"bitcoin", strings.Repeat("a", 32), "bitcoin-x"} {
		if !ValidChainName(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "Bitcoin", "bit coin", "bit_coin", strings.Repeat("a", 33)} {
		if ValidChainName(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// The encoder refuses an unsigned connection, a non-ASCII hint and no usable hint,
// and skips a blank one the signature never covered.
func TestEncodeCashHubConnection_Refusals(t *testing.T) {
	c := kch1(t, true)
	unsigned := c
	unsigned.Signature = nil
	if _, err := EncodeCashHubConnection(unsigned); !errors.Is(err, ErrConnUnsigned) {
		t.Errorf("unsigned: %v", err)
	}
	nonASCII := c
	nonASCII.Relays = []string{"wss://rélay.example"}
	if _, err := EncodeCashHubConnection(nonASCII); !errors.Is(err, ErrNonASCIIRelayHint) {
		t.Errorf("non-ASCII: %v", err)
	}
	blank := c
	blank.Relays = []string{"  "}
	if _, err := EncodeCashHubConnection(blank); err == nil {
		t.Error("no usable hint encoded")
	}
	sign, _ := LocalChainSigner(key1, "bitcoin")
	withBlank := c
	withBlank.Relays = []string{"", "wss://relay.example.com"}
	withBlank, err := SignCashHubConnection(withBlank, sign, kchIdentity)
	if err != nil {
		t.Fatal(err)
	}
	s, err := EncodeCashHubConnection(withBlank)
	if err != nil || s != kch1String {
		t.Errorf("a blank hint changed the signed string: %v", err)
	}
	// A label set without HasLabel would be written as TLV 3 but left out of
	// the signed text: neither signed nor encoded.
	half := kch1(t, false)
	half.Label = "Alice's Cash Hub"
	if _, err := SignCashHubConnection(half, sign, kchIdentity); err == nil {
		t.Error("a label without HasLabel was signed")
	}
	if _, err := EncodeCashHubConnection(half); err == nil {
		t.Error("a label without HasLabel was encoded")
	}
	badUTF8 := c
	badUTF8.Label = "\xff"
	if _, err := EncodeCashHubConnection(badUTF8); err == nil {
		t.Error("a label that is not UTF-8 was encoded")
	}
}

func mustText(t *testing.T, f ConnFields) string {
	t.Helper()
	s, err := ConnSignedText(f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
