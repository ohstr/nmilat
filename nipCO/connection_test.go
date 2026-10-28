package nipCO

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/internal/credcodec"
	"github.com/ohstr/nmilat/nipcash"
)

// K-CO-1: the spec's cashorder1 example (NIP-CO §Wire Format).
const (
	kco1String = "cashorder1qqs0jvy2qxf93scsfy6ylp0cn4fzndf3epzcxmuekzrqrugnhnsrd7gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzyp" +
		"qyzsjrg3z5v36gf99yknzdfe84q52j2d2924jhtpv45k6ut4097qc5g9kxjcm9yaejqcmpwd5zqcm0w4h8getjqss8n0nx0muaewav2ksx99" +
		"wwsu9swq5mlndjmn3gm9vl9q2mzmup0xq9gy079m5vml5lhete5l55tj2xs3dc0utwlzmp05fuars7sgx9k9q94qrcvyt93he0x9rzhu2gtr" +
		"76ry3z3fuznp0skm4cfl29quz073phg5rqwcnfw33k76twqxha8f"
	kcoPubkey   = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	kcoIdentity = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	kcoSig      = "1fe2ee8cdfe9fbe579a7e945c946845b87f16ef8b617d13ce8e1e820c5b1405a80" +
		"78611658df2f31462bf14858fda192228a782985f0b6eb84fd450704ff443745"
	kcoText = "cash-order:v1:bitcoin:" + kcoPubkey + ":" + kcoIdentity +
		":1681e7f0cca2d68c5a2a57e369f815529f0127b2a118adfeafa2f0edadb4d3d5" +
		":4415045cc4156b398d107e30b03adc967e5cafa1008863146c4467e79f6ed76f"
	key1 = "0000000000000000000000000000000000000000000000000000000000000001"
)

func kcoSecret() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0x40 + i)
	}
	return hex.EncodeToString(b)
}

func kco1(t *testing.T) OrderConnection {
	t.Helper()
	sign, err := nipcash.LocalChainSigner(key1, "bitcoin")
	if err != nil {
		t.Fatal(err)
	}
	c, err := SignOrderConnection(OrderConnection{Pubkey: kcoPubkey, Relays: []string{"wss://relay.example.com"},
		Secret: kcoSecret(), Label: "Alice's cash counter", HasLabel: true, HubIdentity: kcoIdentity, Chain: "bitcoin"},
		sign, kcoIdentity)
	if err != nil {
		t.Fatalf("SignOrderConnection: %v", err)
	}
	return c
}

// T20-01: sign + encode the K-CO-1 inputs → the 376-character spec string;
// decode → the same fields; the uppercase string decodes.
func TestT20_01_KCO1(t *testing.T) {
	c := kco1(t)
	text, err := nipcash.ConnSignedText(c.Fields())
	if err != nil || text != kcoText {
		t.Fatalf("signed text = %q (%v)", text, err)
	}
	if got := hex.EncodeToString(c.Signature); got != kcoSig {
		t.Fatalf("TLV 5 = %s", got)
	}
	s, err := EncodeOrderConnection(c)
	if err != nil {
		t.Fatal(err)
	}
	if s != kco1String || len(s) != 376 {
		t.Fatalf("encoded = %s (%d)", s, len(s))
	}
	for _, in := range []string{kco1String, strings.ToUpper(kco1String)} {
		d, err := DecodeOrderConnection(in)
		if err != nil {
			t.Fatal(err)
		}
		if d.Pubkey != kcoPubkey || d.HubIdentity != kcoIdentity || d.Chain != "bitcoin" || d.Secret != kcoSecret() ||
			d.Label != "Alice's cash counter" || !d.HasLabel || !bytes.Equal(d.Signature, c.Signature) ||
			len(d.Relays) != 1 || d.Relays[0] != "wss://relay.example.com" {
			t.Fatalf("decoded = %+v", d)
		}
		if err := d.Verify(); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
}

type tlv struct {
	typ byte
	val []byte
}

func kcoEntries(t *testing.T) []tlv {
	t.Helper()
	pk, _ := hex.DecodeString(kcoPubkey)
	sec, _ := hex.DecodeString(kcoSecret())
	id, _ := hex.DecodeString(kcoIdentity)
	sig, _ := hex.DecodeString(kcoSig)
	return []tlv{{0, pk}, {1, []byte("wss://relay.example.com")}, {2, sec}, {3, []byte("Alice's cash counter")},
		{4, id}, {5, sig}, {6, []byte("bitcoin")}}
}

func encodeEntries(t *testing.T, hrp string, es []tlv) string {
	t.Helper()
	var buf bytes.Buffer
	for _, e := range es {
		credcodec.WriteTLV(&buf, e.typ, e.val)
	}
	s, err := credcodec.EncodeBech32(hrp, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func without(es []tlv, typ byte) []tlv {
	var out []tlv
	for _, e := range es {
		if e.typ != typ {
			out = append(out, e)
		}
	}
	return out
}

func replaced(es []tlv, typ byte, val []byte) []tlv {
	out := append([]tlv(nil), es...)
	for i := range out {
		if out[i].typ == typ {
			out[i].val = val
		}
	}
	return out
}

func repeated(es []tlv, typ byte) []tlv {
	var out []tlv
	for _, e := range es {
		out = append(out, e)
		if e.typ == typ {
			out = append(out, e)
		}
	}
	return out
}

// T20-02 (K-CO-2): decoder and encoder refusals; an extra TLV 9 is ignored.
func TestT20_02_KCO2(t *testing.T) {
	es := kcoEntries(t)
	if got := encodeEntries(t, OrderConnectionHRP, es); got != kco1String {
		t.Fatalf("entries do not rebuild K-CO-1: %s", got)
	}
	bad := map[string][]tlv{
		"no TLV 0":       without(es, 0),
		"no TLV 2":       without(es, 2),
		"no TLV 4":       without(es, 4),
		"no TLV 5":       without(es, 5),
		"no TLV 6":       without(es, 6),
		"31-byte TLV 0":  replaced(es, 0, make([]byte, 31)),
		"64-byte TLV 5":  replaced(es, 5, make([]byte, 64)),
		"empty TLV 6":    replaced(es, 6, nil),
		"TLV 6 Bitcoin":  replaced(es, 6, []byte("Bitcoin")),
		"33-byte TLV 6":  replaced(es, 6, []byte(strings.Repeat("a", 33))),
		"TLV 3 twice":    repeated(es, 3),
		"TLV 5 twice":    repeated(es, 5),
		"TLV 6 twice":    repeated(es, 6),
		"TLV 4 twice":    repeated(es, 4),
		"33-byte TLV 4":  replaced(es, 4, append([]byte{0x02}, es[4].val...)),
		"cashhub1 shape": es,
	}
	for name, entries := range bad {
		hrp := OrderConnectionHRP
		if name == "cashhub1 shape" {
			hrp = nipcash.CashHubConnectionHRP
		}
		if _, err := DecodeOrderConnection(encodeEntries(t, hrp, entries)); !errors.Is(err, ErrOrderConnection) {
			t.Errorf("%s: %v, want ErrOrderConnection", name, err)
		}
	}
	extra := append(append([]tlv(nil), es...), tlv{9, []byte("future")})
	d, err := DecodeOrderConnection(encodeEntries(t, OrderConnectionHRP, extra))
	if err != nil {
		t.Fatalf("TLV 9: %v", err)
	}
	if err := d.Verify(); err != nil {
		t.Fatalf("TLV 9 verify: %v", err)
	}
	mixed := []byte(kco1String)
	mixed[12] = byte(strings.ToUpper(string(mixed[12]))[0])
	if _, err := DecodeOrderConnection(string(mixed)); !errors.Is(err, credcodec.ErrMixedCase) {
		t.Errorf("mixed case: %v", err)
	}

	c := kco1(t)
	unsigned := c
	unsigned.Signature = nil
	if _, err := EncodeOrderConnection(unsigned); !errors.Is(err, nipcash.ErrConnUnsigned) {
		t.Errorf("unsigned: %v", err)
	}
	for _, relays := range [][]string{nil, {""}, {"  "}, {"wss://relé.example"}, {"wss://ok", ""}} {
		r := c
		r.Relays = relays
		if _, err := EncodeOrderConnection(r); !errors.Is(err, ErrOrderConnection) {
			t.Errorf("relays %q: %v", relays, err)
		}
	}
}

// T20-25: Verify on K-CO-1 → nil; the K-CSIG-1 variants → unverified.
func TestT20_25_Verify(t *testing.T) {
	c := kco1(t)
	if err := c.Verify(); err != nil {
		t.Fatal(err)
	}
	x := c
	x.Chain = "bitcoin-x"
	if err := x.Verify(); !errors.Is(err, nipcash.ErrConnUnverified) || !errors.Is(err, nipcash.ErrChainNoPrefix) {
		t.Errorf("bitcoin-x: %v", err)
	}
	l := c
	l.Label = "Bob's cash counter"
	if err := l.Verify(); !errors.Is(err, nipcash.ErrConnSignerMismatch) {
		t.Errorf("relabelled: %v", err)
	}
	// TLV 6 bitcoin-x decodes and stays unverified.
	es := replaced(kcoEntries(t), 6, []byte("bitcoin-x"))
	d, err := DecodeOrderConnection(encodeEntries(t, OrderConnectionHRP, es))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(); !errors.Is(err, nipcash.ErrConnUnverified) {
		t.Errorf("decoded bitcoin-x: %v", err)
	}
	// A signer other than TLV 4 issues nothing.
	key2 := strings.Repeat("0", 63) + "2"
	sign2, _ := nipcash.LocalChainSigner(key2, "bitcoin")
	if _, err := SignOrderConnection(c, sign2, kcoIdentity); !errors.Is(err, nipcash.ErrSignerMismatch) {
		t.Errorf("key 2: %v", err)
	}
}
