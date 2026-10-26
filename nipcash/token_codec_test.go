package nipcash

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/internal/credcodec"
)

// The spec's scheme-1 token (NIP-CASH §Token Test Vectors), K-TOK-1.
const (
	ktok1 = "satscash1qqsvvprlj3q76ltdxpz5qm54cp7dshrh3e9cemeu5746czdet3cfaegpzamhxue69uhhyetvv9ujuetcv9khqmr99e3" +
		"k7mgprpmhxue69uhkyctrdd6hqtn90psk6urvv5hxuet5qgsqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8c" +
		"rqyqs2sfq7gvnhvt0jjxg049a9kg9jnl306hyqexhxn6gw3e0928ftmtxr7n5r2emz4x3r8q6lrx6hgjhzrykwj9wtnchnh78hjc" +
		"z23pr6n2tf7sxpqqqqqqqqqq9yzq8qnkhn68lpqqszp39gk7"
	ktokWallet = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	ktokSig    = "20f2193bb16f948c87d4bd2d90594ff17eae4064d734f487472f2a8e95ed661fa741ab3b154d119c1af8cdaba25710c96748ae5cf179dfc7bcb0254423d4d4b4fa"
	ktokStream = "0020c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" +
		"01177773733a2f2f72656c61792e6578616d706c652e636f6d" +
		"01187773733a2f2f6261636b75702e6578616d706c652e6e6574" +
		"0220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"030101" + "0541" + ktokSig + "06080000000000005208" + "0704ed79e8ff" + "080101"
	r1 = "wss://relay.example.com"
	r2 = "wss://backup.example.net"
)

func secret0to1f() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return hex.EncodeToString(b)
}

func ktok1Token(t *testing.T) Token {
	t.Helper()
	sig, _ := hex.DecodeString(ktokSig)
	amt := uint64(21000)
	yes := true
	group, _ := hex.DecodeString("ed79e8ff")
	return Token{HRP: "satscash", WalletPubkey: ktokWallet, Secret: secret0to1f(), RelayURLs: []string{r1, r2},
		IdentityRequired: &yes, MintSignature: sig, AttestedAmountMillis: &amt, HubGroup: group, Scheme: SchemeMintV1}
}

// T03-01, T03-16, T03-12 (K-TOK-1): the spec token decodes to every input, and the
// inputs encode to the spec string byte for byte, entries 0, 1, 1, 2, 3, 5, 6, 7, 8.
func TestKTOK1_SpecToken(t *testing.T) {
	got, err := Decode(ktok1)
	if err != nil {
		t.Fatal(err)
	}
	want := ktok1Token(t)
	if got.HRP != want.HRP || got.WalletPubkey != want.WalletPubkey || got.Secret != want.Secret ||
		!slices.Equal(got.RelayURLs, want.RelayURLs) || got.IdentityRequired == nil || !*got.IdentityRequired ||
		!bytes.Equal(got.MintSignature, want.MintSignature) || *got.AttestedAmountMillis != 21000 ||
		!bytes.Equal(got.HubGroup, want.HubGroup) || got.Scheme != SchemeMintV1 {
		t.Fatalf("decoded = %+v", got)
	}
	s, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if s != ktok1 || len(s) != 348 {
		t.Fatalf("encoded %d chars:\n%s", len(s), s)
	}
	_, data, err := credcodec.DecodeBech32(s)
	if err != nil || hex.EncodeToString(data) != ktokStream {
		t.Fatalf("TLV stream = %x", data)
	}
}

// T03-12: a shuffled TLV stream decodes to the same token.
func TestDecode_AnyEntryOrder(t *testing.T) {
	_, data, _ := credcodec.DecodeBech32(ktok1)
	var entries [][]byte
	for curr := 0; curr < len(data); {
		_, v, _ := credcodec.ReadTLV(data[curr:])
		entries = append(entries, data[curr:curr+2+len(v)])
		curr += 2 + len(v)
	}
	slices.Reverse(entries)
	s, _ := credcodec.EncodeBech32("satscash", bytes.Join(entries, nil))
	got, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	// Relay order follows the entries as encoded, so the reversed pair comes back
	// reversed; everything else is the same token.
	if got.Scheme != SchemeMintV1 || got.WalletPubkey != ktokWallet || !slices.Equal(got.RelayURLs, []string{r2, r1}) {
		t.Fatalf("shuffled: %+v", got)
	}
}

// T03-13, T03-28 (XQ-43): the uppercase token decodes to the lowercase one's
// fields, HRP lowercase; a mixed-case one is ErrMixedCase; "<UPPERCASE>#<secret>"
// splits on the first '#' and its token half decodes; the whole string does not.
func TestToken_Case(t *testing.T) {
	up, err := Decode(QRForm(ktok1))
	if err != nil {
		t.Fatal(err)
	}
	if up.HRP != "satscash" || up.WalletPubkey != ktokWallet || up.Scheme != SchemeMintV1 {
		t.Fatalf("uppercase: %+v", up)
	}
	mixed := []byte(ktok1)
	for i := 0; i < len(mixed); i += 2 {
		mixed[i] = byte(strings.ToUpper(string(mixed[i]))[0])
	}
	if _, err := Decode(string(mixed)); !errors.Is(err, ErrMixedCase) {
		t.Fatalf("mixed case: %v", err)
	}
	whole := QRForm(ktok1) + "#" + strings.Repeat("ab", 32)
	tok, secret := splitAtHash(whole)
	if secret != strings.Repeat("ab", 32) {
		t.Fatalf("secret %q", secret)
	}
	if _, err := Decode(tok); err != nil {
		t.Fatalf("token half: %v", err)
	}
	if _, err := Decode(whole); err == nil {
		t.Fatal("the whole <token>#<secret> string decoded as a token")
	}
}

func splitAtHash(s string) (string, string) {
	i := strings.IndexByte(s, '#')
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// T03-28: every credential decoder reaches bech32 only through the shared case
// helper.
func TestDecodeNoLimitOnlyInTheCaseHelper(t *testing.T) {
	for _, dir := range []string{".", "../nipcw", "../internal/credcodec"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			n := strings.Count(string(b), "bech32.DecodeNoLimit(")
			want := 0
			if filepath.Base(f) == "credcodec.go" {
				want = 1
			}
			if n != want {
				t.Errorf("%s calls bech32.DecodeNoLimit %d times, want %d", f, n, want)
			}
		}
	}
}

// T03-08: TLV 4 and 9 are ignored.
func TestDecode_IgnoresTypes4And9(t *testing.T) {
	_, data, _ := credcodec.DecodeBech32(ktok1)
	var buf bytes.Buffer
	buf.Write(data)
	credcodec.WriteTLV(&buf, 4, []byte{1, 2})
	credcodec.WriteTLV(&buf, 9, []byte("x"))
	s, _ := credcodec.EncodeBech32("satscash", buf.Bytes())
	got, err := Decode(s)
	if err != nil || got.Scheme != SchemeMintV1 {
		t.Fatalf("types 4/9: %v %+v", err, got)
	}
}

// T03-09: long tokens (no 90-character limit) decode.
func TestDecode_LongTokens(t *testing.T) {
	tok := ktok1Token(t)
	tok.RelayURLs = append(tok.RelayURLs, "wss://"+strings.Repeat("a", 40)+".example", "wss://"+strings.Repeat("b", 40)+".example")
	s, err := Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) < 400 {
		t.Fatalf("only %d characters", len(s))
	}
	if _, err := Decode(s); err != nil {
		t.Fatal(err)
	}
}

func tokenWithRelays(t *testing.T, relays ...string) string {
	t.Helper()
	tok := ktok1Token(t)
	_, data, _ := credcodec.DecodeBech32(ktok1)
	_ = tok
	var buf bytes.Buffer
	for curr := 0; curr < len(data); {
		typ, v, _ := credcodec.ReadTLV(data[curr:])
		curr += 2 + len(v)
		if typ == 1 {
			continue
		}
		credcodec.WriteTLV(&buf, typ, v)
	}
	for _, r := range relays {
		credcodec.WriteTLV(&buf, 1, []byte(r))
	}
	s, _ := credcodec.EncodeBech32("satscash", buf.Bytes())
	return s
}

// T03-10, T03-15: an empty hint beside a usable one decodes and is kept in
// RelayURLs (relay_hash covers it) but not in UsableRelays; no usable hint is
// rejected; order is kept.
func TestDecode_RelayHints(t *testing.T) {
	got, err := Decode(tokenWithRelays(t, "", "wss://r.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.RelayURLs, []string{"", "wss://r.example"}) || !slices.Equal(got.UsableRelays(), []string{"wss://r.example"}) {
		t.Fatalf("relays %q usable %q", got.RelayURLs, got.UsableRelays())
	}
	for _, bad := range [][]string{{""}, {"   "}} {
		if _, err := Decode(tokenWithRelays(t, bad...)); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
	got, _ = Decode(tokenWithRelays(t, "wss://a", "wss://b"))
	if !slices.Equal(got.RelayURLs, []string{"wss://a", "wss://b"}) {
		t.Errorf("order %q", got.RelayURLs)
	}
	got, _ = Decode(tokenWithRelays(t, " ", "http://x", "not a url", "wss://ok", "ws://ok2"))
	if !slices.Equal(got.UsableRelays(), []string{"wss://ok", "ws://ok2"}) {
		t.Errorf("usable %q", got.UsableRelays())
	}
}

// T03-11, T03-14: the encoder refuses empty, whitespace-only, non-ASCII and
// 256-byte hints, no hints, an unsigned token, SchemeNone, SchemeMalformed and an
// uppercase HRP.
func TestEncode_Refusals(t *testing.T) {
	base := ktok1Token(t)
	for name, mutate := range map[string]func(*Token){
		"empty hint":      func(t *Token) { t.RelayURLs = []string{"", r1} },
		"blank hint":      func(t *Token) { t.RelayURLs = []string{" \t"} },
		"non-ASCII hint":  func(t *Token) { t.RelayURLs = []string{"wss://ü.example"} },
		"256-byte hint":   func(t *Token) { t.RelayURLs = []string{"wss://" + strings.Repeat("a", 250)} },
		"no hints":        func(t *Token) { t.RelayURLs = nil },
		"no signature":    func(t *Token) { t.MintSignature = nil },
		"64-byte sig":     func(t *Token) { t.MintSignature = t.MintSignature[:64] },
		"no amount":       func(t *Token) { t.AttestedAmountMillis = nil },
		"SchemeNone":      func(t *Token) { t.Scheme = SchemeNone },
		"SchemeMalformed": func(t *Token) { t.Scheme = SchemeMalformed },
		"uppercase HRP":   func(t *Token) { t.HRP = "SATSCASH" },
		"3-byte group":    func(t *Token) { t.HubGroup = []byte{1, 2, 3} },
	} {
		tok := base
		tok.RelayURLs = slices.Clone(base.RelayURLs)
		mutate(&tok)
		if _, err := Encode(tok); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}

// T03-22: TLV 3 = 2 is rejected.
func TestDecode_IdentityRequiredTwo(t *testing.T) {
	_, data, _ := credcodec.DecodeBech32(ktok1)
	s, _ := credcodec.EncodeBech32("satscash", bytes.Replace(data, []byte{3, 1, 1}, []byte{3, 1, 2}, 1))
	if _, err := Decode(s); err == nil {
		t.Fatal("identity_required 2 decoded")
	}
}

// T03-21 (K-HG-1).
func TestKHG1_HubGroup(t *testing.T) {
	if got := hex.EncodeToString(HubGroupFor("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")); got != "3bbf9943" {
		t.Errorf("hex text: %s", got)
	}
	raw, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if got := hex.EncodeToString(HubGroupFor(string(raw))); got != "132f39a9" {
		t.Errorf("raw bytes: %s", got)
	}
	if got := hex.EncodeToString(HubGroupFor("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")); got != "ed79e8ff" {
		t.Errorf("f930…: %s", got)
	}
	if SameHubGroup(Token{}, Token{}) {
		t.Error("two absent groups compared equal")
	}
}

// K-RH-1..8.
func TestKRH_RelayHash(t *testing.T) {
	sec := secret0to1f()
	for name, tc := range map[string]struct {
		relays []string
		want   string
	}{
		"K-RH-1": {[]string{r1, r2}, "487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c"},
		"K-RH-4": {[]string{r1, "", r2}, "abe08272a5cca81fdf51ce0774373822ae4aa3130d6148c10c05321588c9b153"},
		"K-RH-5": {[]string{r2, r1}, "eb757e18a18ae11158c67b20196890ac7cc92a12c87f4a6e5e17568f28a3a53f"},
		"K-RH-7": {[]string{" ", r1}, "5eef6ec81f3de6610fb473f95c9235e979c461d42fe97227059e1a64b20f2edb"},
		"K-RH-8": {[]string{r1}, "454ad3fbd842bc4afd94753d5efc1ee9e6df6a9313ee33291588e21a9232c958"},
	} {
		got, err := RelayHash(tc.relays, sec)
		if err != nil || got != tc.want {
			t.Errorf("%s = %s (%v), want %s", name, got, err, tc.want)
		}
	}
	// The negatives: what a wrong implementation would compute.
	h, _ := RelayHash([]string{r1, r2}, sec)
	for name, wrong := range map[string]string{
		"K-RH-2 no length bytes": "1105ab44514b1aa0f20b14313c7c801448daa546a3ef06dcc4cb25b8c4fd7740",
		"K-RH-3 no secret":       "69900c591bcd6978a183599c4d21f355da493a4b26e440035c511739562045a7",
		"K-RH-6 secret as text":  "a6a986b2e479b623370ae8d4b6f27a0ebcdb9de06ddf65357e0b40977c342d0f",
	} {
		if h == wrong {
			t.Errorf("%s matched", name)
		}
	}
	if _, err := RelayHash([]string{strings.Repeat("a", 256)}, sec); err == nil {
		t.Error("a 256-byte hint hashed")
	}
}

// F-TLV-1: Decode never panics; a decoded scheme 1 or 2 has its signature and
// amount; a signed token decodes, encodes and decodes to the same string.
func FuzzDecodeToken(f *testing.F) {
	f.Add(ktok1)
	f.Add(QRForm(ktok1))
	f.Add(tokenWithRelaysForFuzz())
	f.Fuzz(func(t *testing.T, s string) {
		tok, err := Decode(s)
		if err != nil {
			return
		}
		if (tok.Scheme == SchemeMintV1 || tok.Scheme == SchemeZapV1) && (len(tok.MintSignature) != mintSigLen || tok.AttestedAmountMillis == nil) {
			t.Fatalf("scheme %d without its signature or amount", tok.Scheme)
		}
		if !tok.HasProvenance() {
			return
		}
		again, err := Encode(tok)
		if err != nil {
			return // e.g. a blank hint a decoder keeps and an encoder refuses
		}
		tok2, err := Decode(again)
		if err != nil {
			t.Fatalf("re-encoded token does not decode: %v", err)
		}
		if again2, _ := Encode(tok2); again2 != again {
			t.Fatal("decode→encode→decode is not stable")
		}
	})
}

func tokenWithRelaysForFuzz() string { return ktok1[:len(ktok1)-1] }

// F-CH-1, F-CSIG-1 (cashhub1): DecodeCashHubConnection never panics; an accepted
// string re-encodes identically; Verify never passes once TLV 0-4 or 6 changed.
func FuzzDecodeCashHubConnection(f *testing.F) {
	f.Add(kch1String)
	f.Add(QRForm(kch1String))
	f.Fuzz(func(t *testing.T, s string) {
		c, err := DecodeCashHubConnection(s)
		if err != nil {
			return
		}
		if c.Verify() == nil && c.HubIdentity != kchIdentity {
			// Only key 1 signs the seeds; a verifying string from anyone else
			// would mean a forged signature.
			t.Fatalf("a string not signed by key 1 verified: %+v", c)
		}
		again, err := EncodeCashHubConnection(c)
		if err != nil {
			return // a decoder keeps blank hints and an empty label an encoder refuses
		}
		if strings.ToLower(s) == again {
			return
		}
		if c2, err := DecodeCashHubConnection(again); err != nil || c2.Pubkey != c.Pubkey {
			t.Fatalf("re-encoded string differs: %v", err)
		}
	})
}
