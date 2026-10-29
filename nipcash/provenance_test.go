package nipcash

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
)

func keyN(n byte) string { return strings.Repeat("0", 62) + hex.EncodeToString([]byte{n}) }

const (
	ktokMinter = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
	ktokPay1   = "cash-mint:v1:satscash:" + ktokWallet + ":21000:487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c"
	kzapTarget = "30023:e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13:my-article"
	kzapPay    = "cash-zap:v1:satscash:" + ktokWallet + ":5000:487f70e79899e5f04dabdeaa62db4654d0d005db40496df0930c5e12e8d2775c:" +
		"pubkey/2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4:" +
		"pubkey/fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556:" +
		"79c69fd2170904248edc898066fce02a7fefa36235f4fb863f4329c99f891b8f:1720000000:0"
)

func kzapContext() ZapContext {
	return ZapContext{Recipient: "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
		Sender: "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556", ZapTarget: kzapTarget, IssuedAt: 1720000000}
}

func unsignedKTOK(t *testing.T) Token {
	tok := ktok1Token(t)
	tok.MintSignature, tok.Scheme = nil, SchemeNone
	return tok
}

func minterKey1() string { return strings.Repeat("01", 32) }

// T04-02 (K-PAY-1, K-PAY-2), T04-08 (K-PAY-4).
func TestT04_02_MintPayloadV1(t *testing.T) {
	rh, _ := RelayHash([]string{r1, r2}, secret0to1f())
	if got := MintPayloadV1("satscash", ktokWallet, 21000, rh); got != ktokPay1 {
		t.Fatalf("K-PAY-1 = %s", got)
	}
	if got := MintPayloadV1("lokicash", ktokWallet, 21000, rh); !strings.HasPrefix(got, "cash-mint:v1:lokicash:") {
		t.Errorf("K-PAY-2 = %s", got)
	}
	tok := ktok1Token(t)
	tok.HRP = "SATSCASH"
	if got, _ := ProvenancePayload(tok, nil); got != ktokPay1 {
		t.Errorf("K-PAY-4 = %s", got)
	}
}

// T04-03 (K-ZAP-1), T04-04.
func TestT04_03_ZapPayloadV1(t *testing.T) {
	rh, _ := RelayHash([]string{r1, r2}, secret0to1f())
	got, err := ZapPayloadV1("satscash", ktokWallet, 5000, rh, kzapContext())
	if err != nil || got != kzapPay {
		t.Fatalf("K-ZAP-1 = %s (%v)", got, err)
	}
	z := kzapContext()
	z.ZapTarget = "hello world"
	got, _ = ZapPayloadV1("satscash", ktokWallet, 5000, rh, z)
	if !strings.Contains(got, ":b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9:") {
		t.Errorf("target_hash of hello world: %s", got)
	}
	for name, mutate := range map[string]func(*ZapContext){
		"empty target":        func(z *ZapContext) { z.ZapTarget = "" },
		"uppercase recipient": func(z *ZapContext) { z.Recipient = strings.ToUpper(z.Recipient) },
		"short sender":        func(z *ZapContext) { z.Sender = z.Sender[:62] },
	} {
		z := kzapContext()
		mutate(&z)
		if _, err := ZapPayloadV1("satscash", ktokWallet, 5000, rh, z); !errors.Is(err, ErrPayloadField) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// T04-06, T04-16, T04-17 (K-TOK-1 signature): the spec digest, the spec TLV 5 from
// LocalMintSigner, the spec minter; the bare payload recovers nothing useful.
func TestT04_16_SpecSignature(t *testing.T) {
	if d := hex.EncodeToString(doubleSHA256([]byte(LndSignedMessagePrefix + ktokPay1))); d != "278d47f6702494ccb7127d9ff80ed049ac324ac6bb30287a20a11c54520cdf23" {
		t.Fatalf("digest %s", d)
	}
	sign, err := LocalMintSigner(minterKey1(), "satscash")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := SignToken(unsignedKTOK(t), SchemeMintV1, nil, ktokMinter[2:], sign)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tok.MintSignature) != ktokSig || tok.MintSignature[0] != 32 {
		t.Fatalf("TLV 5 = %x", tok.MintSignature)
	}
	got, ok := VerifyProvenance(tok)
	if !ok || got != ktokMinter {
		t.Fatalf("minter %s %v", got, ok)
	}
	if x, _ := MinterXOnly(got); x != ktokMinter[2:] {
		t.Errorf("MinterXOnly %s", x)
	}
	if x2, _ := MinterXOnly("02" + ktokMinter[2:]); x2 != ktokMinter[2:] {
		t.Errorf("MinterXOnly of the 02 form %s", x2)
	}
	if s, _ := Encode(tok); s != ktok1 {
		t.Errorf("SignToken + Encode is not the spec token")
	}
	decoded, _ := Decode(ktok1)
	if m, ok := VerifyProvenance(decoded); !ok || m != ktokMinter {
		t.Errorf("spec token: %s %v", m, ok)
	}
	if pub, _, err := recoverWithDigest(tok.MintSignature, doubleSHA256([]byte(ktokPay1))); err == nil && pub == ktokMinter {
		t.Error("the bare payload recovered the minter")
	}
}

// T04-07: an unknown HRP has no provenance but decodes.
func TestT04_07_UnknownHRP(t *testing.T) {
	tok := ktok1Token(t)
	tok.HRP = "xyzcash"
	s, err := Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := VerifyProvenance(d); ok {
		t.Error("an unknown HRP verified")
	}
	if _, err := LocalMintSigner(minterKey1(), "xyzcash"); err == nil {
		t.Error("a signer for an unknown HRP")
	}
}

// T04-09: headers 27..34 and raw 0..3 recover; 26 and 35 do not.
func TestT04_09_Headers(t *testing.T) {
	tok := ktok1Token(t)
	recid := tok.MintSignature[0] - 31
	for h := byte(27); h <= 34; h++ {
		if (h-27)%4 != recid {
			continue
		}
		tok.MintSignature = append([]byte{h}, tok.MintSignature[1:]...)
		if _, ok := VerifyProvenance(tok); !ok {
			t.Errorf("header %d refused", h)
		}
	}
	tok.MintSignature = append([]byte{recid}, tok.MintSignature[1:]...)
	if _, ok := VerifyProvenance(tok); !ok {
		t.Error("raw recid refused")
	}
	for _, h := range []byte{26, 35} {
		tok.MintSignature = append([]byte{h}, tok.MintSignature[1:]...)
		if _, ok := VerifyProvenance(tok); ok {
			t.Errorf("header %d accepted", h)
		}
	}
}

// T04-10, T04-11, T04-15: any change to the hints, the secret or the amount voids
// the provenance; a bill reissued with new hints and re-signed verifies too.
func TestT04_10_RelayHashBinding(t *testing.T) {
	base := ktok1Token(t)
	for name, mutate := range map[string]func(*Token){
		"swapped":   func(t *Token) { t.RelayURLs = []string{r2, r1} },
		"added":     func(t *Token) { t.RelayURLs = []string{r1, r2, "wss://x"} },
		"removed":   func(t *Token) { t.RelayURLs = []string{r1} },
		"empty one": func(t *Token) { t.RelayURLs = []string{r1, "", r2} },
		"secret":    func(t *Token) { t.Secret = strings.Repeat("44", 32) },
		"amount":    func(t *Token) { a := uint64(21001); t.AttestedAmountMillis = &a },
	} {
		tok := base
		tok.RelayURLs = slices.Clone(base.RelayURLs)
		mutate(&tok)
		// Any signature recovers some key; "verifies" means it recovers the minter.
		if m, _ := VerifyProvenance(tok); m == ktokMinter {
			t.Errorf("%s: still recovers the minter", name)
		}
	}
	sign, _ := LocalMintSigner(minterKey1(), "satscash")
	re := unsignedKTOK(t)
	re.RelayURLs = []string{"wss://new.example"}
	re, err := SignToken(re, SchemeMintV1, nil, ktokMinter[2:], sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := VerifyProvenance(re); !ok {
		t.Error("the reissued token does not verify")
	}
	if _, ok := VerifyProvenance(base); !ok {
		t.Error("the earlier token stopped verifying")
	}
}

// T04-12: scheme 2 verifies only through VerifyZapProvenance with its context.
func TestT04_12_ZapProvenance(t *testing.T) {
	sign, _ := LocalMintSigner(minterKey1(), "satscash")
	tok := unsignedKTOK(t)
	amt := uint64(5000)
	tok.AttestedAmountMillis = &amt
	z := kzapContext()
	tok, err := SignToken(tok, SchemeZapV1, &z, ktokMinter[2:], sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := VerifyProvenance(tok); ok {
		t.Error("scheme 2 verified without its context")
	}
	if m, ok := VerifyZapProvenance(tok, z); !ok || m != ktokMinter {
		t.Fatalf("zap: %s %v", m, ok)
	}
	for name, mutate := range map[string]func(*ZapContext){
		"recipient": func(z *ZapContext) { z.Recipient = z.Sender },
		"sender":    func(z *ZapContext) { z.Sender = z.Recipient },
		"target":    func(z *ZapContext) { z.ZapTarget += "x" },
		"issued_at": func(z *ZapContext) { z.IssuedAt++ },
		"expires":   func(z *ZapContext) { z.ExpiresAt = 1 },
	} {
		zz := z
		mutate(&zz)
		if m, _ := VerifyZapProvenance(tok, zz); m == ktokMinter {
			t.Errorf("%s changed and still recovers the minter", name)
		}
	}
	if _, err := SignToken(unsignedKTOK(t), SchemeZapV1, nil, ktokMinter[2:], sign); !errors.Is(err, ErrZapContextRequired) {
		t.Errorf("zap without context: %v", err)
	}
	if _, err := SignToken(unsignedKTOK(t), SchemeMintV1, &z, ktokMinter[2:], sign); !errors.Is(err, ErrZapContextUnexpected) {
		t.Errorf("mint with context: %v", err)
	}
}

// T04-13, T04-14: SignToken fails before anything is issued; it is deterministic.
func TestT04_13_SignTokenRefusals(t *testing.T) {
	failing := func(string) ([]byte, error) { return nil, errors.New("node down") }
	if _, err := SignToken(unsignedKTOK(t), SchemeMintV1, nil, ktokMinter[2:], failing); err == nil {
		t.Error("a failing signer issued a token")
	}
	other, _ := LocalMintSigner(keyN(2), "satscash")
	if _, err := SignToken(unsignedKTOK(t), SchemeMintV1, nil, ktokMinter[2:], other); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("wrong key: %v", err)
	}
	blank := unsignedKTOK(t)
	blank.RelayURLs = []string{r1, " "}
	sign, _ := LocalMintSigner(minterKey1(), "satscash")
	if _, err := SignToken(blank, SchemeMintV1, nil, ktokMinter[2:], sign); !errors.Is(err, ErrBlankRelayHint) {
		t.Errorf("blank hint: %v", err)
	}
	if _, err := SignToken(unsignedKTOK(t), SchemeMalformed, nil, ktokMinter[2:], sign); !errors.Is(err, ErrSchemeUnsupported) {
		t.Errorf("SchemeMalformed: %v", err)
	}
	a, _ := SignToken(unsignedKTOK(t), SchemeMintV1, nil, ktokMinter[2:], sign)
	b, _ := SignToken(unsignedKTOK(t), SchemeMintV1, nil, ktokMinter[2:], sign)
	sa, _ := Encode(a)
	sb, _ := Encode(b)
	if sa != sb {
		t.Error("two signings of the same inputs differ")
	}
}

// T04-18.
func TestT04_18_IsReservedSignText(t *testing.T) {
	for _, s := range []string{"cash-mint:x", "CASH-ZAP:x", "cash-hub:x", "cash-order:x", "Circle-Hub:x"} {
		if !IsReservedSignText(s) {
			t.Errorf("%q not reserved", s)
		}
	}
	for _, s := range []string{"cash-mint", "satscash-mint:x", "hello"} { // legacy-check: a removed prefix is no longer reserved
		if IsReservedSignText(s) {
			t.Errorf("%q reserved", s)
		}
	}
}

// T04-23: one prefix table, by HRP and by chain.
func TestT04_23_PrefixTable(t *testing.T) {
	if p, ok := ChainSignedMessagePrefix("bitcoin"); !ok || p != "Lightning Signed Message:" {
		t.Errorf("bitcoin: %q", p)
	}
	if _, ok := ChainSignedMessagePrefix("bitcoin-x"); ok {
		t.Error("unknown chain has a prefix")
	}
	for _, row := range prefixTable {
		a, _ := SignedMessagePrefix(row.hrp)
		b, _ := ChainSignedMessagePrefix(row.chain)
		if a != b || a != row.prefix {
			t.Errorf("row %+v disagrees", row)
		}
	}
}

// T04-24: VerifyConnection reads every header the spec allows.
func TestT04_24_ConnectionHeaders(t *testing.T) {
	c := kch1(t, true)
	recid := c.Signature[0] - 31
	for h := byte(26); h <= 35; h++ {
		sig := append([]byte{h}, c.Signature[1:]...)
		err := VerifyConnection(c.Fields(), sig)
		want := h >= 27 && h <= 34 && (h-27)%4 == recid
		if (err == nil) != want {
			t.Errorf("header %d: %v", h, err)
		}
	}
	if err := VerifyConnection(c.Fields(), append([]byte{recid}, c.Signature[1:]...)); err != nil {
		t.Errorf("raw recid: %v", err)
	}
}

// T11-14, T11-54 (unit), T04-25 (K-ONL-1).
func TestT04_25_OnlineCheck(t *testing.T) {
	id := "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	o := OnlineCheck{HubIdentity: id, Chain: "bitcoin"}
	for _, v := range []string{id, "02" + id, "03" + id, strings.ToUpper(id)} {
		if err := o.Check(v, "bitcoin"); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"04" + id, id[:63] + "9"} {
		if err := o.Check(v, "bitcoin"); !errors.Is(err, ErrHubIdentityMismatch) {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, c := range []string{"Bitcoin", ""} {
		if err := o.Check(id, c); !errors.Is(err, ErrChainMismatch) {
			t.Errorf("chain %q: %v", c, err)
		}
	}
}

// F-PROV-1: the verifiers never panic.
func FuzzVerifyProvenance(f *testing.F) {
	f.Add([]byte(nil), "satscash", r1, uint8(1))
	f.Add(bytes.Repeat([]byte{31}, 65), "lokicash", "", uint8(2))
	f.Fuzz(func(t *testing.T, sig []byte, hrp, relay string, scheme uint8) {
		amt := uint64(1)
		tok := Token{HRP: hrp, WalletPubkey: ktokWallet, Secret: secret0to1f(), RelayURLs: []string{relay},
			MintSignature: sig, AttestedAmountMillis: &amt, Scheme: SignatureScheme(scheme)}
		VerifyProvenance(tok)
		VerifyZapProvenance(tok, kzapContext())
	})
}
