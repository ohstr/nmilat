package vectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ohstr/nmilat/nipcash"
)

type provenanceFile struct {
	header
	MintPayload  []mintPayloadCase  `json:"mintPayload"`
	ZapPayload   []zapPayloadCase   `json:"zapPayload"`
	SpecToken    specTokenCase      `json:"specToken"`
	Prefix       []prefixCase       `json:"signedMessagePrefix"`
	ChainPrefix  []chainPrefixCase  `json:"chainSignedMessagePrefix"`
	ReservedText []reservedTextCase `json:"reservedSignText"`
	Verify       []verifyCase       `json:"verify"`
}

// mintPayloadCase: K-PAY-1/2 and others, MintPayloadV1(hrp, wallet, amount,
// relayHash) where relayHash = RelayHash(relays, secret).
type mintPayloadCase struct {
	Name         string   `json:"name"`
	HRP          string   `json:"hrp"`
	WalletPubkey string   `json:"walletPubkey"`
	AmountMillis string   `json:"amountMillis"`
	Relays       []string `json:"relays"`
	Secret       string   `json:"secret"`
	RelayHash    string   `json:"relayHash"`
	Payload      string   `json:"payload"`
}

// zapPayloadCase: ZapPayloadV1, scheme 2 (K-ZAP-1). Error is set for a field
// the payload refuses.
type zapPayloadCase struct {
	Name         string  `json:"name"`
	HRP          string  `json:"hrp"`
	WalletPubkey string  `json:"walletPubkey"`
	AmountMillis string  `json:"amountMillis"`
	RelayHash    string  `json:"relayHash"`
	Zap          zapJSON `json:"zap"`
	TargetHash   string  `json:"targetHash,omitempty"`
	Payload      string  `json:"payload,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// specTokenCase: K-TOK-1's signature. Digest is sha256d(prefix || payload);
// the signature is LocalMintSigner's (RFC 6979) and must equal the spec's.
type specTokenCase struct {
	MinterSecret string `json:"minterSecret"`
	Prefix       string `json:"prefix"`
	Payload      string `json:"payload"`
	Digest       string `json:"digest"`
	Signature    string `json:"signature"`
	Header       int    `json:"header"`
	Minter       string `json:"minter"`
	MinterXOnly  string `json:"minterXOnly"`
	Token        string `json:"token"`
}

// prefixCase: the signed-message prefix for HRP, null when the HRP has none
// (and so can carry no provenance); chain is ChainForHRP's answer.
type prefixCase struct {
	HRP    string  `json:"hrp"`
	Prefix *string `json:"prefix"`
	Chain  *string `json:"chain"`
}

type chainPrefixCase struct {
	Chain  string  `json:"chain"`
	Prefix *string `json:"prefix"`
}

// reservedTextCase: IsReservedSignText, the five labels a Hub's generic
// sign-message method refuses.
type reservedTextCase struct {
	Text     string `json:"text"`
	Reserved bool   `json:"reserved"`
}

// verifyCase: VerifyProvenance (scheme 1) or VerifyZapProvenance (scheme 2,
// with zap) on the given token fields returns Minter (a compressed secp256k1
// pubkey, hex) or null for no provenance. A tampered token usually still
// recovers SOME key, just not the true signer's; the vectors pin exactly
// which one.
type verifyCase struct {
	Name                 string   `json:"name"`
	HRP                  string   `json:"hrp"`
	WalletPubkey         string   `json:"walletPubkey"`
	Relays               []string `json:"relays"`
	Secret               string   `json:"secret"`
	Scheme               int      `json:"scheme"`
	Zap                  *zapJSON `json:"zap,omitempty"`
	MintSignature        *string  `json:"mintSignature"`
	AttestedAmountMillis *string  `json:"attestedAmountMillis"`
	Minter               *string  `json:"minter"`
}

func privKey(b []byte) *secp256k1.PrivateKey { return secp256k1.PrivKeyFromBytes(b) }

func seq(from byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = from + byte(i)
	}
	return b
}

func doubleSHA256(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// signText signs like a Lightning node's signmessage: a compact recoverable
// signature over sha256d(prefix || text), RFC 6979.
func signText(priv *secp256k1.PrivateKey, prefix, text string, compressed bool) []byte {
	return ecdsa.SignCompact(priv, doubleSHA256([]byte(prefix+text)), compressed)
}

// Spec token inputs (NIP-CASH §Token Test Vectors, K-TOK-1).
const (
	specWallet    = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	specRelay1    = "wss://relay.example.com"
	specRelay2    = "wss://backup.example.net"
	specMinterKey = "0101010101010101010101010101010101010101010101010101010101010101"
	specToken     = "satscash1qqsvvprlj3q76ltdxpz5qm54cp7dshrh3e9cemeu5746czdet3cfaegpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgprpmhxue69uhkyctrdd6hqtn90psk6urvv5hxuet5qgsqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8crqyqs2sfq7gvnhvt0jjxg049a9kg9jnl306hyqexhxn6gw3e0928ftmtxr7n5r2emz4x3r8q6lrx6hgjhzrykwj9wtnchnh78hjcz23pr6n2tf7sxpqqqqqqqqqq9yzq8qnkhn68lpqqszp39gk7"
)

func specSecret() string { return hex.EncodeToString(seq(0)) }

// specUnsigned is K-TOK-1 without its signature.
func specUnsigned() nipcash.Token {
	amt := uint64(21000)
	yes := true
	return nipcash.Token{HRP: "satscash", WalletPubkey: specWallet, Secret: specSecret(),
		RelayURLs: []string{specRelay1, specRelay2}, IdentityRequired: &yes, AttestedAmountMillis: &amt,
		HubGroup: []byte{0xed, 0x79, 0xe8, 0xff}}
}

// specZap is K-ZAP-1's context (NIP-CZ scheme-2 example).
func specZap() nipcash.ZapContext {
	return nipcash.ZapContext{Recipient: "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
		Sender:    "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
		ZapTarget: "30023:e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13:my-article", IssuedAt: 1720000000}
}

func buildProvenance() (any, error) {
	f := provenanceFile{header: newHeader(
		"Mint provenance: the cash-mint:v1 and cash-zap:v1 payloads over the relay hash, the per-HRP signed-message prefix, public-key recovery from the 65-byte compact signature over sha256d, and the reserved sign-text labels.",
		"nipcash/provenance.go, nipcash/sign.go; nipcash/provenance_test.go, token_codec_test.go (K-PAY-1, K-PAY-2, K-PAY-4, K-ZAP-1, K-TOK-1)",
	)}
	rhSpec, err := nipcash.RelayHash([]string{specRelay1, specRelay2}, specSecret())
	if err != nil {
		return nil, err
	}
	walletA := hex.EncodeToString(repeat(0x22, 32))
	for _, c := range []struct {
		name, hrp, wallet string
		amount            uint64
		relays            []string
		secret            string
	}{
		{"K-PAY-1", "satscash", specWallet, 21000, []string{specRelay1, specRelay2}, specSecret()},
		{"K-PAY-2 (the label stays cash-mint:v1)", "lokicash", specWallet, 21000, []string{specRelay1, specRelay2}, specSecret()},
		{"zero amount, one hint", "satscash", walletA, 0, []string{specRelay1}, specSecret()},
		{"max amount, no hint", "xyzcash", walletA, 18446744073709551615, []string{}, specSecret()},
	} {
		rh, err := nipcash.RelayHash(c.relays, c.secret)
		if err != nil {
			return nil, err
		}
		f.MintPayload = append(f.MintPayload, mintPayloadCase{c.name, c.hrp, c.wallet, strconv.FormatUint(c.amount, 10), c.relays, c.secret, rh, nipcash.MintPayloadV1(c.hrp, c.wallet, c.amount, rh)})
	}
	// K-PAY-4: an uppercase HRP in a hand-built token signs the lowercase one.
	up := specUnsigned()
	up.HRP = "SATSCASH"
	up.Scheme = nipcash.SchemeMintV1
	if p, err := nipcash.ProvenancePayload(up, nil); err != nil {
		return nil, err
	} else {
		f.MintPayload = append(f.MintPayload, mintPayloadCase{"K-PAY-4 (uppercase HRP in a hand-built token)", "SATSCASH", specWallet, "21000", up.RelayURLs, up.Secret, rhSpec, p})
	}

	zap := func(name string, z nipcash.ZapContext) {
		c := zapPayloadCase{Name: name, HRP: "satscash", WalletPubkey: specWallet, AmountMillis: "5000", RelayHash: rhSpec, Zap: toZapJSON(z)}
		p, err := nipcash.ZapPayloadV1("satscash", specWallet, 5000, rhSpec, z)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Payload = p
			parts := strings.Split(p, ":")
			c.TargetHash = parts[len(parts)-3]
		}
		f.ZapPayload = append(f.ZapPayload, c)
	}
	zap("K-ZAP-1", specZap())
	z := specZap()
	z.ZapTarget = "hello world"
	zap("target hashed exactly as given", z)
	z = specZap()
	z.ExpiresAt = 1720086400
	zap("with an expiry", z)
	z = specZap()
	z.ZapTarget = ""
	zap("empty target", z)
	z = specZap()
	z.Recipient = strings.ToUpper(z.Recipient)
	zap("uppercase recipient", z)
	z = specZap()
	z.Sender = z.Sender[:62]
	zap("short sender", z)

	// K-TOK-1's signature.
	sign, err := nipcash.LocalMintSigner(specMinterKey, "satscash")
	if err != nil {
		return nil, err
	}
	payload := nipcash.MintPayloadV1("satscash", specWallet, 21000, rhSpec)
	tok, err := nipcash.SignToken(specUnsigned(), nipcash.SchemeMintV1, nil, "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", sign)
	if err != nil {
		return nil, err
	}
	minter, ok := nipcash.VerifyProvenance(tok)
	if !ok {
		return nil, fmt.Errorf("K-TOK-1 does not verify")
	}
	xonly, _ := nipcash.MinterXOnly(minter)
	enc, err := nipcash.Encode(tok)
	if err != nil {
		return nil, err
	}
	if enc != specToken {
		return nil, fmt.Errorf("K-TOK-1: the signed token is not the spec string")
	}
	f.SpecToken = specTokenCase{specMinterKey, nipcash.LndSignedMessagePrefix, payload,
		hex.EncodeToString(doubleSHA256([]byte(nipcash.LndSignedMessagePrefix + payload))),
		hex.EncodeToString(tok.MintSignature), int(tok.MintSignature[0]), minter, xonly, enc}

	for _, hrp := range []string{"lokicash", "satscash", "xyzcash", "SATSCASH", ""} {
		c := prefixCase{HRP: hrp}
		if s, ok := nipcash.SignedMessagePrefix(hrp); ok {
			c.Prefix = &s
		}
		if s, ok := nipcash.ChainForHRP(hrp); ok {
			c.Chain = &s
		}
		f.Prefix = append(f.Prefix, c)
	}
	for _, ch := range []string{"bitcoin", "flokicoin", "Bitcoin", "testnet", ""} {
		c := chainPrefixCase{Chain: ch}
		if s, ok := nipcash.ChainSignedMessagePrefix(ch); ok {
			c.Prefix = &s
		}
		f.ChainPrefix = append(f.ChainPrefix, c)
	}
	for _, t := range []string{"cash-mint:v1:x", "cash-zap:v1:x", "cash-hub:v1:x", "cash-order:v1:x", "circle-hub:v1:x",
		"CASH-MINT:v1", "Cash-Hub:", "cash-mint", "hello", " cash-mint:v1", "circle-hub", "cash-withdraw:v1"} {
		f.ReservedText = append(f.ReservedText, reservedTextCase{t, nipcash.IsReservedSignText(t)})
	}

	add := func(name string, t nipcash.Token, zc *nipcash.ZapContext) {
		c := verifyCase{Name: name, HRP: t.HRP, WalletPubkey: t.WalletPubkey, Relays: t.RelayURLs, Secret: t.Secret, Scheme: int(t.Scheme)}
		if zc != nil {
			zj := toZapJSON(*zc)
			c.Zap = &zj
		}
		if c.Relays == nil {
			c.Relays = []string{}
		}
		if t.MintSignature != nil {
			c.MintSignature = strPtr(hex.EncodeToString(t.MintSignature))
		}
		if t.AttestedAmountMillis != nil {
			c.AttestedAmountMillis = strPtr(strconv.FormatUint(*t.AttestedAmountMillis, 10))
		}
		var m string
		var ok bool
		if zc != nil {
			m, ok = nipcash.VerifyZapProvenance(t, *zc)
		} else {
			m, ok = nipcash.VerifyProvenance(t)
		}
		if ok {
			c.Minter = &m
		}
		f.Verify = append(f.Verify, c)
	}
	amt := func(v uint64) *uint64 { return &v }
	with := func(mod func(*nipcash.Token)) nipcash.Token {
		t := tok
		t.RelayURLs = append([]string(nil), tok.RelayURLs...)
		mod(&t)
		return t
	}
	signer := privKey(seq(33))
	other := privKey(seq(65))
	lnd := nipcash.LndSignedMessagePrefix
	flnd := nipcash.LNSignedMessagePrefix
	signed := func(priv *secp256k1.PrivateKey, prefix string, t nipcash.Token, compressed bool) nipcash.Token {
		p, err := nipcash.ProvenancePayload(t, nil)
		if err != nil {
			panic(err)
		}
		t.MintSignature = signText(priv, prefix, p, compressed)
		return t
	}
	base := with(func(t *nipcash.Token) { t.MintSignature = nil })

	add("K-TOK-1", tok, nil)
	add("valid, another signer", signed(signer, lnd, base, true), nil)
	loki := with(func(t *nipcash.Token) { t.HRP = "lokicash" })
	add("lokicash under the flnd prefix", signed(signer, flnd, loki, true), nil)
	add("lokicash signed under the lnd prefix", signed(signer, lnd, loki, true), nil)
	add("satscash signed under the flnd prefix", signed(signer, flnd, base, true), nil)
	add("uncompressed recovery flag still yields the compressed key", signed(signer, lnd, base, false), nil)
	add("signature from another node", signed(other, lnd, base, true), nil)

	// Tampering: recovery succeeds but yields a different key.
	add("tampered amount", with(func(t *nipcash.Token) { t.AttestedAmountMillis = amt(21001) }), nil)
	add("tampered wallet pubkey", with(func(t *nipcash.Token) { t.WalletPubkey = walletA }), nil)
	add("tampered hrp", with(func(t *nipcash.Token) { t.HRP = "lokicash" }), nil)
	add("relay hints swapped", with(func(t *nipcash.Token) { t.RelayURLs = []string{specRelay2, specRelay1} }), nil)
	add("relay hint removed", with(func(t *nipcash.Token) { t.RelayURLs = t.RelayURLs[:1] }), nil)
	add("relay hint added", with(func(t *nipcash.Token) { t.RelayURLs = append(t.RelayURLs, "wss://x.example") }), nil)
	add("tampered secret", with(func(t *nipcash.Token) { t.Secret = strings.Repeat("44", 32) }), nil)

	// Scheme 2.
	zs, err := nipcash.SignToken(with(func(t *nipcash.Token) { t.MintSignature = nil; t.AttestedAmountMillis = amt(5000) }), nipcash.SchemeZapV1, ptrZap(specZap()), "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", sign)
	if err != nil {
		return nil, err
	}
	add("scheme 2 with its zap", zs, ptrZap(specZap()))
	zOther := specZap()
	zOther.IssuedAt++
	add("scheme 2 with another issued_at", zs, &zOther)
	add("scheme 2 read as scheme 1", zs, nil)
	add("scheme 1 read with a zap", tok, ptrZap(specZap()))

	// No provenance at all.
	add("unknown hrp", with(func(t *nipcash.Token) { t.HRP = "xyzcash" }), nil)
	add("signature without amount", with(func(t *nipcash.Token) { t.AttestedAmountMillis = nil }), nil)
	add("amount without signature", base, nil)
	add("short signature", with(func(t *nipcash.Token) { t.MintSignature = t.MintSignature[:64] }), nil)
	add("all-zero signature", with(func(t *nipcash.Token) { t.MintSignature = make([]byte, 65) }), nil)
	add("scheme none", with(func(t *nipcash.Token) { t.Scheme = nipcash.SchemeNone }), nil)

	// Recovery headers: 27..34 and the raw recid recover; 26 and 35 do not.
	for _, h := range []byte{0, 1, 3, 26, 27, 28, 31, 32, 34, 35, 255} {
		add(fmt.Sprintf("header byte %d", h), with(func(t *nipcash.Token) { t.MintSignature = append([]byte{h}, tok.MintSignature[1:]...) }), nil)
	}
	sigA := tok.MintSignature
	zeroR := append(append([]byte{sigA[0]}, make([]byte, 32)...), sigA[33:]...)
	zeroS := append(append([]byte{}, sigA[:33]...), make([]byte, 32)...)
	maxR := append(append([]byte{sigA[0]}, repeat(0xff, 32)...), sigA[33:]...)
	add("r = 0", with(func(t *nipcash.Token) { t.MintSignature = zeroR }), nil)
	add("s = 0", with(func(t *nipcash.Token) { t.MintSignature = zeroS }), nil)
	add("r = 2^256-1", with(func(t *nipcash.Token) { t.MintSignature = maxR }), nil)
	add("high s with flipped recovery parity", with(func(t *nipcash.Token) { t.MintSignature = highS(sigA) }), nil)
	return f, nil
}

// zapJSON is a ZapContext as the vector files spell it.
type zapJSON struct {
	Recipient string `json:"recipient"`
	Sender    string `json:"sender"`
	ZapTarget string `json:"zapTarget"`
	IssuedAt  uint64 `json:"issuedAt"`
	ExpiresAt uint64 `json:"expiresAt"`
}

func toZapJSON(z nipcash.ZapContext) zapJSON {
	return zapJSON{z.Recipient, z.Sender, z.ZapTarget, z.IssuedAt, z.ExpiresAt}
}

func ptrZap(z nipcash.ZapContext) *nipcash.ZapContext { return &z }

// highS returns the malleated twin of a compact signature: s -> n - s, with
// the recovery parity flipped so the same key is recovered if high s is
// accepted.
func highS(sig []byte) []byte {
	var s secp256k1.ModNScalar
	s.SetByteSlice(sig[33:])
	s.Negate()
	out := append([]byte{}, sig[:33]...)
	sb := s.Bytes()
	out = append(out, sb[:]...)
	out[0] = 27 + (((sig[0] - 27) & 4) | (((sig[0] - 27) & 3) ^ 1))
	return out
}
