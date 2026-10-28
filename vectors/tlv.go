package vectors

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
)

// The four TLV string kinds cashkit decodes (design §2.1).
const (
	kindToken       = "token"
	kindCashHub     = "cashhub"
	kindCircleHub   = "circlehub"
	kindNConnection = "nconnection"
	kindCashOrder   = "cashorder"
)

type tlvFile struct {
	header
	Decode []decodeCase `json:"decode"`
	Encode []encodeCase `json:"encode"`
}

// decodeCase: decoding Input as Kind either fails (Error set, Want absent)
// or yields Want.
type decodeCase struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Input string `json:"input"`
	Error string `json:"error,omitempty"`
	Want  any    `json:"want,omitempty"`
}

// encodeCase: encoding Fields as Kind either fails (Error set) or yields
// Output exactly.
type encodeCase struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Fields any    `json:"fields"`
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
}

// tokenJSON is a nipcash.Token in vector form. Byte fields are hex, the
// amount is a decimal string (it is a bigint in TypeScript), and every
// optional field is present with null meaning absent.
type tokenJSON struct {
	HRP                  string   `json:"hrp"`
	WalletPubkey         string   `json:"walletPubkey"`
	Secret               string   `json:"secret"`
	Relays               []string `json:"relays"`
	IdentityRequired     *bool    `json:"identityRequired"`
	MintSignature        *string  `json:"mintSignature"`
	AttestedAmountMillis *string  `json:"attestedAmountMillis"`
	HubGroup             *string  `json:"hubGroup"`
	// Scheme is TLV 8 as decoded: 0 none, 1 cash-mint:v1, 2 cash-zap:v1, 255
	// malformed (the provenance fields are dropped). An encoder writes it
	// when a signature is present.
	Scheme int `json:"scheme"`
}

func tokenToJSON(t nipcash.Token) tokenJSON {
	out := tokenJSON{
		HRP:              t.HRP,
		WalletPubkey:     t.WalletPubkey,
		Secret:           t.Secret,
		Relays:           nonNil(t.RelayURLs),
		IdentityRequired: t.IdentityRequired,
		Scheme:           int(t.Scheme),
	}
	if t.MintSignature != nil {
		out.MintSignature = strPtr(hex.EncodeToString(t.MintSignature))
	}
	if t.AttestedAmountMillis != nil {
		out.AttestedAmountMillis = strPtr(strconv.FormatUint(*t.AttestedAmountMillis, 10))
	}
	if t.HubGroup != nil {
		out.HubGroup = strPtr(hex.EncodeToString(t.HubGroup))
	}
	return out
}

func tokenFromJSON(j tokenJSON) nipcash.Token {
	t := nipcash.Token{
		HRP:              j.HRP,
		WalletPubkey:     j.WalletPubkey,
		Secret:           j.Secret,
		RelayURLs:        j.Relays,
		IdentityRequired: j.IdentityRequired,
		Scheme:           nipcash.SignatureScheme(j.Scheme),
	}
	if j.MintSignature != nil {
		t.MintSignature, _ = hex.DecodeString(*j.MintSignature)
	}
	if j.AttestedAmountMillis != nil {
		amt, _ := strconv.ParseUint(*j.AttestedAmountMillis, 10, 64)
		t.AttestedAmountMillis = &amt
	}
	if j.HubGroup != nil {
		t.HubGroup, _ = hex.DecodeString(*j.HubGroup)
	}
	return t
}

type nconnectionJSON struct {
	ConnectionKey string   `json:"connectionKey"`
	Relays        []string `json:"relays"`
	Platform      string   `json:"platform"`
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type tlv struct {
	typ   byte
	value []byte
}

func tlvBytes(entries []tlv, raw []byte) []byte {
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteByte(e.typ)
		buf.WriteByte(byte(len(e.value)))
		buf.Write(e.value)
	}
	buf.Write(raw)
	return buf.Bytes()
}

func words(data []byte) []byte {
	w, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		panic(err)
	}
	return w
}

// bech32String hand-builds a TLV string, bypassing nmilat's encoders so that
// malformed inputs can be produced.
func bech32String(hrp string, entries []tlv, raw ...byte) string {
	s, err := bech32.Encode(hrp, words(tlvBytes(entries, raw)))
	if err != nil {
		panic(err)
	}
	return s
}

func bech32mString(hrp string, entries []tlv) string {
	s, err := bech32.EncodeM(hrp, words(tlvBytes(entries, nil)))
	if err != nil {
		panic(err)
	}
	return s
}

func decodeAs(kind, input string) (any, error) {
	switch kind {
	case kindToken:
		t, err := nipcash.Decode(input)
		if err != nil {
			return nil, err
		}
		return tokenToJSON(t), nil
	case kindCashHub:
		c, err := nipcash.DecodeCashHubConnection(input)
		if err != nil {
			return nil, err
		}
		return cashHubJSON(c), nil
	case kindCircleHub:
		c, err := nipcw.DecodeCircleHubConnection(input)
		if err != nil {
			return nil, err
		}
		return circleHubJSON(c), nil
	case kindCashOrder:
		c, err := nipCO.DecodeOrderConnection(input)
		if err != nil {
			return nil, err
		}
		return orderConnJSON(c), nil
	case kindNConnection:
		key, relays, platform, err := nipIC.DecodeNConnection(input)
		if err != nil {
			return nil, err
		}
		return nconnectionJSON{string(key), nonNil(relays), string(platform)}, nil
	}
	panic("unknown kind " + kind)
}

func encodeAs(kind string, fields any) (string, error) {
	switch kind {
	case kindToken:
		return nipcash.Encode(tokenFromJSON(fields.(tokenJSON)))
	case kindCashHub:
		return nipcash.EncodeCashHubConnection(fields.(connJSON).cashHub())
	case kindCircleHub:
		return nipcw.EncodeCircleHubConnection(fields.(connJSON).circleHub())
	case kindCashOrder:
		return nipCO.EncodeOrderConnection(fields.(connJSON).order())
	case kindNConnection:
		f := fields.(nconnectionJSON)
		return nipIC.EncodeNConnection(nipIC.ConnectionKey(f.ConnectionKey), f.Relays, nipIC.WebIdentity(f.Platform))
	}
	panic("unknown kind " + kind)
}

func decodeVector(name, kind, input string) decodeCase {
	want, err := decodeAs(kind, input)
	return decodeCase{Name: name, Kind: kind, Input: input, Error: errString(err), Want: want}
}

func encodeVector(name, kind string, fields any) encodeCase {
	out, err := encodeAs(kind, fields)
	return encodeCase{Name: name, Kind: kind, Fields: fields, Error: errString(err), Output: out}
}

var (
	fixKey    = repeat(0x22, 32)
	fixSecret = repeat(0x33, 32)
	fixURL    = []byte("wss://r.example")
	fixSig    = repeat(0x01, 65)
	fixAmount = []byte{0, 0, 0, 0, 0, 0, 0x52, 0x08} // 21000
	fixGroup  = nipcash.HubGroupFor(strings.Repeat("cd", 32))
)

func hrpFor(kind string) string {
	switch kind {
	case kindCashHub:
		return nipcash.CashHubConnectionHRP
	case kindCircleHub:
		return nipcw.CircleHubConnectionHRP
	case kindNConnection:
		return nipIC.NConnectionPrefix
	case kindCashOrder:
		return nipCO.OrderConnectionHRP
	}
	return "lokicash"
}

func buildTLV() (any, error) {
	f := tlvFile{header: newHeader(
		"Decode and encode of cash tokens (any HRP): TLV 0-3, the provenance pair 5/6 and its scheme (TLV 8; without it a token has no valid provenance), the hub group (TLV 7), encoder refusals, ascending entry order on encode, and bech32 framing (an all-uppercase token decodes as its lowercase form, a mixed-case one is refused). Signed connection strings are in connection.json, nconnection1 in nconnection.json.",
		"nipcash/token.go, internal/credcodec; nipcash/token_codec_test.go (K-TOK-1), decode_tlv_rules_test.go, token_test.go, hub_group_test.go, encode_relay_test.go, kat_test.go",
	)}
	add := func(name, kind, input string) { f.Decode = append(f.Decode, decodeVector(name, kind, input)) }

	base := []tlv{{0, fixKey}, {1, fixURL}, {2, fixSecret}}
	with := func(extra ...tlv) []tlv { return append(append([]tlv{}, base...), extra...) }

	// Rules shared by the token, cashhub1 and circlehub1 decoders.
	shared := []struct {
		name    string
		entries []tlv
		raw     []byte
	}{
		{"minimal", base, nil},
		{"fields in any order", []tlv{{2, fixSecret}, {1, fixURL}, {0, fixKey}}, nil},
		{"two relays", with(tlv{1, []byte("wss://r2.example")}), nil},
		{"blank relay beside a real one is kept", with(tlv{1, []byte(" ")}), nil},
		{"empty relay beside a real one is kept", with(tlv{1, []byte{}}), nil},
		{"unknown types are ignored", []tlv{{0, fixKey}, {4, []byte{1, 2, 3}}, {1, fixURL}, {200, []byte("future")}, {2, fixSecret}}, nil},
		{"missing pubkey", []tlv{{1, fixURL}, {2, fixSecret}}, nil},
		{"missing secret", []tlv{{0, fixKey}, {1, fixURL}}, nil},
		{"duplicate pubkey", []tlv{{0, fixKey}, {0, fixKey}, {1, fixURL}, {2, fixSecret}}, nil},
		{"duplicate secret", with(tlv{2, fixSecret}), nil},
		{"short pubkey", []tlv{{0, fixKey[:31]}, {1, fixURL}, {2, fixSecret}}, nil},
		{"long secret", []tlv{{0, fixKey}, {1, fixURL}, {2, append(append([]byte{}, fixSecret...), 0)}}, nil},
		{"no relay", []tlv{{0, fixKey}, {2, fixSecret}}, nil},
		{"only blank relays", []tlv{{0, fixKey}, {1, []byte(" ")}, {1, []byte("\t")}, {2, fixSecret}}, nil},
		// Blank means Go's unicode.IsSpace, not JavaScript's trim().
		{"relay of U+0085 only is blank", []tlv{{0, fixKey}, {1, []byte("\u0085")}, {2, fixSecret}}, nil},
		{"relay of U+3000 only is blank", []tlv{{0, fixKey}, {1, []byte("\u3000")}, {2, fixSecret}}, nil},
		{"relay of U+FEFF only is not blank", []tlv{{0, fixKey}, {1, []byte("\ufeff")}, {2, fixSecret}}, nil},
		{"truncated entry", []tlv{{0, fixKey}, {1, fixURL}}, []byte{2, 32, 1, 2, 3}},
		{"lone type byte", base, []byte{9}},
		{"empty payload", nil, nil},
	}
	for _, kind := range []string{kindToken} {
		for _, c := range shared {
			add(c.name, kind, bech32String(hrpFor(kind), c.entries, c.raw...))
		}
	}

	// Token only: any HRP, identity_required, provenance and hub group.
	for _, hrp := range []string{"satscash", "xyzcash", "a"} {
		add("hrp "+hrp, kindToken, bech32String(hrp, base))
	}
	add("identity_required 1", kindToken, bech32String("lokicash", with(tlv{3, []byte{1}})))
	add("identity_required 0", kindToken, bech32String("lokicash", with(tlv{3, []byte{0}})))
	add("identity_required two bytes", kindToken, bech32String("lokicash", with(tlv{3, []byte{0, 1}})))
	add("identity_required empty", kindToken, bech32String("lokicash", with(tlv{3, []byte{}})))
	add("identity_required value 2", kindToken, bech32String("lokicash", with(tlv{3, []byte{2}})))
	add("identity_required duplicate", kindToken, bech32String("lokicash", with(tlv{3, []byte{1}}, tlv{3, []byte{1}})))
	add("K-TOK-1 (the spec token)", kindToken, specToken)
	add("K-TOK-1 uppercase decodes as its lowercase form", kindToken, strings.ToUpper(specToken))
	add("K-TOK-1 mixed case is refused", kindToken, "S"+specToken[1:])
	add("provenance pair, scheme 1", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{8, []byte{1}})))
	add("provenance pair, scheme 2", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{8, []byte{2}})))
	add("provenance pair without TLV 8 has no valid provenance", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount})))
	add("provenance pair, TLV 8 = 0", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{8, []byte{0}})))
	add("provenance pair, unknown scheme 3", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{8, []byte{3}})))
	add("provenance pair, TLV 8 two bytes", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{8, []byte{0, 1}})))
	add("provenance pair, TLV 8 empty", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{8, []byte{}})))
	add("provenance pair, TLV 8 twice", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{8, []byte{1}}, tlv{8, []byte{1}})))
	add("TLV 8 without a signature", kindToken, bech32String("lokicash", with(tlv{8, []byte{1}})))
	add("provenance amount before signature", kindToken, bech32String("lokicash", with(tlv{8, []byte{1}}, tlv{6, fixAmount}, tlv{5, fixSig})))
	add("provenance max amount", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, repeat(0xff, 8)}, tlv{8, []byte{1}})))
	add("provenance zero amount", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, make([]byte, 8)}, tlv{8, []byte{1}})))
	for _, c := range []struct {
		name  string
		extra []tlv
	}{
		{"signature alone", []tlv{{5, fixSig}}},
		{"amount alone", []tlv{{6, fixAmount}}},
		{"short signature", []tlv{{5, fixSig[:64]}, {6, fixAmount}}},
		{"long signature", []tlv{{5, append(append([]byte{}, fixSig...), 1)}, {6, fixAmount}}},
		{"short amount", []tlv{{5, fixSig}, {6, fixAmount[:7]}}},
		{"duplicate signature", []tlv{{5, fixSig}, {5, fixSig}, {6, fixAmount}}},
		{"duplicate amount", []tlv{{5, fixSig}, {6, fixAmount}, {6, fixAmount}}},
	} {
		add("anomalous provenance is dropped: "+c.name, kindToken, bech32String("lokicash", with(append(c.extra, tlv{8, []byte{1}})...)))
	}
	add("hub group", kindToken, bech32String("lokicash", with(tlv{7, fixGroup})))
	add("hub group with provenance", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{7, fixGroup}, tlv{8, []byte{1}})))
	for _, c := range []struct {
		name  string
		extra []tlv
	}{
		{"too short", []tlv{{7, []byte{1}}}},
		{"three bytes beside provenance", []tlv{{5, fixSig}, {6, fixAmount}, {7, []byte{1, 2, 3}}, {8, []byte{1}}}},
		{"too long", []tlv{{7, repeat(1, 8)}}},
		{"empty", []tlv{{7, []byte{}}}},
		{"duplicated", []tlv{{7, fixGroup}, {7, fixGroup}}},
	} {
		add("anomalous hub group is dropped: "+c.name, kindToken, bech32String("lokicash", with(c.extra...)))
	}
	// A cashhub1 string read as a token: its label rides on type 3, which a
	// token reads as identity_required.
	add("cashhub label read as a token", kindToken, bech32String("cashhub", with(tlv{3, []byte("a")})))
	add("cashhub label byte 1 read as a token", kindToken, bech32String("cashhub", with(tlv{3, []byte{1}})))

	// bech32 framing, exercised through the token decoder.
	valid := bech32String("lokicash", base)
	add("framing: uppercase", kindToken, strings.ToUpper(valid))
	add("framing: bech32m checksum", kindToken, bech32mString("lokicash", base))
	add("framing: bad checksum", kindToken, flipLastChar(valid))
	add("framing: mixed case", kindToken, "L"+valid[1:])
	add("framing: character outside the charset", kindToken, replaceAt(valid, len("lokicash1")+3, 'b'))
	add("framing: character outside printable ASCII", kindToken, replaceAt(valid, 0, ' '))
	add("framing: no separator", kindToken, "lokicashqqqqqqqqqq")
	add("framing: empty hrp", kindToken, valid[len("lokicash"):])
	add("framing: shorter than 8", kindToken, "a1qqqqq")
	add("framing: data shorter than the checksum", kindToken, "lokicash1qqqqq")
	add("framing: hrp only, empty data", kindToken, mustEncodeWords("lokicash", nil))
	add("framing: hrp containing 1", kindToken, bech32String("loki1cash", base))
	add("framing: non-zero padding bits", kindToken, nonZeroPadding("lokicash", tlvBytes(with(tlv{1, []byte("x")}), nil)))
	add("framing: excess padding group", kindToken, excessPadding("lokicash", tlvBytes(with(tlv{1, []byte("x")}), nil)))
	add("framing: leading and trailing space", kindToken, " "+valid+" ")
	add("framing: empty string", kindToken, "")
	long := bech32String("lokicash", with(tlv{1, repeat('r', 255)}, tlv{1, repeat('s', 255)}, tlv{1, repeat('t', 255)}))
	add("framing: longer than bech32's 90-character limit", kindToken, long)

	f.Encode = buildTLVEncode()
	return f, nil
}

func flipLastChar(s string) string {
	last := s[len(s)-1]
	repl := byte('q')
	if last == 'q' {
		repl = 'p'
	}
	return s[:len(s)-1] + string(repl)
}

func replaceAt(s string, i int, c byte) string {
	b := []byte(s)
	b[i] = c
	return string(b)
}

func mustEncodeWords(hrp string, w []byte) string {
	s, err := bech32.Encode(hrp, w)
	if err != nil {
		panic(err)
	}
	return s
}

// nonZeroPadding sets a padding bit in the last 5-bit group, so the checksum
// is valid but the bit conversion is not.
func nonZeroPadding(hrp string, data []byte) string {
	if len(data)*8%5 == 0 {
		panic("data has no padding bits")
	}
	w := words(data)
	w[len(w)-1] |= 1
	return mustEncodeWords(hrp, w)
}

// excessPadding appends a whole extra zero group.
func excessPadding(hrp string, data []byte) string {
	return mustEncodeWords(hrp, append(words(data), 0))
}

func buildTLVEncode() []encodeCase {
	var out []encodeCase
	add := func(name, kind string, fields any) { out = append(out, encodeVector(name, kind, fields)) }

	key := hex.EncodeToString(fixKey)
	secret := hex.EncodeToString(fixSecret)
	relays := []string{string(fixURL)}
	amt := "21000"
	sig := hex.EncodeToString(fixSig)
	group := hex.EncodeToString(fixGroup)
	yes, no := true, false

	tok := func(mod func(*tokenJSON)) tokenJSON {
		t := tokenJSON{HRP: "lokicash", WalletPubkey: key, Secret: secret, Relays: relays, MintSignature: &sig, AttestedAmountMillis: &amt, Scheme: 1}
		if mod != nil {
			mod(&t)
		}
		return t
	}
	add("token minimal", kindToken, tok(nil))
	add("K-TOK-1 (the spec token)", kindToken, tokenToJSON(must(nipcash.Decode(specToken))))
	add("token satscash", kindToken, tok(func(t *tokenJSON) { t.HRP = "satscash" }))
	add("token uppercase hrp is lowercased", kindToken, tok(func(t *tokenJSON) { t.HRP = "LOKICASH" }))
	add("token uppercase hex", kindToken, tok(func(t *tokenJSON) { t.WalletPubkey = strings.ToUpper(key) }))
	add("token identity_required true", kindToken, tok(func(t *tokenJSON) { t.IdentityRequired = &yes }))
	add("token identity_required false", kindToken, tok(func(t *tokenJSON) { t.IdentityRequired = &no }))
	add("token every field", kindToken, tok(func(t *tokenJSON) {
		t.Relays = []string{"wss://r1.example", "wss://r2.example"}
		t.IdentityRequired = &yes
		t.MintSignature, t.AttestedAmountMillis, t.HubGroup, t.Scheme = &sig, &amt, &group, 1
	}))
	add("token every field, in reverse order of the struct, encodes in ascending type order", kindToken, tok(func(t *tokenJSON) {
		t.HubGroup, t.AttestedAmountMillis, t.MintSignature, t.Scheme = &group, &amt, &sig, 2
		t.IdentityRequired = &no
	}))
	add("token signature without a scheme", kindToken, tok(func(t *tokenJSON) { t.Scheme = 0 }))
	add("token unsigned", kindToken, tok(func(t *tokenJSON) { t.MintSignature, t.AttestedAmountMillis, t.Scheme = nil, nil, 0 }))
	add("token mixed-case hrp", kindToken, tok(func(t *tokenJSON) { t.HRP = "LokiCash" }))
	add("token non-ASCII relay hint", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{"wss://r\u00e9.example"} }))
	add("token relay hint with an inner space", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{"wss://r.example", "wss://a b"} }))
	add("token max amount", kindToken, tok(func(t *tokenJSON) {
		t.MintSignature, t.AttestedAmountMillis, t.Scheme = &sig, strPtr("18446744073709551615"), 1
	}))
	add("token blank relays are skipped", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{"", "wss://r.example", "  "} }))
	add("token 255-byte relay", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{strings.Repeat("r", 255)} }))
	add("token 256-byte relay", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{strings.Repeat("r", 256)} }))
	add("token no relays", kindToken, tok(func(t *tokenJSON) { t.Relays = nil }))
	add("token only blank relays", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{" ", ""} }))
	add("token signature without amount", kindToken, tok(func(t *tokenJSON) { t.AttestedAmountMillis = nil }))
	add("token amount without signature", kindToken, tok(func(t *tokenJSON) { t.MintSignature = nil }))
	add("token 64-byte signature", kindToken, tok(func(t *tokenJSON) {
		t.MintSignature, t.AttestedAmountMillis, t.Scheme = strPtr(sig[:128]), &amt, 1
	}))
	add("token 2-byte hub group", kindToken, tok(func(t *tokenJSON) { t.HubGroup = strPtr("0102") }))
	add("token short pubkey", kindToken, tok(func(t *tokenJSON) { t.WalletPubkey = key[:62] }))
	add("token non-hex secret", kindToken, tok(func(t *tokenJSON) { t.Secret = "zz" + secret[2:] }))

	return out
}
