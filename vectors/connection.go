package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/internal/credcodec"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
)

// ---- connection.json (NIP-CASH §Connection Signatures; cashhub1, circlehub1, cashorder1)

// connJSON is a signed connection string's fields. Label is null when TLV 3
// is absent; Signature is TLV 5 in hex, null when absent.
type connJSON struct {
	Pubkey      string   `json:"pubkey"`
	Relays      []string `json:"relays"`
	Secret      string   `json:"secret"`
	Label       *string  `json:"label"`
	HubIdentity string   `json:"hubIdentity"`
	Signature   *string  `json:"signature"`
	Chain       string   `json:"chain"`
}

// connDecoded is a decoded string and what Verify said of it ("" = verified).
type connDecoded struct {
	connJSON
	Verified    bool   `json:"verified"`
	VerifyError string `json:"verifyError,omitempty"`
}

func newConnJSON(pub string, relays []string, secret, label string, hasLabel bool, id string, sig []byte, chain string) connJSON {
	c := connJSON{Pubkey: pub, Relays: nonNil(relays), Secret: secret, HubIdentity: id, Chain: chain}
	if hasLabel {
		c.Label = strPtr(label)
	}
	if sig != nil {
		c.Signature = strPtr(hex.EncodeToString(sig))
	}
	return c
}

func decoded(c connJSON, verify error) connDecoded {
	return connDecoded{c, verify == nil, errString(verify)}
}

func cashHubJSON(c nipcash.CashHubConnection) connDecoded {
	return decoded(newConnJSON(c.Pubkey, c.Relays, c.Secret, c.Label, c.HasLabel, c.HubIdentity, c.Signature, c.Chain), c.Verify())
}

func circleHubJSON(c nipcw.CircleHubConnection) connDecoded {
	return decoded(newConnJSON(c.Pubkey, c.Relays, c.Secret, c.Label, c.HasLabel, c.HubIdentity, c.Signature, c.Chain), c.Verify())
}

func orderConnJSON(c nipCO.OrderConnection) connDecoded {
	return decoded(newConnJSON(c.Pubkey, c.Relays, c.Secret, c.Label, c.HasLabel, c.HubIdentity, c.Signature, c.Chain), c.Verify())
}

func (j connJSON) parts() (label string, has bool, sig []byte) {
	if j.Label != nil {
		label, has = *j.Label, true
	}
	if j.Signature != nil {
		sig, _ = hex.DecodeString(*j.Signature)
	}
	return
}

func (j connJSON) cashHub() nipcash.CashHubConnection {
	l, h, s := j.parts()
	return nipcash.CashHubConnection{Pubkey: j.Pubkey, Relays: j.Relays, Secret: j.Secret, Label: l, HasLabel: h, HubIdentity: j.HubIdentity, Signature: s, Chain: j.Chain}
}

func (j connJSON) circleHub() nipcw.CircleHubConnection {
	l, h, s := j.parts()
	return nipcw.CircleHubConnection{Pubkey: j.Pubkey, Relays: j.Relays, Secret: j.Secret, Label: l, HasLabel: h, HubIdentity: j.HubIdentity, Signature: s, Chain: j.Chain}
}

func (j connJSON) order() nipCO.OrderConnection {
	l, h, s := j.parts()
	return nipCO.OrderConnection{Pubkey: j.Pubkey, Relays: j.Relays, Secret: j.Secret, Label: l, HasLabel: h, HubIdentity: j.HubIdentity, Signature: s, Chain: j.Chain}
}

func (j connJSON) fields(kind string) nipcash.ConnFields {
	switch kind {
	case kindCashHub:
		return j.cashHub().Fields()
	case kindCircleHub:
		return j.circleHub().Fields()
	}
	return j.order().Fields()
}

type connectionFile struct {
	header
	KATs        []connKAT        `json:"kats"`
	Decode      []decodeCase     `json:"decode"`
	Encode      []encodeCase     `json:"encode"`
	Verify      []connVerifyCase `json:"verify"`
	ChainName   []chainNameCase  `json:"chainName"`
	OnlineCheck []onlineCase     `json:"onlineCheck"`
}

// connKAT: a connection string built from Inputs (TLV 5 left out) and
// signed with the Hub identity's private key 1 by RFC 6979.
type connKAT struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Inputs    connJSON `json:"inputs"`
	RelayHash string   `json:"relayHash"`
	LabelHash string   `json:"labelHash"`
	Text      string   `json:"text"`
	Prefix    string   `json:"prefix"`
	Digest    string   `json:"digest"`
	Signature string   `json:"signature"`
	Header    int      `json:"header"`
	String    string   `json:"string"`
	Length    int      `json:"length"`
}

type connVerifyCase struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Input  string `json:"input"`
	Error  string `json:"error,omitempty"` // decoder refusal
	Verify string `json:"verify"`          // "" = verified
}

type chainNameCase struct {
	Value string `json:"value"`
	Valid bool   `json:"valid"`
}

type onlineCase struct {
	ID           string `json:"id"`
	HubIdentity  string `json:"hubIdentity"`
	Chain        string `json:"chain"`
	InfoIdentity string `json:"infoIdentity"`
	InfoChain    string `json:"infoChain"`
	Error        string `json:"error,omitempty"`
}

const (
	connPubkey   = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	connIdentity = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	connRelay    = "wss://relay.example.com"
	connKey1     = "0000000000000000000000000000000000000000000000000000000000000001"
	connKey2     = "0000000000000000000000000000000000000000000000000000000000000002"
)

// connInputs are the spec inputs: K-CH-1/K-CWH-1 use secret 0x20..0x3f,
// K-CO-1 0x40..0x5f.
func connInputs(kind, label string, hasLabel bool) connJSON {
	from := byte(0x20)
	if kind == kindCashOrder {
		from = 0x40
	}
	return newConnJSON(connPubkey, []string{connRelay}, hex.EncodeToString(seq(from)), label, hasLabel, connIdentity, nil, "bitcoin")
}

// signConn signs j as kind with key and returns it with TLV 5 in place.
func signConn(kind string, j connJSON, key string) (connJSON, error) {
	sign, err := nipcash.LocalChainSigner(key, j.Chain)
	if err != nil {
		return j, err
	}
	text, err := nipcash.ConnSignedText(j.fields(kind))
	if err != nil {
		return j, err
	}
	sig, err := sign(text)
	if err != nil {
		return j, err
	}
	j.Signature = strPtr(hex.EncodeToString(sig))
	return j, nil
}

// connEntries is j as TLV entries 0-6 in order.
func connEntries(j connJSON) []tlv {
	l, h, s := j.parts()
	pub, _ := hex.DecodeString(j.Pubkey)
	sec, _ := hex.DecodeString(j.Secret)
	id, _ := hex.DecodeString(j.HubIdentity)
	es := []tlv{{0, pub}}
	for _, r := range j.Relays {
		es = append(es, tlv{1, []byte(r)})
	}
	es = append(es, tlv{2, sec})
	if h {
		es = append(es, tlv{3, []byte(l)})
	}
	return append(es, tlv{4, id}, tlv{5, s}, tlv{6, []byte(j.Chain)})
}

func connString(hrp string, es []tlv) string {
	var buf bytes.Buffer
	for _, e := range es {
		credcodec.WriteTLV(&buf, e.typ, e.value)
	}
	s, err := credcodec.EncodeBech32(hrp, buf.Bytes())
	if err != nil {
		panic(err)
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

func replaced(es []tlv, typ byte, v []byte) []tlv {
	out := append([]tlv(nil), es...)
	for i := range out {
		if out[i].typ == typ {
			out[i].value = v
		}
	}
	return out
}

func repeated(es []tlv, typ byte) []tlv {
	out := append([]tlv(nil), es...)
	for _, e := range es {
		if e.typ == typ {
			return append(out, e)
		}
	}
	return out
}

func buildConnection() (any, error) {
	f := connectionFile{header: newHeader(
		"Signed connection strings (cashhub1, circlehub1, cashorder1): the signed text <label>:<chain>:<TLV 0>:<TLV 4>:<relay_hash>:<label_hash>, its digest under the chain's signed-message prefix, TLV 5, the exact strings; decoder refusals (missing, repeated or malformed TLV 0/2/4/5/6), unverified cases, a type above 6 outside the signature, uppercase strings decode and mixed case is refused; chain names and the online check against get_info.",
		"nipcash/connsig.go, cashhub_connection.go, online.go, nipcw/circlehub_connection.go, nipCO/connection.go, internal/credcodec; nipcash/cashhub_connection_test.go, nipcw/circlehub_connection_test.go, nipCO/connection_test.go (K-CH-1..2, K-CWH-1..2, K-CO-1..2, K-CSIG-1, K-CHAIN-1, K-ONL-1)",
	)}
	type spec struct {
		id, kind, label string
		has             bool
	}
	specs := []spec{
		{"K-CH-1", kindCashHub, "Alice's Cash Hub", true},
		{"K-CH-2", kindCashHub, "", false},
		{"K-CWH-1", kindCircleHub, "Ada's Family Circle", true},
		{"K-CO-1", kindCashOrder, "Alice's cash counter", true},
	}
	signedOf := map[string]connJSON{}
	for _, sp := range specs {
		in := connInputs(sp.kind, sp.label, sp.has)
		signed, err := signConn(sp.kind, in, connKey1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sp.id, err)
		}
		signedOf[sp.id] = signed
		text, err := nipcash.ConnSignedText(signed.fields(sp.kind))
		if err != nil {
			return nil, err
		}
		prefix, _ := nipcash.ChainSignedMessagePrefix("bitcoin")
		rh, err := nipcash.RelayHash(in.Relays, in.Secret)
		if err != nil {
			return nil, err
		}
		lh := ""
		if sp.has {
			sum := sha256.Sum256([]byte(sp.label))
			lh = hex.EncodeToString(sum[:])
		}
		s, err := encodeAs(sp.kind, signed)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sp.id, err)
		}
		_, _, sig := signed.parts()
		f.KATs = append(f.KATs, connKAT{sp.id, sp.kind, in, rh, lh, text, prefix,
			hex.EncodeToString(doubleSHA256([]byte(prefix + text))), *signed.Signature, int(sig[0]), s, len(s)})
	}

	add := func(name, kind, input string) { f.Decode = append(f.Decode, decodeVector(name, kind, input)) }
	for _, k := range []struct{ id, kind string }{{"K-CH-1", kindCashHub}, {"K-CWH-1", kindCircleHub}, {"K-CO-1", kindCashOrder}} {
		es := connEntries(signedOf[k.id])
		hrp := hrpFor(k.kind)
		spec := connString(hrp, es)
		add(k.id, k.kind, spec)
		add(k.id+" uppercase", k.kind, strings.ToUpper(spec))
		mixed := []byte(spec)
		mixed[12] = byte(strings.ToUpper(string(mixed[12]))[0])
		add(k.id+" mixed case", k.kind, string(mixed))
		id, _ := hex.DecodeString(connIdentity)
		_, _, sig := signedOf[k.id].parts()
		for _, c := range []struct {
			name string
			es   []tlv
		}{
			{"no TLV 0", without(es, 0)},
			{"no TLV 1", without(es, 1)},
			{"no TLV 2", without(es, 2)},
			{"no TLV 4", without(es, 4)},
			{"no TLV 5", without(es, 5)},
			{"no TLV 6", without(es, 6)},
			{"31-byte TLV 0", replaced(es, 0, repeat(0xf9, 31))},
			{"31-byte TLV 4", replaced(es, 4, id[:31])},
			{"33-byte TLV 4", replaced(es, 4, append([]byte{0x02}, id...))},
			{"64-byte TLV 5", replaced(es, 5, sig[:64])},
			{"empty TLV 6", replaced(es, 6, nil)},
			{"TLV 6 Bitcoin", replaced(es, 6, []byte("Bitcoin"))},
			{"TLV 6 bit_coin", replaced(es, 6, []byte("bit_coin"))},
			{"33-byte TLV 6", replaced(es, 6, repeat('a', 33))},
			{"TLV 6 bitcoin-x decodes, unverified", replaced(es, 6, []byte("bitcoin-x"))},
			{"TLV 3 twice", repeated(es, 3)},
			{"TLV 4 twice", repeated(es, 4)},
			{"TLV 5 twice", repeated(es, 5)},
			{"TLV 6 twice", repeated(es, 6)},
			{"extra TLV 9 is outside the signature", append(append([]tlv(nil), es...), tlv{9, []byte("future")})},
			{"blank hint beside the real one", append(append([]tlv(nil), es...), tlv{1, []byte(" ")})},
		} {
			add(k.id+" "+c.name, k.kind, connString(hrp, c.es))
		}
		other := map[string]string{kindCashHub: nipcw.CircleHubConnectionHRP, kindCircleHub: nipCO.OrderConnectionHRP, kindCashOrder: nipcash.CashHubConnectionHRP}[k.kind]
		add(k.id+" under another connection HRP", k.kind, connString(other, es))
		add(k.id+" as a token HRP", k.kind, connString("satscash", es))
	}

	enc := func(name, kind string, j connJSON) { f.Encode = append(f.Encode, encodeVector(name, kind, j)) }
	for _, k := range []struct{ id, kind string }{{"K-CH-1", kindCashHub}, {"K-CH-2", kindCashHub}, {"K-CWH-1", kindCircleHub}, {"K-CO-1", kindCashOrder}} {
		s := signedOf[k.id]
		enc(k.id, k.kind, s)
		mod := func(m func(*connJSON)) connJSON {
			c := s
			c.Relays = append([]string(nil), s.Relays...)
			m(&c)
			return c
		}
		enc(k.id+" unsigned", k.kind, mod(func(c *connJSON) { c.Signature = nil }))
		enc(k.id+" empty label is never emitted", k.kind, mod(func(c *connJSON) { c.Label = strPtr("") }))
		enc(k.id+" no relay", k.kind, mod(func(c *connJSON) { c.Relays = nil }))
		enc(k.id+" only a blank relay", k.kind, mod(func(c *connJSON) { c.Relays = []string{" "} }))
		enc(k.id+" non-ASCII relay", k.kind, mod(func(c *connJSON) { c.Relays = []string{"wss://relé.example"} }))
		enc(k.id+" chain Bitcoin", k.kind, mod(func(c *connJSON) { c.Chain = "Bitcoin" }))
		enc(k.id+" short identity", k.kind, mod(func(c *connJSON) { c.HubIdentity = connIdentity[:62] }))
	}

	ver := func(id, name, kind, input string) {
		c := connVerifyCase{ID: id, Name: name, Kind: kind, Input: input}
		d, err := decodeAs(kind, input)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Verify = d.(connDecoded).VerifyError
		}
		f.Verify = append(f.Verify, c)
	}
	co := connEntries(signedOf["K-CO-1"])
	ver("K-CSIG-1", "K-CO-1 re-encoded with TLV 6 bitcoin-x, signature kept", kindCashOrder, connString(nipCO.OrderConnectionHRP, replaced(co, 6, []byte("bitcoin-x"))))
	ver("K-CSIG-1", "K-CO-1 with TLV 3 Bob's cash counter, signature kept", kindCashOrder, connString(nipCO.OrderConnectionHRP, replaced(co, 3, []byte("Bob's cash counter"))))
	forged, err := signConn(kindCircleHub, connInputs(kindCircleHub, "Ada's Family Circle", true), connKey2)
	if err != nil {
		return nil, err
	}
	ver("K-CSIG-1", "K-CWH-1 signed by private key 2 with TLV 4 still key 1's", kindCircleHub, connString(nipcw.CircleHubConnectionHRP, connEntries(forged)))
	ver("K-CSIG-1", "K-CH-1 with an extra TLV 9", kindCashHub, connString(nipcash.CashHubConnectionHRP, append(connEntries(signedOf["K-CH-1"]), tlv{9, []byte("anything")})))
	ver("", "K-CH-1 with the relay changed, signature kept", kindCashHub, connString(nipcash.CashHubConnectionHRP, replaced(connEntries(signedOf["K-CH-1"]), 1, []byte("wss://other.example"))))
	ver("", "K-CH-1 with the secret changed, signature kept", kindCashHub, connString(nipcash.CashHubConnectionHRP, replaced(connEntries(signedOf["K-CH-1"]), 2, repeat(0x44, 32))))
	ver("", "K-CH-1 signature under the circlehub1 HRP", kindCircleHub, connString(nipcw.CircleHubConnectionHRP, connEntries(signedOf["K-CH-1"])))

	for _, v := range []string{"bitcoin", strings.Repeat("a", 32), "bitcoin-x", "flokicoin", "", "Bitcoin", "bit coin", "bit_coin", strings.Repeat("a", 33), "-bitcoin", "bitcoin-"} {
		f.ChainName = append(f.ChainName, chainNameCase{v, nipcash.ValidChainName(v)})
	}

	o := nipcash.OnlineCheck{HubIdentity: connIdentity, Chain: "bitcoin"}
	for _, c := range [][2]string{
		{connIdentity, "bitcoin"}, {"02" + connIdentity, "bitcoin"}, {"03" + connIdentity, "bitcoin"}, {strings.ToUpper(connIdentity), "bitcoin"},
		{"04" + connIdentity, "bitcoin"}, {connIdentity[:63] + "9", "bitcoin"},
		{connIdentity, "Bitcoin"}, {connIdentity, ""},
	} {
		f.OnlineCheck = append(f.OnlineCheck, onlineCase{"K-ONL-1", o.HubIdentity, o.Chain, c[0], c[1], errString(o.Check(c[0], c[1]))})
	}
	return f, nil
}
