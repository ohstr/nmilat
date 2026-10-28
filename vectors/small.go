package vectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

// ---- hub-group.json

type hubGroupFile struct {
	header
	HubGroupFor  []hubGroupForCase  `json:"hubGroupFor"`
	SameHubGroup []sameHubGroupCase `json:"sameHubGroup"`
}

// hubGroupForCase: HubGroupFor(Hub) == Group. NotRawBytes, when present, is
// what hashing the decoded 32 bytes would give instead; a port that
// produces it has fallen into the trap design §2.1 describes.
type hubGroupForCase struct {
	Hub         string `json:"hub"`
	Group       string `json:"group"`
	NotRawBytes string `json:"notRawBytes,omitempty"`
}

// sameHubGroupCase: SameHubGroup on two tokens whose hub groups are A and B
// (hex, null = absent).
type sameHubGroupCase struct {
	Name string  `json:"name"`
	A    *string `json:"a"`
	B    *string `json:"b"`
	Same bool    `json:"same"`
}

func buildHubGroup() (any, error) {
	f := hubGroupFile{header: newHeader(
		"Hub-group fingerprint: the first 4 bytes of sha256 over the hub pubkey's hex TEXT, and the grouping rule.",
		"nipcash/token.go HubGroupFor, SameHubGroup; nipcash/hub_group_test.go",
	)}
	pubkeys := []string{
		k1Pub,      // K-HG-1
		connPubkey, // K-HG-1, the spec token's Hub
		strings.Repeat("cd", 32),
		"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
		strings.ToUpper("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"),
	}
	for _, pk := range pubkeys {
		raw, _ := hex.DecodeString(pk)
		sum := sha256.Sum256(raw)
		f.HubGroupFor = append(f.HubGroupFor, hubGroupForCase{
			Hub:         pk,
			Group:       hex.EncodeToString(nipcash.HubGroupFor(pk)),
			NotRawBytes: hex.EncodeToString(sum[:nipcash.HubGroupLen]),
		})
	}
	for _, s := range []string{"hub-pubkey-aaa", "hub-a", "hub-b", ""} {
		f.HubGroupFor = append(f.HubGroupFor, hubGroupForCase{Hub: s, Group: hex.EncodeToString(nipcash.HubGroupFor(s))})
	}

	ga := hex.EncodeToString(nipcash.HubGroupFor("hub-a"))
	gb := hex.EncodeToString(nipcash.HubGroupFor("hub-b"))
	for _, c := range []struct {
		name string
		a, b *string
	}{
		{"same group", &ga, &ga},
		{"different groups", &ga, &gb},
		{"both absent is not a wildcard", nil, nil},
		{"one absent", &ga, nil},
		{"other absent", nil, &ga},
		{"wrong length on both", strPtr("0102"), strPtr("0102")},
		{"empty on both", strPtr(""), strPtr("")},
	} {
		tok := func(g *string) nipcash.Token {
			if g == nil {
				return nipcash.Token{}
			}
			b, _ := hex.DecodeString(*g)
			if b == nil {
				b = []byte{}
			}
			return nipcash.Token{HubGroup: b}
		}
		f.SameHubGroup = append(f.SameHubGroup, sameHubGroupCase{c.name, c.a, c.b, nipcash.SameHubGroup(tok(c.a), tok(c.b))})
	}
	return f, nil
}

// ---- cash-string.json

type cashStringFile struct {
	header
	Split []splitCase `json:"split"`
}

type splitCase struct {
	Input      string `json:"input"`
	Token      string `json:"token"`
	CashSecret string `json:"cashSecret"`
}

func buildCashString() (any, error) {
	f := cashStringFile{header: newHeader(
		"<token>#<cash_secret>: split on the first '#'.",
		"nipcash/cash_string.go SplitCashSliceString; nipcash/cash_string_test.go",
	)}
	for _, in := range []string{
		"lokicash1abc",
		"lokicash1abc#deadbeef",
		"lokicash1abc#dead#beef",
		"",
		"#",
		"#deadbeef",
		"lokicash1abc#",
		"lokicash1abc#" + strings.Repeat("ab", 32),
	} {
		tok, secret := nipcash.SplitCashSliceString(in)
		f.Split = append(f.Split, splitCase{in, tok, secret})
	}
	return f, nil
}

// ---- connection-key.json

type connectionKeyFile struct {
	header
	KATs       []ckKATCase      `json:"kats"`
	Canonical  []userIDCase     `json:"canonicalUserId"`
	Legacy     []legacyCKCase   `json:"legacy"`
	FromSecret []fromSecretCase `json:"fromSecret"`
	IDNACorpus []userIDCase     `json:"idna_corpus"`
	// Attestations: nipcash.ConnectionKeyFromAttestation of a parsed 35522,
	// refused unless d is the ConnectionKey of its platform and evidence
	// user id and, on a platform with a canonical form, that user id is
	// canonical.
	Attestations []attestationKeyCase `json:"attestations"`
}

type attestationKeyCase struct {
	Name  string      `json:"name"`
	Event nip01.Event `json:"event"`
	Key   string      `json:"key,omitempty"`
	Error string      `json:"error,omitempty"`
}

// ckKATCase: K-CK-*: the connection key of Input on Platform, typed (through
// CanonicalUserID, NewConnectionKey) or attested (ConnectionKeyFromAttested,
// the user id exactly as the IA saw it). Canonical is the typed form's
// canonical user id.
type ckKATCase struct {
	ID        string `json:"id"`
	Platform  string `json:"platform"`
	Input     string `json:"input"`
	Mode      string `json:"mode"`
	Canonical string `json:"canonical,omitempty"`
	Key       string `json:"key,omitempty"`
	Error     string `json:"error,omitempty"`
}

// userIDCase: CanonicalUserID(Platform, Input) is Output or refused.
type userIDCase struct {
	ID       string `json:"id,omitempty"`
	Platform string `json:"platform,omitempty"`
	Input    string `json:"input"`
	Output   string `json:"output,omitempty"`
	Error    string `json:"error,omitempty"`
}

// legacyCKCase: a typed input an earlier revision hashed as
// sha256(platform ":" input), now refused by NewConnectionKey.
type legacyCKCase struct {
	Platform   string `json:"platform"`
	ExternalID string `json:"externalId"`
	Error      string `json:"error"`
}

// fromSecretCase: the NIP-CW member connection key pair derived from a
// secret. Pubkey is the x-only (BIP-340 style) hex.
type fromSecretCase struct {
	Secret string `json:"secret"`
	Pubkey string `json:"pubkey,omitempty"`
	Error  string `json:"error,omitempty"`
}

func buildConnectionKey() (any, error) {
	f := connectionKeyFile{header: newHeader(
		"NIP-IC connection keys: hex(sha256(platform \":\" canonical user id)) for typed input on a platform with a canonical form (x, discord, email, dns, IDNA A-labels by UTS #46 non-transitional with STD3 rules), or the user id an IA attested; legacy typed inputs now refused; a generated IDNA corpus; and NIP-CW member connection key pairs.",
		"nipIC/canonical.go, nipIC/nipIC.go NewConnectionKey, ConnectionKeyFromAttested, nipcw/connection_key.go ConnectionKeyFromSecret; nipIC/canonical_test.go (K-CK-1..9, K-IDNA-1..6), nipcash/kat_test.go",
	)}
	kat := func(id, platform, input, mode string) {
		c := ckKATCase{ID: id, Platform: platform, Input: input, Mode: mode}
		var k nipIC.ConnectionKey
		var err error
		if mode == "typed" {
			c.Canonical, _ = nipIC.CanonicalUserID(nipIC.WebIdentity(platform), input)
			k, err = nipIC.NewConnectionKey(nipIC.WebIdentity(platform), input)
		} else {
			k, err = nipIC.ConnectionKeyFromAttested(nipIC.WebIdentity(platform), input)
		}
		c.Key, c.Error = string(k), errString(err)
		f.KATs = append(f.KATs, c)
	}
	kat("K-CK-1", "discord", "80351110224678912", "typed")
	kat("K-CK-1 (neg)", "discord", "080351110224678912", "typed")
	kat("K-CK-1 (neg: the hash never produced)", "discord", "080351110224678912", "attested")
	// The hash a client must never produce: key is the raw hash for
	// reference, and error is ConnectionKeyFromAttested's refusal of the
	// non-canonical user id.
	f.KATs[len(f.KATs)-1].Key = sha256Hex("discord:080351110224678912")
	kat("K-CK-2", "x", "12345", "typed")
	kat("K-CK-3", "x", "12", "typed")
	kat("K-CK-4", "email", "  Alice@Example.COM ", "typed")
	kat("K-CK-5", "email", "alice@bücher.example", "typed")
	kat("K-CK-6", "email", `"a@b"@Bücher.example`, "typed")
	kat("K-CK-7", "dns", "bücher.example", "typed")
	kat("K-CK-7", "dns", "BüCHER.example", "typed")
	kat("K-CK-7", "dns", "XN--BCHER-KVA.EXAMPLE", "typed")
	kat("K-CK-8", "github", "Alice", "attested")
	kat("K-CK-8 (neg)", "github", "alice", "attested")
	kat("K-CK-9", "github", "12345", "attested")
	kat("K-CK-9", "dns", "example.com", "typed")
	kat("", "github", "12345", "typed")

	canon := func(id, platform, input string) userIDCase {
		out, err := nipIC.CanonicalUserID(nipIC.WebIdentity(platform), input)
		return userIDCase{ID: id, Platform: platform, Input: input, Output: out, Error: errString(err)}
	}
	for i, in := range []string{"bücher.example", "BüCHER.example", "XN--BCHER-KVA.EXAMPLE", "BÜCHER.example", "faß.de", "ab--c.example"} {
		f.Canonical = append(f.Canonical, canon(fmt.Sprintf("K-IDNA-%d", i+1), "dns", in))
	}
	for _, c := range [][2]string{
		{"discord", "0"}, {"discord", "+5"}, {"discord", "18446744073709551615"}, {"discord", "18446744073709551616"}, {"discord", " 12345"}, {"discord", "@alice"},
		{"x", "alice"}, {"x", "@12345"},
		{"email", "alice@BÜCHER.example"}, {"email", "alice@faß.de"}, {"email", "jürgen@x.example"}, {"email", "Ünal@x.example"}, {"email", "alice"}, {"email", "alice@example.com."},
		{"dns", "ｂücher.example"}, {"dns", "bücher。example"}, {"dns", "ς.example"}, {"dns", "a\u200cb.example"}, {"dns", "-a.example"}, {"dns", "a_b.example"},
		{"dns", "a..example"}, {"dns", strings.Repeat("a", 64) + ".example"}, {"dns", "\u05d0a.example"}, {"dns", "example.com."}, {"dns", "xn--fa-hia.de"},
		{"github", "12345"}, {"telegram", "12345"},
	} {
		f.Canonical = append(f.Canonical, canon("", c[0], c[1]))
	}
	for _, c := range [][2]string{
		{"github", "12345"},
		{"x", "alice"},
		{"telegram", ""},
		{"", "12345"},
		{"github", "a:b"},
		{"discord", "Ünïcødé"},
	} {
		_, err := nipIC.NewConnectionKey(nipIC.WebIdentity(c[0]), c[1])
		if err == nil {
			return nil, fmt.Errorf("legacy input %q %q is accepted", c[0], c[1])
		}
		f.Legacy = append(f.Legacy, legacyCKCase{c[0], c[1], err.Error()})
	}
	f.IDNACorpus = idnaCorpus(5000)
	// Out-of-range secrets (zero, >= n) are left out on purpose: nmilat
	// reduces them mod n instead of refusing them.
	for _, s := range []string{
		strings.Repeat("11", 32),
		strings.Repeat("00", 31) + "01",
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", // n-1
		strings.ToUpper(strings.Repeat("ab", 32)),
		strings.Repeat("11", 31),
		strings.Repeat("11", 33),
		"zz" + strings.Repeat("11", 31),
		"",
	} {
		k, err := nipcw.ConnectionKeyFromSecret(s)
		f.FromSecret = append(f.FromSecret, fromSecretCase{Secret: s, Pubkey: k.Pubkey(), Error: errString(err)})
	}

	// Attestations by IA key 0x11×32 for user key 0x22×32, created at
	// 1720000000, with no expiry; a tampered one is re-signed by the IA.
	iaPriv, userPub := strings.Repeat("11", 32), must(utils.GetPublicKey(strings.Repeat("22", 32)))
	attest := func(platform nipIC.WebIdentity, userID string) *nip01.Event {
		ev := must(nipIC.NewAttestation(nipIC.AttestationParams{PrivateKey: iaPriv, UserPubkey: userPub, Platform: platform,
			Evidence: nipIC.Evidence{Version: 1, Platform: platform, UserID: userID, VerifiedAt: 1720000000}, AuthType: "oauth", NoExpiry: true}))
		ev.CreatedAt = 1720000000
		if err := ev.Sign(iaPriv); err != nil {
			panic(err)
		}
		return ev
	}
	retag := func(ev *nip01.Event, edit func(*nip01.Event)) *nip01.Event {
		c := ev.Copy()
		edit(c)
		if err := c.Sign(iaPriv); err != nil {
			panic(err)
		}
		return c
	}
	setD := func(d string) func(*nip01.Event) {
		return func(e *nip01.Event) {
			for _, t := range e.Tags {
				if len(t) >= 2 && t[0] == "d" {
					t[1] = d
				}
			}
		}
	}
	setUserID := func(id string) func(*nip01.Event) {
		return func(e *nip01.Event) {
			for _, t := range e.Tags {
				if len(t) >= 2 && t[0] == nipIC.TagEvidence {
					var ev map[string]any
					_ = json.Unmarshal([]byte(t[1]), &ev)
					ev["user_id"] = id
					b, _ := json.Marshal(ev)
					t[1] = string(b)
				}
			}
		}
	}
	addAtt := func(name string, ev *nip01.Event) {
		c := attestationKeyCase{Name: name, Event: *ev}
		att, err := nipIC.ParseAttestation(ev)
		if err == nil {
			var id nipcash.Target
			id, err = nipcash.ConnectionKeyFromAttestation(att)
			if err == nil {
				c.Key = string(att.ConnectionKey)
				_ = id
			}
		}
		c.Error = errString(err)
		f.Attestations = append(f.Attestations, c)
	}
	gh := attest("github", "Alice")
	dc := attest("discord", "80351110224678912")
	addAtt("github, d = sha256(github:Alice)", gh)
	addAtt("discord, canonical user id", dc)
	addAtt("d is not sha256(platform:user id)", retag(gh, setD(strings.Repeat("ab", 32))))
	nonCanonical := retag(dc, setUserID("080351110224678912"))
	nonCanonical = retag(nonCanonical, setD(string(nipIC.ConnectionKey(sha256Hex("discord:080351110224678912")))))
	addAtt("discord, a non-canonical user id (its own hash as d)", nonCanonical)
	return f, nil
}

// idnaCorpus is n generated domains and what CanonicalUserID("dns", ·)
// makes of each: an A-label form or a refusal. The generator is a fixed
// PCG stream, so the corpus is the same on every run.
func idnaCorpus(n int) []userIDCase {
	r := mrand.New(mrand.NewPCG(0x6e6d696c6174, 0x69646e61))
	alphabets := [][]rune{
		[]rune("abcdefghijklmnopqrstuvwxyz"),
		[]rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		[]rune("0123456789-"),
		[]rune("äöüßéèêñçåøæœ"),
		[]rune("ÄÖÜÉÑÇ"),
		[]rune("абвгдежзиклмн"),
		[]rune("αβγδεζηθικλμνς"),
		[]rune("日本語中文한국"),
		[]rune("\u200c\u200d\u00ad\u0301_ .。．＠ａｂ"),
		[]rune("אבגדابت"),
	}
	weights := []int{40, 6, 10, 12, 4, 6, 4, 4, 3, 2}
	pick := func() []rune {
		w := r.IntN(91)
		for i, x := range weights {
			if w < x {
				return alphabets[i]
			}
			w -= x
		}
		return alphabets[0]
	}
	tlds := []string{"example", "com", "de", "xn--p1ai", "org", "テスト", "Example", "co.uk"}
	out := make([]userIDCase, 0, n)
	for len(out) < n {
		labels := 1 + r.IntN(3)
		var sb strings.Builder
		for l := 0; l < labels; l++ {
			size := 1 + r.IntN(14)
			if r.IntN(50) == 0 {
				size = 60 + r.IntN(8)
			}
			if r.IntN(25) == 0 {
				sb.WriteString("xn--")
			}
			for k := 0; k < size; k++ {
				a := pick()
				sb.WriteRune(a[r.IntN(len(a))])
			}
			sb.WriteByte('.')
		}
		sb.WriteString(tlds[r.IntN(len(tlds))])
		in := sb.String()
		got, err := nipIC.CanonicalUserID("dns", in)
		out = append(out, userIDCase{Input: in, Output: got, Error: errString(err)})
	}
	return out
}
