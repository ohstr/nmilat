package nipCZ

import (
	"strconv"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
)

// fx is a minter, a sender, a recipient and a target note by the recipient.
type fx struct {
	minterPriv, minterX string
	senderPriv, sender  string
	recipPriv, recip    string
	note, article       *nip01.Event
}

func newFx(t *testing.T) *fx {
	t.Helper()
	f := &fx{}
	f.minterPriv, f.minterX = cashtest.Keypair(t)
	f.senderPriv, f.sender = cashtest.Keypair(t)
	f.recipPriv, f.recip = cashtest.Keypair(t)
	var err error
	f.note, err = nip01.NewSignedEvent(1, "a note", f.recipPriv)
	if err != nil {
		t.Fatal(err)
	}
	f.article, err = nip01.NewSignedEvent(30023, "an article", f.recipPriv, []string{"d", "my:slug"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func hexKey(t *testing.T) string {
	t.Helper()
	_, x := cashtest.Keypair(t)
	return x
}

// tokenOpts shapes a signed token.
type tokenOpts struct {
	hrp     string
	scheme  nipcash.SignatureScheme
	amount  uint64
	z       *nipcash.ZapContext
	relays  []string
	idReq   *bool
	signer  string // minter private key; the fixture's by default
	minterX string
}

func (f *fx) token(t *testing.T, o tokenOpts) (nipcash.Token, string) {
	t.Helper()
	if o.hrp == "" {
		o.hrp = "satscash"
	}
	if o.amount == 0 {
		o.amount = 21000
	}
	if o.relays == nil {
		o.relays = []string{"wss://hub.example"}
	}
	if o.signer == "" {
		o.signer, o.minterX = f.minterPriv, f.minterX
	}
	amt := o.amount
	tok := nipcash.Token{HRP: o.hrp, WalletPubkey: hexKey(t), Secret: hexKey(t), RelayURLs: o.relays,
		IdentityRequired: o.idReq, AttestedAmountMillis: &amt}
	// An unknown HRP is signed under the satscash prefix so the token encodes.
	signHRP := tok.HRP
	if _, ok := nipcash.SignedMessagePrefix(o.hrp); !ok {
		tok.HRP = "satscash"
	}
	signer, err := nipcash.LocalMintSigner(o.signer, tok.HRP)
	if err != nil {
		t.Fatal(err)
	}
	tok, err = nipcash.SignToken(tok, o.scheme, o.z, o.minterX, signer)
	if err != nil {
		t.Fatal(err)
	}
	tok.HRP = signHRP
	s, err := nipcash.Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := nipcash.Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	return dec, s
}

// zapOpts shapes a 9522 built by hand (not through NewCashZap), so tests can
// break it.
type zapOpts struct {
	target     *nip01.Event // nil: no e/a
	useA       bool         // tag the target by its a coordinate (and e)
	scheme     nipcash.SignatureScheme
	amount     uint64
	issuedAt   uint64
	expiresAt  uint64
	signer     string // 9522 signer; the sender by default
	recipient  string // p; the fixture recipient by default
	ctxSender  string // the sender the token's zap signature names; the signer by default
	ctxTarget  string // the target the zap signature names; the tagged one by default
	ctxRecip   string
	relays     []string
	idReq      *bool
	minterPriv string
	minterX    string
	mutate     func(tags [][]string) [][]string
}

func (f *fx) zap(t *testing.T, o zapOpts) (*nip01.Event, nipcash.Token) {
	t.Helper()
	if o.scheme == 0 {
		o.scheme = nipcash.SchemeZapV1
	}
	if o.amount == 0 {
		o.amount = 21000
	}
	if o.issuedAt == 0 {
		o.issuedAt = f.note.CreatedAt + 60
		if f.article.CreatedAt+60 > o.issuedAt {
			o.issuedAt = f.article.CreatedAt + 60
		}
	}
	if o.signer == "" {
		o.signer = f.senderPriv
	}
	signerPub := pubOf(t, o.signer)
	if o.recipient == "" {
		o.recipient = f.recip
	}
	if o.ctxSender == "" {
		o.ctxSender = signerPub
	}
	if o.ctxRecip == "" {
		o.ctxRecip = o.recipient
	}
	var e, a string
	if o.target != nil {
		e = o.target.ID
		if o.useA {
			a, _ = ZapTargetFor(o.target)
		}
	}
	if o.ctxTarget == "" {
		o.ctxTarget = e
		if a != "" {
			o.ctxTarget = a
		}
	}
	var z *nipcash.ZapContext
	if o.scheme == nipcash.SchemeZapV1 {
		ct := o.ctxTarget
		if ct == "" {
			ct = "none"
		}
		z = &nipcash.ZapContext{Recipient: o.ctxRecip, Sender: o.ctxSender, ZapTarget: ct, IssuedAt: o.issuedAt, ExpiresAt: o.expiresAt}
	}
	tok, s := f.token(t, tokenOpts{scheme: o.scheme, amount: o.amount, z: z, relays: o.relays, idReq: o.idReq, signer: o.minterPriv, minterX: o.minterX})
	tags := [][]string{}
	if e != "" {
		tags = append(tags, []string{"e", e})
	}
	if a != "" {
		tags = append(tags, []string{"a", a})
	}
	if o.target != nil {
		tags = append(tags, []string{"k", strconv.Itoa(o.target.Kind)})
	}
	tags = append(tags,
		[]string{"p", o.recipient},
		[]string{"amount", strconv.FormatUint(o.amount, 10)},
		[]string{"chain", "bitcoin"},
		[]string{"cash", s},
		[]string{"w", tok.WalletPubkey},
		[]string{"issued_at", strconv.FormatUint(o.issuedAt, 10)},
		[]string{"expires_at", strconv.FormatUint(o.expiresAt, 10)},
	)
	if o.mutate != nil {
		tags = o.mutate(tags)
	}
	ev, err := nip01.NewSignedEvent(KindCashZap, "Great post!", o.signer, tags...)
	if err != nil {
		t.Fatal(err)
	}
	return ev, tok
}

func pubOf(t *testing.T, priv string) string {
	t.Helper()
	ev, err := nip01.NewSignedEvent(1, "", priv)
	if err != nil {
		t.Fatal(err)
	}
	return ev.PubKey
}

// setTag replaces the first tag named name (or appends one) with vals.
func setTag(name string, vals ...string) func([][]string) [][]string {
	return func(tags [][]string) [][]string {
		for i, tg := range tags {
			if tg[0] == name {
				tags[i] = append([]string{name}, vals...)
				return tags
			}
		}
		return append(tags, append([]string{name}, vals...))
	}
}

func dropTag(name string) func([][]string) [][]string {
	return func(tags [][]string) [][]string {
		out := tags[:0:0]
		for _, tg := range tags {
			if tg[0] != name {
				out = append(out, tg)
			}
		}
		return out
	}
}

func addTag(vals ...string) func([][]string) [][]string {
	return func(tags [][]string) [][]string { return append(tags, vals) }
}

func chain(fs ...func([][]string) [][]string) func([][]string) [][]string {
	return func(tags [][]string) [][]string {
		for _, f := range fs {
			tags = f(tags)
		}
		return tags
	}
}

func signInfo(t *testing.T, priv string, tags ...[]string) *nip01.Event {
	t.Helper()
	ev, err := nip01.NewSignedEvent(KindCashZapInfo, "", priv, tags...)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// compressed is the 02-prefixed form of an x-only key, and its 03 twin.
func compressed(x string) (c02, c03 string) { return "02" + x, "03" + x }
