package vectors

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57/nip57test"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/utils"
)

type claimFile struct {
	header
	Attestation []attestationCase     `json:"attestation"`
	CashTarget  []cashTargetCase      `json:"cashTarget"`
	Requests    []requestCase         `json:"requests"`
	KATs        []claimKAT            `json:"kats"`
	VerifyClaim []verifyClaimCase     `json:"verifyClaimProof"`
	Results     []claimResultCase     `json:"results"`
	Tombstones  []tombstoneCase       `json:"tombstones"`
	TombReasons []tombstoneReasonCase `json:"tombstoneReason"`
	Ordered     []orderedCase         `json:"ordered"`
	OwnRow      []ownRowCase          `json:"ownRow"`
	Claimable   []claimableCase       `json:"claimable"`
}

// attestationCase: nipIC.ParseAttestation on Event either fails or yields Want.
type attestationCase struct {
	Name  string          `json:"name"`
	Event nip01.Event     `json:"event"`
	Error string          `json:"error,omitempty"`
	Want  *attestationOut `json:"want,omitempty"`
}

type attestationOut struct {
	ConnectionKey string      `json:"connectionKey"`
	UserPubkey    string      `json:"userPubkey"`
	Platform      string      `json:"platform"`
	Evidence      evidenceOut `json:"evidence"`
	ExpiresAt     *int64      `json:"expiresAt"`
}

type evidenceOut struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	VerifiedAt  int64  `json:"verifiedAt"`
	EvidenceURL string `json:"evidenceUrl"`
	Challenge   string `json:"challenge"`
	PreAuthCode string `json:"preAuthCode"`
}

// cashTargetCase: a cash target is a random secret whose sha256 is what the
// wire carries. Secret is fixed here (CashTargetFromSecret).
type cashTargetCase struct {
	Secret string `json:"secret"`
	Commit string `json:"commit"`
}

// requestCase: a cash method request nmilat builds. Inputs describes the
// call; Request is its JSON with every identity_event replaced by the parsed
// claim proof (created_at dropped, since nmilat stamps the current time).
type requestCase struct {
	Name    string         `json:"name"`
	Method  string         `json:"method"`
	Inputs  map[string]any `json:"inputs"`
	Error   string         `json:"error,omitempty"`
	Request map[string]any `json:"request,omitempty"`
}

const (
	claimantSecret = "0202020202020202020202020202020202020202020202020202020202020202"
	iaSecret       = "0303030303030303030303030303030303030303030303030303030303030303"
	attTime        = 1760000000
	attExpiry      = 4102444800 // 2100-01-01: far enough that nmilat's now() check passes
)

// seededReader is a deterministic stream for crypto/rand during vector
// generation: sha256(seed || counter).
type seededReader struct {
	seed string
	n    uint64
	buf  []byte
}

func (r *seededReader) Read(p []byte) (int, error) {
	for len(r.buf) < len(p) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], r.n)
		r.n++
		sum := sha256.Sum256(append([]byte(r.seed), c[:]...))
		r.buf = append(r.buf, sum[:]...)
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func withSeededRand[T any](seed string, f func() T) T {
	old := rand.Reader
	rand.Reader = &seededReader{seed: seed}
	defer func() { rand.Reader = old }()
	return f()
}

func signedEvent(secret string, kind int, tags [][]string, content string) nip01.Event {
	ev := nip01.Event{CreatedAt: attTime, Kind: kind, Tags: tags, Content: content}
	if err := ev.Sign(secret); err != nil {
		panic(err)
	}
	return ev
}

func evidenceJSON(userID string) string {
	return `{"version":1,"platform":"github","auth_type":"public_post","user_id":"` + userID +
		`","username":"alice","verified_at":1759999000,"evidence_url":"https://gist.github.com/alice/1","challenge":"npv1x","pre_auth_code":"abcd"}`
}

func buildClaim() (any, error) {
	f := claimFile{header: newHeader(
		"Claim proofs (kind 23198, K-CLAIM-1..5) and their verification, NIP-IC attestations, cash targets, the requests nmilat builds for cash_redeem, cash_transfer and cash_consolidate, their results (tokens decrypted, tombstones), tombstone reasons, ordered inheritance, and finding the caller's own row (ownRow) and whether it can be spent (claimable).",
		"nipcash/{claim_proof,claim,identity,proof,cash_redeem,cash_transfer,cash_consolidate,tombstone,ordered}.go, nipIC/attestation.go; nipcash/claim_proof_test.go, withdraw_test.go, proof_binding_test.go",
	)}
	userPub, _ := utils.GetPublicKey(claimantSecret)
	iaPub, _ := utils.GetPublicKey(iaSecret)
	ckKey, err := nipIC.ConnectionKeyFromAttested("github", "12345")
	if err != nil {
		return nil, err
	}
	ck := string(ckKey)

	// ---- attestations
	attTags := func(mod func([][]string) [][]string) [][]string {
		t := [][]string{{"d", ck}, {"p", userPub}, {"platform", "github"}, {"evidence", evidenceJSON("12345")}, {"expiration", fmt.Sprint(attExpiry)}}
		if mod != nil {
			t = mod(t)
		}
		return t
	}
	addAtt := func(name string, ev nip01.Event) {
		c := attestationCase{Name: name, Event: ev}
		a, err := nipIC.ParseAttestation(&ev)
		if err != nil {
			c.Error = err.Error()
		} else {
			out := &attestationOut{
				ConnectionKey: string(a.ConnectionKey), UserPubkey: a.UserPubkey, Platform: string(a.Platform),
				Evidence: evidenceOut{a.Evidence.UserID, a.Evidence.Username, a.Evidence.VerifiedAt, a.Evidence.EvidenceURL, string(a.Evidence.Challenge), a.Evidence.PreAuthCode},
			}
			if a.ExpiresAt != nil {
				ts := a.ExpiresAt.Unix()
				out.ExpiresAt = &ts
			}
			c.Want = out
		}
		f.Attestation = append(f.Attestation, c)
	}
	drop := func(name string) func([][]string) [][]string {
		return func(t [][]string) [][]string {
			var out [][]string
			for _, tag := range t {
				if tag[0] != name {
					out = append(out, tag)
				}
			}
			return out
		}
	}
	set := func(name, value string) func([][]string) [][]string {
		return func(t [][]string) [][]string {
			for i, tag := range t {
				if tag[0] == name {
					t[i] = []string{name, value}
				}
			}
			return t
		}
	}
	att := signedEvent(iaSecret, nipIC.KindAttestation, attTags(nil), "")
	addAtt("valid", att)
	addAtt("no expiration", signedEvent(iaSecret, nipIC.KindAttestation, attTags(drop("expiration")), ""))
	addAtt("an unparseable expiration is refused", signedEvent(iaSecret, nipIC.KindAttestation, attTags(set("expiration", "soon")), ""))
	addAtt("wrong kind", signedEvent(iaSecret, 1, attTags(nil), ""))
	bad := att
	bad.Sig = flipHex(bad.Sig)
	addAtt("bad signature", bad)
	for _, tag := range []string{"d", "p", "platform", "evidence"} {
		addAtt("missing "+tag, signedEvent(iaSecret, nipIC.KindAttestation, attTags(drop(tag)), ""))
		addAtt("empty "+tag, signedEvent(iaSecret, nipIC.KindAttestation, attTags(set(tag, "")), ""))
	}
	addAtt("platform-prefixed d", signedEvent(iaSecret, nipIC.KindAttestation, attTags(set("d", "github:"+ck)), ""))
	addAtt("evidence not JSON", signedEvent(iaSecret, nipIC.KindAttestation, attTags(set("evidence", "{")), ""))
	addAtt("evidence null", signedEvent(iaSecret, nipIC.KindAttestation, attTags(set("evidence", "null")), ""))
	addAtt("evidence an array", signedEvent(iaSecret, nipIC.KindAttestation, attTags(set("evidence", "[]")), ""))
	addAtt("evidence with a string version", signedEvent(iaSecret, nipIC.KindAttestation, attTags(set("evidence", `{"version":"1","user_id":"x"}`)), ""))
	addAtt("evidence with a fractional verified_at", signedEvent(iaSecret, nipIC.KindAttestation, attTags(set("evidence", `{"verified_at":1.5}`)), ""))
	addAtt("evidence with unknown fields", signedEvent(iaSecret, nipIC.KindAttestation, attTags(set("evidence", `{"user_id":"x","extra":{"a":1}}`)), ""))
	addAtt("a repeated platform tag is refused", signedEvent(iaSecret, nipIC.KindAttestation, append(attTags(nil), []string{"platform", "x"}), ""))
	addAtt("one-element tags are skipped", signedEvent(iaSecret, nipIC.KindAttestation, append(attTags(nil), []string{"d"}), ""))
	parsedAtt, err := nipIC.ParseAttestation(&att)
	if err != nil {
		return nil, err
	}

	// ---- cash targets
	// Fixed secrets: NewCashTarget draws from the system generator.
	targets := []*nipcash.CashTarget{must(nipcash.CashTargetFromSecret(strings.Repeat("c1", 32))), must(nipcash.CashTargetFromSecret(strings.Repeat("c2", 32)))}
	for _, t := range targets {
		// The commitment is read back out of a transfer request.
		req, err := nipcash.CashTransferParams{RequestID: vecRID, Credential: nipcash.BySecret("x"), To: t, CurrentAmount: 1}.Request(strings.Repeat("ab", 32))
		if err != nil {
			return nil, err
		}
		f.CashTarget = append(f.CashTarget, cashTargetCase{t.Secret(), req.NewIdentity.IdentityValue})
	}

	// ---- requests
	wallet := strings.Repeat("ab", 32)
	wallet2 := strings.Repeat("cd", 32)
	inv := invoice("lnfc10u", hashField(1, repeat(0xaa, 32)))
	cred := map[string]nipcash.Credential{
		"secret":  nipcash.BySecret(strings.Repeat("5e", 32)),
		"signing": nipcash.BySigning(claimantSecret),
	}
	credErr := map[string]error{}
	for name, att := range map[string]*nipIC.Attestation{"connection_key": parsedAtt, "connection_key_no_att": nil, "connection_key_expired": expired(parsedAtt)} {
		c, err := nipcash.BySigningConnectionKey(claimantSecret, att)
		cred[name], credErr[name] = c, err
	}
	tgt := map[string]nipcash.Target{
		"pubkey":           nipcash.Pubkey(userPub),
		"pubkey uppercase": nipcash.Pubkey(strings.ToUpper(userPub)),
		"cash":             targets[0],
	}
	tgtErr := map[string]error{}
	for name, mk := range map[string]func() (nipcash.Target, error){
		"connection_key":              func() (nipcash.Target, error) { return nipcash.ResolvedConnectionKey(ckKey, "github", iaPub) },
		"connection_key no ia":        func() (nipcash.Target, error) { return nipcash.ResolvedConnectionKey(ckKey, "github", "") },
		"connection_key no platform":  func() (nipcash.Target, error) { return nipcash.ResolvedConnectionKey(ckKey, "", iaPub) },
		"connection_key typed github": func() (nipcash.Target, error) { return nipcash.ConnectionKey("github", "12345", iaPub) },
		"connection_key typed x":      func() (nipcash.Target, error) { return nipcash.ConnectionKey("x", "12345", iaPub) },
	} {
		t, err := mk()
		if err != nil {
			tgtErr[name] = err
			continue
		}
		tgt[name] = t
	}
	add := func(name, method string, inputs map[string]any, req any, err error) {
		c := requestCase{Name: name, Method: method, Inputs: inputs}
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Request = flattenRequest(req)
		}
		f.Requests = append(f.Requests, c)
	}
	u64 := func(v uint64) *uint64 { return &v }

	for _, cn := range []string{"secret", "signing", "connection_key", "connection_key_no_att", "connection_key_expired"} {
		if e := credErr[cn]; e != nil {
			add("redeem by "+cn, "cash_redeem", map[string]any{"wallet": wallet, "invoice": inv, "credential": cn}, nil, e)
			continue
		}
		req, err := nipcash.CashRedeemParams{Invoice: inv, Credential: cred[cn]}.Request(wallet)
		add("redeem by "+cn, "cash_redeem", map[string]any{"wallet": wallet, "invoice": inv, "credential": cn}, req, err)
	}
	req, err := nipcash.CashRedeemParams{Invoice: inv, Credential: cred["signing"], Amount: u64(500000)}.Request(wallet)
	add("redeem with an amount", "cash_redeem", map[string]any{"wallet": wallet, "invoice": inv, "credential": "signing", "amount": 500000}, req, err)
	amountless := must(nip57test.SignedBolt11(nip57test.Invoice{Currency: "fc", PaymentHash: seq(0x50), Timestamp: 1720000000, NodePriv: strings.Repeat("0", 63) + "1"}))
	req, err = nipcash.CashRedeemParams{Invoice: amountless, Credential: cred["signing"], Amount: u64(500000)}.Request(wallet)
	add("redeem an amountless invoice with an amount", "cash_redeem", map[string]any{"wallet": wallet, "invoice": amountless, "credential": "signing", "amount": 500000}, req, err)
	req, err = nipcash.CashRedeemParams{Invoice: "lnfc1notaninvoice", Credential: cred["signing"]}.Request(wallet)
	add("redeem with a bad invoice", "cash_redeem", map[string]any{"wallet": wallet, "invoice": "lnfc1notaninvoice", "credential": "signing"}, req, err)

	for _, tn := range []string{"pubkey", "pubkey uppercase", "connection_key", "connection_key no ia", "connection_key no platform", "connection_key typed github", "connection_key typed x", "cash"} {
		if e := tgtErr[tn]; e != nil {
			add("transfer to "+tn, "cash_transfer", map[string]any{"wallet": wallet, "credential": "signing", "to": tn, "currentAmount": 21000}, nil, e)
			continue
		}
		r, err := nipcash.CashTransferParams{RequestID: vecRID, Credential: cred["signing"], To: tgt[tn], CurrentAmount: 21000}.Request(wallet)
		add("transfer to "+tn, "cash_transfer", map[string]any{"wallet": wallet, "credential": "signing", "to": tn, "currentAmount": 21000}, r, err)
	}
	for _, cn := range []string{"secret", "connection_key"} {
		r, err := nipcash.CashTransferParams{RequestID: vecRID, Credential: cred[cn], To: tgt["pubkey"], CurrentAmount: 21000}.Request(wallet)
		add("transfer by "+cn, "cash_transfer", map[string]any{"wallet": wallet, "credential": cn, "to": "pubkey", "currentAmount": 21000}, r, err)
	}
	r, err := nipcash.CashTransferParams{RequestID: vecRID, Credential: cred["signing"], To: tgt["cash"], CurrentAmount: 21000, SplitAmount: u64(5000)}.Request(wallet)
	add("transfer a split", "cash_transfer", map[string]any{"wallet": wallet, "credential": "signing", "to": "cash", "currentAmount": 21000, "splitAmount": 5000}, r, err)

	src := func(w string, amount uint64, cn string) nipcash.Source { return nipcash.From(w, amount, cred[cn]) }
	cons := func(name string, to string, sources []nipcash.Source, desc []map[string]any) {
		r, err := nipcash.CashConsolidateParams{RequestID: vecRID, Sources: sources, To: tgt[to]}.Request()
		add(name, "cash_consolidate", map[string]any{"to": to, "sources": desc}, r, err)
	}
	d := func(w string, amount uint64, cn string) map[string]any {
		return map[string]any{"wallet": w, "amount": amount, "credential": cn}
	}
	cons("consolidate two bills", "pubkey", []nipcash.Source{src(wallet, 1000, "signing"), src(wallet2, 2000, "signing")}, []map[string]any{d(wallet, 1000, "signing"), d(wallet2, 2000, "signing")})
	cons("consolidate to a cash target", "cash", []nipcash.Source{src(wallet, 1000, "signing"), src(wallet2, 2000, "connection_key")}, []map[string]any{d(wallet, 1000, "signing"), d(wallet2, 2000, "connection_key")})
	cons("consolidate one bill", "pubkey", []nipcash.Source{src(wallet, 1000, "signing")}, []map[string]any{d(wallet, 1000, "signing")})
	cons("consolidate a cash-mode bill", "pubkey", []nipcash.Source{src(wallet, 1000, "signing"), src(wallet2, 2000, "secret")}, []map[string]any{d(wallet, 1000, "signing"), d(wallet2, 2000, "secret")})
	cons("consolidate the same bill twice", "pubkey", []nipcash.Source{src(wallet, 1000, "signing"), src(wallet, 1000, "signing")}, []map[string]any{d(wallet, 1000, "signing"), d(wallet, 1000, "signing")})
	cons("consolidate to a connection key without ia", "connection_key no ia", []nipcash.Source{src(wallet, 1000, "signing"), src(wallet2, 2000, "signing")}, []map[string]any{d(wallet, 1000, "signing"), d(wallet2, 2000, "signing")})

	f.KATs = claimKATs()
	f.VerifyClaim = verifyClaimCases()
	f.Results = claimResultCases(userPub, cred, targets)
	f.Tombstones, f.TombReasons = tombstoneCases()
	f.Ordered = orderedCases()
	f.OwnRow, f.Claimable = ownRowCases(userPub, ckKey, iaPub, targets, cred)
	return f, nil
}

func expired(a *nipIC.Attestation) *nipIC.Attestation {
	c := *a
	t := *a.ExpiresAt
	t = t.AddDate(-200, 0, 0)
	c.ExpiresAt = &t
	return &c
}

// flattenRequest turns a request struct into JSON-shaped maps, replacing each
// identity_event string with its parsed claim proof.
func flattenRequest(req any) map[string]any {
	raw, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	replaceEvents(m)
	return m
}

func replaceEvents(m map[string]any) {
	for k, v := range m {
		switch x := v.(type) {
		case string:
			if k == "identity_event" {
				var ev nip01.Event
				if err := json.Unmarshal([]byte(x), &ev); err != nil {
					panic(err)
				}
				m[k] = map[string]any{
					"kind": ev.Kind, "pubkey": ev.PubKey, "tags": ev.Tags, "content": ev.Content,
					"valid": ev.Verify() == nil,
				}
			}
		case map[string]any:
			replaceEvents(x)
		case []any:
			for _, e := range x {
				if em, ok := e.(map[string]any); ok {
					replaceEvents(em)
				}
			}
		}
	}
}

var _ io.Reader = (*seededReader)(nil)
