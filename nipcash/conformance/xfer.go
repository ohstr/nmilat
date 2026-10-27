package conformance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/utils"
)

// Transfers, zap transfers, consolidation, the operator's caps on new wallets
// and archive drops (NIP-CASH §Transferring and Splitting a Slice,
// §Consolidating Tokens, §Mint Provenance, §Security Considerations for
// Cash-Mode Slices, §Looking Up a Call), on bills minted over the Cash Hub
// connection.

var xferCases = []ctCase{
	{id: "CT-XFER-04", run: ctXfer04},
	{id: "CT-XFER-12", run: ctXfer12},
	{id: "CT-XFER-20", needs: []need{needAdmin}, run: ctXfer20},
	{id: "CT-CONS-01", run: ctCons01},
	{id: "CT-CONS-02", run: ctCons02},
	{id: "CT-CONS-03", run: ctCons03},
	{id: "CT-CONS-05", run: ctCons05},
	{id: "CT-CONS-08", run: ctCons08},
	{id: "CT-CONS-09", run: ctCons09},
	{id: "CT-LK-15", needs: []need{needAdmin}, run: ctLk15},
}

// transfer sends one cash_transfer through the SDK's batch session.
func (s *suite) transfer(t *testing.T, h holder, p nipcash.CashTransferParams) (client.TransferOutcome, nipcash.PendingCall) {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	if p.Credential == nil {
		p.Credential = h.cred
	}
	if p.CurrentAmount == 0 {
		p.CurrentAmount = h.amount
	}
	if p.RequestID == "" {
		p.RequestID, _ = nipcash.NewRequestID()
	}
	j := newMemJournal()
	outs, err := s.wdSession(t).TransferMany(ctx, []client.BatchTransfer{{ID: "1", Bill: h.bill, Params: p}}, j, "conformance")
	if len(outs) != 1 {
		t.Fatalf("cash_transfer: %v", err)
	}
	pc, _ := j.call(p.RequestID)
	return outs[0], pc
}

// transferParams is a well-formed cash_transfer request for h, as a map a case
// can spoil.
func transferParams(t *testing.T, h holder, p nipcash.CashTransferParams) map[string]any {
	t.Helper()
	if p.Credential == nil {
		p.Credential = h.cred
	}
	if p.CurrentAmount == 0 {
		p.CurrentAmount = h.amount
	}
	p.RequestID, _ = nipcash.NewRequestID()
	req, err := p.Request(h.tok.WalletPubkey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(req)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

// holderFor mints a one-slice pubkey bill of amount for priv's key.
func (s *suite) holderFor(t *testing.T, priv string, amount uint64, expiry time.Duration) holder {
	t.Helper()
	pub := mustPub(t, priv)
	h := s.holderOf(t, s.mint(t, expiry, nipcash.Send(nipcash.Pubkey(pub), amount)))
	h.priv, h.cred, h.amount = priv, nipcash.BySigning(priv), amount
	return h
}

func mustPub(t *testing.T, priv string) string {
	t.Helper()
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// CT-XFER-04 (S-CASH-94): a zap transfer's bill for new_identity is signed
// under scheme 2 over the sender, the target's hash and the reply's issued_at
// and expires_at; a partial one's remainder under scheme 1.
func ctXfer04(t *testing.T, s *suite) {
	h := s.pubkeyBill(t, 21_000_000, 30*24*time.Hour)
	expires := s.status(t, h, nipcash.ScopeMine).Recipients[0].ExpiresAt
	_, xc := keypair(t)
	const target = "30023:0000000000000000000000000000000000000000000000000000000000000001:a:b"
	split := uint64(5_000_000)
	o, _ := s.transfer(t, h, nipcash.CashTransferParams{To: nipcash.Pubkey(xc), SplitAmount: &split, ZapTarget: target})
	if o.Result == nil {
		t.Fatalf("zap transfer refused: %+v", o.Error)
	}
	r := o.Result
	if !r.ZapSigned() {
		t.Fatalf("the reply lacks issued_at or expires_at: %+v", r)
	}
	if want := uint64(expires.At); expires.Present && *r.ExpiresAt != want {
		t.Errorf("expires_at %d, want the source's %d", *r.ExpiresAt, want)
	}
	zb, err := nipcash.Decode(r.NewWalletToken)
	if err != nil || zb.Scheme != nipcash.SchemeZapV1 {
		t.Fatalf("the zap bill: %v, scheme %d, want 2", err, zb.Scheme)
	}
	z := nipcash.ZapContext{Recipient: xc, Sender: mustPub(t, h.priv), ZapTarget: target, IssuedAt: *r.IssuedAt, ExpiresAt: *r.ExpiresAt}
	if minter, ok := nipcash.VerifyZapProvenance(zb, z); !ok || !strings.HasSuffix(minter, s.nodeXOnly) {
		t.Errorf("the zap bill's signature recovers to %q, want the node %s", minter, s.nodeXOnly)
	}
	rb, err := nipcash.Decode(r.RemainderWalletToken)
	if err != nil || rb.Scheme != nipcash.SchemeMintV1 {
		t.Fatalf("the remainder: %v, scheme %d, want 1", err, rb.Scheme)
	}
	if minter, ok := nipcash.VerifyProvenance(rb); !ok || !strings.HasSuffix(minter, s.nodeXOnly) {
		t.Errorf("the remainder's signature recovers to %q, want the node", minter)
	}
}

// CT-XFER-12 (S-CASH-92, S-CZ-25): the zap gates: an empty zap_target and a
// non-pubkey new_identity are BAD_REQUEST; a cash or connection_key source is
// RESTRICTED.
func ctXfer12(t *testing.T, s *suite) {
	_, xc := keypair(t)
	p := s.pubkeyBill(t, 2_000_000, 0)
	m := transferParams(t, p, nipcash.CashTransferParams{To: nipcash.Pubkey(xc)})
	m["zap_target"] = ""
	joinWant(t, "an empty zap_target", s.raw(t, p, nipcash.MethodCashTransfer, m, p.priv), nipcash.ErrCodeBadRequest)

	target, err := nipcash.NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	m = transferParams(t, p, nipcash.CashTransferParams{To: target})
	m["zap_target"] = "ab"
	joinWant(t, "a cash new_identity", s.raw(t, p, nipcash.MethodCashTransfer, m, p.priv), nipcash.ErrCodeBadRequest)

	c := s.cashBill(t, 2_000_000)
	m = transferParams(t, c, nipcash.CashTransferParams{To: nipcash.Pubkey(xc)})
	m["zap_target"] = "ab"
	joinWant(t, "a cash source", s.raw(t, c, nipcash.MethodCashTransfer, m, ""), nipcash.ErrCodeRestricted)

	k := s.ckBill(t, 2_000_000)
	m = transferParams(t, k, nipcash.CashTransferParams{To: nipcash.Pubkey(xc)})
	m["zap_target"] = "ab"
	joinWant(t, "a connection_key source", s.raw(t, k, nipcash.MethodCashTransfer, m, k.priv), nipcash.ErrCodeRestricted)
}

// CT-XFER-20 (CASH-CSEC-01, CASH-CSEC-02, CASH-S-35): a spin-off over the live
// wallet cap is QUOTA_EXCEEDED, one over the lineage's spin-off rate
// RATE_LIMITED, never INTERNAL or OTHER; a valid call on the same bill from
// another source after those refusals is still served.
func ctXfer20(t *testing.T, s *suite) {
	admin := s.h.(Admin)
	a, b := s.pubkeyPair(t, 4_000_000)
	_, xc := keypair(t)
	split := uint64(1_000_000)
	admin.SetLiveWalletCap(t, 1)
	t.Cleanup(func() { admin.SetLiveWalletCap(t, 0) })
	if o, _ := s.transfer(t, a, nipcash.CashTransferParams{To: nipcash.Pubkey(xc), SplitAmount: &split}); o.Error == nil || o.Error.Code != nipcash.ErrCodeQuotaExceeded {
		t.Errorf("a spin-off over the live-wallet cap: %+v, want QUOTA_EXCEEDED", o.ItemOutcome)
	}
	admin.SetLiveWalletCap(t, 0)
	admin.SetSpinOffRate(t, 1, time.Hour)
	t.Cleanup(func() { admin.SetSpinOffRate(t, 0, 0) })
	if o, _ := s.transfer(t, a, nipcash.CashTransferParams{To: nipcash.Pubkey(xc), SplitAmount: &split}); o.Result == nil {
		t.Fatalf("the first spin-off under the rate: %+v", o.Error)
	}
	o, _ := s.transfer(t, b, nipcash.CashTransferParams{To: nipcash.Pubkey(xc), SplitAmount: &split})
	if o.Error == nil || o.Error.Code != nipcash.ErrCodeRateLimited {
		t.Errorf("a spin-off over the lineage rate: %+v, want RATE_LIMITED", o.ItemOutcome)
	}
	if o, _ := s.transfer(t, b, nipcash.CashTransferParams{To: nipcash.Pubkey(xc)}); o.Result == nil {
		t.Errorf("an in-place transfer of the bill's other slice after the refusals: %+v, want served", o.Error)
	}
}

// consolidation is a two-source consolidation by one holder's key.
type consolidation struct {
	a, b holder
	p    nipcash.CashConsolidateParams
}

func (s *suite) consolidation(t *testing.T, to nipcash.Target, expA, expB time.Duration) consolidation {
	t.Helper()
	priv := mustKey(t)
	a := s.holderFor(t, priv, 3_000_000, expA)
	b := s.holderFor(t, priv, 2_000_000, expB)
	rid, _ := nipcash.NewRequestID()
	return consolidation{a: a, b: b, p: nipcash.CashConsolidateParams{Sources: []nipcash.Source{
		{WalletPubkey: a.tok.WalletPubkey, Amount: a.amount, Credential: a.cred},
		{WalletPubkey: b.tok.WalletPubkey, Amount: b.amount, Credential: b.cred}}, To: to, RequestID: rid}}
}

// params is the request as a map a case can spoil.
func (c consolidation) params(t *testing.T) map[string]any {
	t.Helper()
	req, err := c.p.Request()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(req)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func (s *suite) consolidateItem(t *testing.T, c consolidation) client.ConsolidateOutcome {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	outs, err := s.wdSession(t).ConsolidateMany(ctx, []client.BatchConsolidate{{ID: "1", Bill: c.a.bill, Params: c.p}}, newMemJournal(), "conformance")
	if len(outs) != 1 {
		t.Fatalf("cash_consolidate: %v", err)
	}
	return outs[0]
}

// CT-CONS-01 (S-CASH-99): an item whose target is not sources[0] is BAD_REQUEST.
func ctCons01(t *testing.T, s *suite) {
	_, xc := keypair(t)
	c := s.consolidation(t, nipcash.Pubkey(xc), 0, 0)
	joinWant(t, "target sources[1]", s.raw(t, c.b, nipcash.MethodCashConsolidate, c.params(t), c.b.priv), nipcash.ErrCodeBadRequest)
}

// CT-CONS-02 (S-CASH-100): one source and a repeated source are BAD_REQUEST;
// more than max_consolidate_sources is QUOTA_EXCEEDED.
func ctCons02(t *testing.T, s *suite) {
	_, xc := keypair(t)
	c := s.consolidation(t, nipcash.Pubkey(xc), 0, 0)
	m := c.params(t)
	src := m["sources"].([]any)
	m["sources"] = src[:1]
	joinWant(t, "one source", s.raw(t, c.a, nipcash.MethodCashConsolidate, m, c.a.priv), nipcash.ErrCodeBadRequest)
	m = c.params(t)
	m["sources"] = []any{src[0], src[0]}
	joinWant(t, "a repeated source", s.raw(t, c.a, nipcash.MethodCashConsolidate, m, c.a.priv), nipcash.ErrCodeBadRequest)
	if s.limits.MaxConsolidateSources <= 0 {
		t.Skip("the Hub announces no max_consolidate_sources")
	}
	many := make([]any, s.limits.MaxConsolidateSources+1)
	for i := range many {
		_, w := keypair(t)
		many[i] = map[string]any{"wallet_pubkey": w, "identity_type": "pubkey", "identity_value": w}
	}
	many[0] = map[string]any{"wallet_pubkey": c.a.tok.WalletPubkey, "identity_type": "pubkey", "identity_value": mustPub(t, c.a.priv)}
	m = c.params(t)
	m["sources"] = many
	joinWant(t, "over max_consolidate_sources", s.raw(t, c.a, nipcash.MethodCashConsolidate, m, c.a.priv), nipcash.ErrCodeQuotaExceeded)
}

// CT-CONS-03 (S-CASH-101): a source the caller does not hold is UNAUTHORIZED
// with the same message as a bad proof; a claimed source whose proofs verify is
// RESTRICTED.
func ctCons03(t *testing.T, s *suite) {
	_, xc := keypair(t)
	c := s.consolidation(t, nipcash.Pubkey(xc), 0, 0)
	foreign := s.pubkeyBill(t, 2_000_000, 0)
	f := c
	f.p.Sources = []nipcash.Source{c.p.Sources[0], {WalletPubkey: foreign.tok.WalletPubkey, Amount: foreign.amount, Credential: c.a.cred}}
	resForeign := s.raw(t, c.a, nipcash.MethodCashConsolidate, f.params(t), c.a.priv)
	joinWant(t, "a foreign source", resForeign, nipcash.ErrCodeUnauthorized)
	m := c.params(t)
	src := m["sources"].([]any)[1].(map[string]any)
	var ev map[string]any
	_ = json.Unmarshal([]byte(src["identity_event"].(string)), &ev)
	ev["content"] = "spoiled"
	raw, _ := json.Marshal(ev)
	src["identity_event"] = string(raw)
	resBad := s.raw(t, c.a, nipcash.MethodCashConsolidate, m, c.a.priv)
	joinWant(t, "a bad proof", resBad, nipcash.ErrCodeUnauthorized)
	if resForeign != nil && resBad != nil && digitless(resForeign["error"]) != digitless(resBad["error"]) {
		t.Errorf("a foreign source answers %s, a bad proof %s: they must not differ", resForeign["error"], resBad["error"])
	}
	// b's slice is claimed by a split; proofs for its original amount verify.
	split := uint64(1_000_000)
	if o, _ := s.transfer(t, c.b, nipcash.CashTransferParams{To: nipcash.Pubkey(xc), SplitAmount: &split}); o.Result == nil {
		t.Fatalf("split b: %+v", o.Error)
	}
	joinWant(t, "a claimed source", s.raw(t, c.a, nipcash.MethodCashConsolidate, c.params(t), c.a.priv), nipcash.ErrCodeRestricted)
}

// CT-CONS-05 (S-CASH-103): a cash-mode source is BAD_REQUEST.
func ctCons05(t *testing.T, s *suite) {
	_, xc := keypair(t)
	c := s.consolidation(t, nipcash.Pubkey(xc), 0, 0)
	cash := s.cashBill(t, 2_000_000)
	m := c.params(t)
	m["sources"] = []any{m["sources"].([]any)[0], map[string]any{"wallet_pubkey": cash.tok.WalletPubkey, "cash_secret": cash.secret}}
	joinWant(t, "a cash source", s.raw(t, c.a, nipcash.MethodCashConsolidate, m, c.a.priv), nipcash.ErrCodeBadRequest)
}

// CT-CONS-08 (S-CASH-107): the merged bill takes the earliest expiry, and the
// sum of the sources.
func ctCons08(t *testing.T, s *suite) {
	_, xc := keypair(t)
	c := s.consolidation(t, nipcash.Pubkey(xc), 0, 48*time.Hour)
	exp := s.status(t, c.b, nipcash.ScopeMine).Recipients[0].ExpiresAt
	o := s.consolidateItem(t, c)
	if o.Result == nil {
		t.Fatalf("consolidate: %+v", o.Error)
	}
	if o.Result.AmountMillis != c.a.amount+c.b.amount || o.Result.ExpiresAt != exp {
		t.Errorf("merged %d expiring %+v, want %d expiring %+v (the earliest)", o.Result.AmountMillis, o.Result.ExpiresAt, c.a.amount+c.b.amount, exp)
	}
	t.Log("the per-wallet ceiling (C and C+1) is not announced, so its boundary is not checked here")
}

// CT-CONS-09 (S-CASH-109, 110): a pubkey target's token is delivered to the
// caller, a cash target's in the clear; a malformed target is BAD_REQUEST and
// a connection_key target under an untrusted IA RESTRICTED.
func ctCons09(t *testing.T, s *suite) {
	_, xc := keypair(t)
	o := s.consolidateItem(t, s.consolidation(t, nipcash.Pubkey(xc), 0, 0))
	if o.Result == nil {
		t.Fatalf("to a pubkey: %+v", o.Error)
	}
	if tok, err := nipcash.Decode(o.Result.NewWalletToken); err != nil || tok.WalletPubkey != o.Result.NewWalletPubkey {
		t.Errorf("a pubkey target's token, decrypted with the first source's key: %v", err)
	}
	target, err := nipcash.NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	cc := s.consolidation(t, target, 0, 0)
	o = s.consolidateItem(t, cc)
	if o.Result == nil {
		t.Fatalf("to cash: %+v", o.Error)
	}
	var raw struct {
		Token string `json:"new_wallet_token"`
	}
	if json.Unmarshal(o.ItemOutcome.Result, &raw) == nil && raw.Token != "" && !strings.HasPrefix(raw.Token, cc.a.tok.HRP) {
		t.Errorf("a cash target's token is not in the clear: %.20s…", raw.Token)
	}
	bad := s.consolidation(t, target, 0, 0)
	joinWant(t, "a malformed target", s.raw(t, bad.a, nipcash.MethodCashConsolidate, bad.signedFor(t, "pubkey", "zz", ""), bad.a.priv), nipcash.ErrCodeBadRequest)
	ck := s.consolidation(t, untrustedCK(t), 0, 0)
	joinWant(t, "an untrusted IA", s.raw(t, ck.a, nipcash.MethodCashConsolidate, ck.params(t), ck.a.priv), nipcash.ErrCodeRestricted)
}

// signedFor is c's request naming new_identity (idType, idValue, ia) as given,
// even malformed, each source's claim proof signed over it by hand.
func (c consolidation) signedFor(t *testing.T, idType, idValue, ia string) map[string]any {
	t.Helper()
	wallets := []string{c.a.tok.WalletPubkey, c.b.tok.WalletPubkey}
	sHash, err := nipcash.SourcesHash(wallets)
	if err != nil {
		t.Fatal(err)
	}
	var sources []any
	for _, h := range []holder{c.a, c.b} {
		amount := h.amount
		b := nipcash.ClaimBinding{Method: nipcash.MethodCashConsolidate, Wallet: h.tok.WalletPubkey,
			NewIdentityHash: nipcash.NewIdentityHashOf(idType, idValue, ia), AmountMillis: &amount, SourcesHash: sHash}
		ev := nip01.NewEvent(nipcash.KindClaimProof, "", b.Tags()...)
		if err := ev.Sign(h.priv); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(ev)
		sources = append(sources, map[string]any{"wallet_pubkey": h.tok.WalletPubkey, "identity_type": "pubkey",
			"identity_value": mustPub(t, h.priv), "identity_event": string(raw)})
	}
	ni := map[string]any{"identity_type": idType, "identity_value": idValue}
	if ia != "" {
		ni["ia_pubkey"] = ia
	}
	return map[string]any{"sources": sources, "new_identity": ni, "request_id": c.p.RequestID}
}

// untrustedCK is a connection_key target vouched for by an IA no Hub trusts.
func untrustedCK(t *testing.T) nipcash.Target {
	t.Helper()
	iaPriv, _ := keypair(t)
	_, pub := keypair(t)
	key, err := nipIC.NewConnectionKey("discord", "54321")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := nipIC.NewAttestation(nipIC.AttestationParams{PrivateKey: iaPriv, ConnectionKey: key, UserPubkey: pub,
		Platform: "discord", ExpirationDays: 30, AuthType: "email_code", Evidence: nipIC.Evidence{Platform: "discord", UserID: "54321"}})
	if err != nil {
		t.Fatal(err)
	}
	att, err := nipIC.ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	id, err := nipcash.ConnectionKeyFromAttestation(att)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// CT-LK-15 (CASH-S-34): a destroyed bill whose archive was dropped while its
// pairing key stays derivable: a lookup with a valid bill proof is answered by
// its deadline, never omitted. A SHOULD: an omission is reported, not failed.
func ctLk15(t *testing.T, s *suite) {
	h := s.pubkeyBill(t, 2_000_000, 0)
	_, xc := keypair(t)
	split := uint64(1_000_000)
	o, pc := s.transfer(t, h, nipcash.CashTransferParams{To: nipcash.Pubkey(xc), SplitAmount: &split})
	if o.Result == nil {
		t.Fatalf("split: %+v", o.Error)
	}
	s.h.(Admin).DropArchive(t, h.tok.WalletPubkey)
	res := s.raw(t, h, nipcash.MethodCashLookup, nipcash.CashLookupRequest{RequestID: pc.RequestID, Deadline: pc.Deadline}, h.priv)
	if res == nil {
		t.Skip("warning (SHOULD, CASH-S-34): the lookup of a bill whose archive was dropped was omitted")
	}
	if st := lookupStatus(t, res); st.Status == "" {
		t.Errorf("lookup answered %s, want a status by its deadline", res["result"])
	}
}
