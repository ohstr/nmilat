package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/flokiorg/go-flokicoin/wire"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/utils"
)

// withdrawCases are the on-chain withdrawal cases (NIP-CASH §Redeeming
// On-chain). Their bills come from mint_cash on the Cash Hub connection; a Hub
// whose connection does not serve it runs only the wire cases. CT-WD-24 runs
// first: a re-minted bill another case leaves behind keeps a Cash Hub from
// teardown for good.
var withdrawCases = []ctCase{
	{id: "CT-WD-24", needs: []need{needDeleter, needWithdrawChain, needClock}, run: ctWd24},
	{id: "CT-WD-01", run: ctWd01},
	{id: "CT-WD-02", run: ctWd02},
	{id: "CT-WD-03", run: ctWd03},
	{id: "CT-WD-04", run: ctWd04},
	{id: "CT-WD-05", run: ctWd05},
	{id: "CT-WD-06", run: ctWd06},
	{id: "CT-WD-07", run: ctWd07},
	{id: "CT-WD-08", run: ctWd08},
	{id: "CT-WD-09", run: ctWd09},
	{id: "CT-WD-10", run: ctWd10},
	{id: "CT-WD-11", needs: []need{needWithdrawChain}, run: ctWd11},
	{id: "CT-WD-12", needs: []need{needWithdrawChain, needClock}, run: ctWd12},
	{id: "CT-WD-13", run: ctWd13},
	{id: "CT-WD-14", needs: []need{needWithdrawChain, needClock}, run: ctWd14},
	{id: "CT-WD-15", needs: []need{needWithdrawChain}, run: ctWd15},
	{id: "CT-WD-16", needs: []need{needWithdrawChain}, run: ctWd16},
	{id: "CT-WD-17", needs: []need{needWithdrawChain}, run: ctWd17},
	{id: "CT-WD-18", needs: []need{needWithdrawChain}, run: ctWd18},
	{id: "CT-WD-19", needs: []need{needFaulty, needClock}, run: ctWd19},
	{id: "CT-WD-20", needs: []need{needFaulty, needClock, needWithdrawChain}, run: ctWd20},
	{id: "CT-WD-21", needs: []need{needWithdrawChain, needClock}, run: ctWd21},
	{id: "CT-WD-22", needs: []need{needAdmin, needFaulty, needClock}, run: ctWd22},
	{id: "CT-WD-23", needs: []need{needWithdrawChain, needClock}, run: ctWd23},
	{id: "CT-WD-25", needs: []need{needFaulty, needWithdrawChain}, run: ctWd25},
	{id: "CT-WD-26", needs: []need{needWithdrawChain, needClock}, run: ctWd26},
	{id: "CT-WD-27", run: ctWd27},
	{id: "CT-STAT-13", run: ctStat13},
	{id: "CT-ENV-16", run: ctEnv16},
	{id: "CT-SCOPE-05", run: ctScope05},
}

const wdAmount = 21_000_000

// CT-WD-01 (CASH-WD-01): cash_withdraw_quote and cash_withdraw sent as kind
// 23194 are NOT_IMPLEMENTED, and get_info's methods lists neither. A Hub
// offering withdrawals lists both privately and carries the withdraw object;
// switched off (WithdrawToggle), it lists neither, carries no object and
// refuses both NOT_IMPLEMENTED at I5 (after a destroyed bill's tombstone at I4),
// while lookups and cancel requests of payouts committed before are served.
func ctWd01(t *testing.T, s *suite) {
	for _, method := range []string{nipcash.MethodCashWithdrawQuote, nipcash.MethodCashWithdraw} {
		if slices.Contains(s.info.Methods, method) {
			t.Errorf("get_info methods lists %s", method)
		}
		ctx, cancel := ctx15()
		resp, err := s.nwc.Call(ctx, method, map[string]any{})
		cancel()
		var we *relayclient.WalletError
		switch {
		case errors.As(err, &we):
			if we.Code != nipcash.ErrCodeNotImplemented {
				t.Errorf("%s on 23194: %s, want NOT_IMPLEMENTED", method, we.Code)
			}
		case err != nil:
			t.Errorf("%s on 23194: %v", method, err)
		case resp.Error == nil || resp.Error.Code != nipcash.ErrCodeNotImplemented:
			t.Errorf("%s on 23194 was not refused NOT_IMPLEMENTED: %+v", method, resp.Response)
		}
	}
	if !slices.Contains(s.info.Methods, nipcash.MethodMintCash) || !s.offersWithdrawals(t) {
		t.Logf("the bill part needs a Hub offering withdrawals and serving mint_cash")
		return
	}
	s.withdrawals(t)
	a, b := s.pubkeyPair(t, wdAmount)
	if st := s.status(t, b, nipcash.ScopeMine); st.Withdraw == nil {
		t.Errorf("cash_status of a Hub listing the withdrawal methods carries no withdraw object")
	}
	// A Hub that lists them on its bills' connections only (the probe found
	// them there) lists both on this bill's too.
	byBill := s.wd.billInfo != nil
	if byBill {
		if gi, err := s.billGetInfo(b.tok); err != nil {
			t.Error(err)
		} else if !slices.Contains(gi.PrivateMethods, nipcash.MethodCashWithdrawQuote) || !slices.Contains(gi.PrivateMethods, nipcash.MethodCashWithdraw) {
			t.Errorf("a bill's private_methods %v lacks a withdrawal method", gi.PrivateMethods)
		}
	}
	toggle, ok := s.h.(WithdrawToggle)
	if !ok {
		return
	}
	addr := s.address(t, p2wpkh)
	_, pc := s.withdrawOK(t, a, addr)
	gone := s.pubkeyBill(t, wdAmount, 0)
	s.withdrawOK(t, gone, addr)
	qb := s.quoteOK(t, b, addr)
	toggle.SetWithdrawals(t, false)
	t.Cleanup(func() { toggle.SetWithdrawals(t, true) })

	ctx, cancel := ctx15()
	info, err := s.nwc.GetInfo(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(info.PrivateMethods, nipcash.MethodCashWithdrawQuote) || slices.Contains(info.PrivateMethods, nipcash.MethodCashWithdraw) {
		t.Errorf("withdrawals off: private_methods %v still lists them", info.PrivateMethods)
	}
	if byBill {
		if gi, err := s.billGetInfo(b.tok); err != nil {
			t.Error(err)
		} else if slices.Contains(gi.PrivateMethods, nipcash.MethodCashWithdrawQuote) || slices.Contains(gi.PrivateMethods, nipcash.MethodCashWithdraw) {
			t.Errorf("withdrawals off: a bill's private_methods %v still lists them", gi.PrivateMethods)
		}
	}
	if st := s.status(t, b, nipcash.ScopeMine); st.Withdraw != nil {
		t.Errorf("withdrawals off: cash_status still carries the withdraw object")
	}
	if o := s.quote(t, b, addr, nil); o.Error == nil || o.Error.Code != nipcash.ErrCodeNotImplemented {
		t.Errorf("withdrawals off: quote %+v, want NOT_IMPLEMENTED", o.ItemOutcome)
	}
	if o, _ := s.withdraw(t, b, qb); o.Error == nil || o.Error.Code != nipcash.ErrCodeNotImplemented {
		t.Errorf("withdrawals off: cash_withdraw %+v, want NOT_IMPLEMENTED", o.ItemOutcome)
	}
	if o := s.quote(t, gone, addr, nil); o.Gone == nil {
		t.Errorf("withdrawals off: a destroyed bill's quote %+v, want its tombstone (I4 before I5)", o.ItemOutcome)
	}
	if lo := s.lookup(t, a, pc, ""); lo.Status != nipcash.LookupDone {
		t.Errorf("withdrawals off: the lookup of a committed payout %+v, want done", lo)
	}
	if o := s.cancel(t, a, pc); (o.Error != nil && o.Error.Code == nipcash.ErrCodeNotImplemented) || o.State == client.OutcomeNotServed {
		t.Errorf("withdrawals off: a cancel request was not served: %+v", o.ItemOutcome)
	}
}

// malformedAddresses are K-ADDR-7..11 under hrp: v1 with a bech32 checksum, v0
// with a bech32m one, v0 with a 21-byte program, all uppercase, mixed case.
func malformedAddresses(t *testing.T, hrp string) map[string]string {
	t.Helper()
	enc := func(m bool, v byte, n int) string {
		conv, _ := bech32.ConvertBits(bytes.Repeat([]byte{0x75}, n), 8, 5, true)
		data := append([]byte{v}, conv...)
		var s string
		var err error
		if m {
			s, err = bech32.EncodeM(hrp, data)
		} else {
			s, err = bech32.Encode(hrp, data)
		}
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	good := enc(false, 0, 20)
	return map[string]string{
		"K-ADDR-7 v1 bech32":  enc(false, 1, 32),
		"K-ADDR-8 v0 bech32m": enc(true, 0, 20),
		"K-ADDR-9 v0 21":      enc(false, 0, 21),
		"K-ADDR-10 upper":     strings.ToUpper(good),
		"K-ADDR-11 mixed":     strings.ToUpper(good[:4]) + good[4:],
	}
}

func wantCode(t *testing.T, name string, res map[string]json.RawMessage, code string, detail nipcash.Detail) {
	t.Helper()
	if res == nil {
		t.Errorf("%s: omitted, want %s", name, code)
		return
	}
	if got := resultCode(res); got != code || nipcash.Detail(resultDetail(res)) != detail {
		t.Errorf("%s: %s/%s (%s), want %s/%s", name, got, resultDetail(res), res["error"], code, detail)
	}
}

func wantOutcome(t *testing.T, name string, o client.ItemOutcome, code string, detail nipcash.Detail) {
	t.Helper()
	c, d := codeOf(o)
	if c != code || nipcash.Detail(d) != detail {
		t.Errorf("%s: %s/%s (%+v), want %s/%s", name, c, d, o, code, detail)
	}
}

func quoteParams(addr string, sendBefore *int64) map[string]any {
	m := map[string]any{"address": addr}
	if sendBefore != nil {
		m["send_before"] = *sendBefore
	}
	return m
}

// CT-WD-02 (CASH-WD-03, CASH-S-25): quote refusals in row order with their
// detail, each paired with a later row's defect.
func ctWd02(t *testing.T, s *suite) {
	s.withdrawals(t)
	hrp := s.hrp(t)
	soon := time.Now().Unix() + 30 // a send_before no Hub can meet: row 8
	h := s.pubkeyBill(t, wdAmount, 0)
	terms := s.wdTerms(t, h)

	// Row 1: an unknown signer, with a malformed address.
	stranger, _ := keypair(t)
	wantCode(t, "unknown signer", s.raw(t, h, nipcash.MethodCashWithdrawQuote, quoteParams("x", nil), stranger), nipcash.ErrCodeNotFound, "")
	// Row 1: a connection_key attestation that does not verify (by another IA).
	ck := s.ckBill(t, wdAmount)
	other := s.ckBill(t, wdAmount)
	attRaw, _ := json.Marshal(other.att.Event)
	wantCode(t, "attestation of another IA", s.raw(t, ck, nipcash.MethodCashWithdrawQuote, map[string]any{"address": "x",
		"identity_value": ck.att.ConnectionKey.String(), "ia_pubkey": ck.att.PubKey, "attestation_event": string(attRaw)}, ck.priv),
		nipcash.ErrCodeNotFound, "")
	// Row 5: a connection_key slice whose IA is no longer trusted, too slow.
	s.h.TrustIA(t, ck.att.PubKey, false)
	o := s.quote(t, ck, s.address(t, p2wpkh), &soon)
	s.h.TrustIA(t, ck.att.PubKey, true)
	wantOutcome(t, "IA no longer trusted", o.ItemOutcome, nipcash.ErrCodeRestricted, "")
	// Row 2: malformed, too slow.
	for name, addr := range malformedAddresses(t, hrp) {
		wantCode(t, name, s.raw(t, h, nipcash.MethodCashWithdrawQuote, quoteParams(addr, &soon), h.priv), nipcash.ErrCodeBadRequest, "")
	}
	// Row 3: another network, with a script type not paid.
	wantCode(t, "K-ADDR-6 another network", s.raw(t, h, nipcash.MethodCashWithdrawQuote,
		quoteParams(witnessAddress(t, s.otherHRP(t), nipcash.ScriptType{Version: 2, ProgramLen: 16}), nil), h.priv),
		nipcash.ErrCodeRestricted, nipcash.DetailNetwork)
	// Row 4: script types not paid, and no witness program, too slow.
	pays := terms.ScriptTypeList()
	for _, st := range []nipcash.ScriptType{{Version: 2, ProgramLen: 16}, {Version: 1, ProgramLen: 20}} {
		if nipcash.PaysScriptType(pays, st) {
			continue
		}
		wantCode(t, "script type not paid", s.raw(t, h, nipcash.MethodCashWithdrawQuote, quoteParams(witnessAddress(t, hrp, st), &soon), h.priv),
			nipcash.ErrCodeRestricted, nipcash.DetailScriptType)
	}
	wantCode(t, "K-ADDR-12 base58", s.raw(t, h, nipcash.MethodCashWithdrawQuote, quoteParams("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", &soon), h.priv),
		nipcash.ErrCodeRestricted, nipcash.DetailScriptType)
	addr := s.address(t, p2wpkh)
	// Row 5: a claimed slice, too slow.
	a, _ := s.pubkeyPair(t, wdAmount)
	s.withdrawOK(t, a, addr)
	wantOutcome(t, "claimed slice", s.quote(t, a, addr, &soon).ItemOutcome, nipcash.ErrCodeRestricted, "")
	// Row 5: past its expiry (Clocked), too slow.
	if _, ok := s.h.(Clocked); ok {
		e := s.pubkeyBill(t, wdAmount, time.Hour)
		s.advance(t, 2*time.Hour)
		wantOutcome(t, "expired slice", s.quote(t, e, addr, &soon).ItemOutcome, nipcash.ErrCodeRestricted, "")
	}
	// Row 6: above the maximum, too slow.
	if terms.MaxMillis != nil {
		big := s.pubkeyBill(t, *terms.MaxMillis+1000, 0)
		wantOutcome(t, "above max_millis", s.quote(t, big, addr, &soon).ItemOutcome, nipcash.ErrCodeQuotaExceeded, "")
	}
	// Row 7: below the minimum, and a payout below dust, both too slow.
	if terms.MinMillis != nil && *terms.MinMillis > 1000 {
		small := s.pubkeyBill(t, *terms.MinMillis-1000, 0)
		wantOutcome(t, "below min_millis", s.quote(t, small, addr, &soon).ItemOutcome, nipcash.ErrCodeRestricted, nipcash.DetailBelowMin)
	}
	// A slice at the minimum whose payout the Hub's own network fee estimate
	// (read from a quote) brings to zero.
	network := s.quoteOK(t, h, addr).NetworkFeeMillis
	dust := s.pubkeyBill(t, max(1000, derefOr(terms.MinMillis, 1000)), 0)
	if _, _, pay, _ := nipcash.WithdrawFee(dust.amount, network, terms.FeeBase, terms.FeePpm, 0); pay == 0 {
		wantOutcome(t, "payout below dust", s.quote(t, dust, addr, &soon).ItemOutcome, nipcash.ErrCodeRestricted, nipcash.DetailBelowMin)
	} else {
		t.Logf("no slice at min_millis pays out zero under this Hub's terms; the dust row is not exercised")
	}
	// Row 8 alone.
	wantOutcome(t, "send_before unreachable", s.quote(t, h, addr, &soon).ItemOutcome, nipcash.ErrCodeRestricted, nipcash.DetailTooSlow)
}

func derefOr(p *uint64, d uint64) uint64 {
	if p == nil {
		return d
	}
	return *p
}

// CT-WD-03 (CASH-WD-05, CASH-WD-07, CASH-WD-23): quote answers. Tags equal the
// fields, d/i/address name the slice and the address, signed by get_info's
// pubkey, sent_by ≤ send_before, a whole number of base units, the fee per
// WithdrawFee with the slice's redeem fee as floor; a connection_key quote
// with its attestation; a cash-mode quote on the bill proof alone, and one
// carrying a cash_secret BAD_REQUEST.
func ctWd03(t *testing.T, s *suite) {
	s.withdrawals(t)
	h := s.pubkeyBill(t, wdAmount, 0)
	terms := s.wdTerms(t, h)
	row := s.status(t, h, nipcash.ScopeMine).Recipients[0]
	addr := s.address(t, p2wpkh)
	// A send_before an hour past what the Hub would give anyway, on its clock.
	sb := s.quoteOK(t, h, addr).SentBy + 3600
	o := s.quote(t, h, addr, &sb)
	if o.Result == nil {
		t.Fatalf("quote refused: %+v", o.ItemOutcome)
	}
	identity, _, _ := nipcash.SliceIdentity(h.cred)
	q, err := nipcash.VerifyQuoteAnswer(*o.Result, nipcash.QuoteExpectation{HubXOnly: s.info.Pubkey, Wallet: h.tok.WalletPubkey,
		IdentityValue: identity, Address: addr, SendBefore: &sb, AmountMillis: wdAmount, RedeemFeeMillis: &row.RedeemFeeMillis})
	if err != nil {
		t.Fatalf("quote answer: %v", err)
	}
	if q.Event.PubKey != s.info.Pubkey || nipcash.VerifyWithdrawQuote(q, s.info.Pubkey) != nil {
		t.Errorf("the quote is not signed by get_info's pubkey %s", s.info.Pubkey)
	}
	hub, fee, pay, err := nipcash.WithdrawFee(wdAmount, q.NetworkFeeMillis, terms.FeeBase, terms.FeePpm, row.RedeemFeeMillis)
	if err != nil || hub != q.HubFeeMillis || fee != q.FeeMillis() || pay != q.PayoutMillis {
		t.Errorf("fee: hub %d fee %d payout %d, want WithdrawFee's %d %d %d", q.HubFeeMillis, q.FeeMillis(), q.PayoutMillis, hub, fee, pay)
	}
	if q.PayoutMillis%1000 != 0 || q.SentBy > sb {
		t.Errorf("payout %d, sent_by %d (send_before %d)", q.PayoutMillis, q.SentBy, sb)
	}
	s.quoteOK(t, s.ckBill(t, wdAmount), addr)
	c := s.cashBill(t, wdAmount)
	s.quoteOK(t, c, addr)
	wantCode(t, "cash-mode quote with cash_secret", s.raw(t, c, nipcash.MethodCashWithdrawQuote,
		map[string]any{"address": addr, "cash_secret": c.secret}, ""), nipcash.ErrCodeBadRequest, "")
}

// CT-WD-04 (CASH-WD-02): a quote moves nothing: the slice stays claimable
// with its amount, and with Admin the Hub's balance is unchanged.
func ctWd04(t *testing.T, s *suite) {
	s.withdrawals(t)
	h := s.pubkeyBill(t, wdAmount, 0)
	var before uint64
	admin, isAdmin := s.h.(Admin)
	if isAdmin {
		before = admin.Balance(t)
	}
	s.quoteOK(t, h, s.address(t, p2wpkh))
	row := s.status(t, h, nipcash.ScopeMine).Recipients[0]
	if row.Claimed || row.AmountMillis != wdAmount || row.WithdrawRequestID != "" {
		t.Errorf("after a quote the row is %+v", row)
	}
	if isAdmin && admin.Balance(t) != before {
		t.Errorf("a quote moved the Hub's balance")
	}
}

// CT-WD-05 (CASH-WD-08, CASH-WD-22): BAD_REQUEST before step 1, I6's
// malformed request_id and I8's item with neither proof nor secret; the id
// stays unused, so the same id then succeeds.
func ctWd05(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	h := s.pubkeyBill(t, wdAmount, 0)
	q := s.quoteOK(t, h, addr)
	good := withdrawParams(t, h, q, nil)
	spoil := func(f func(m map[string]any)) map[string]any {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		f(m)
		return m
	}
	cases := map[string]func(map[string]any){
		"no quote":                 func(m map[string]any) { delete(m, "quote") },
		"quote not a string":       func(m map[string]any) { m["quote"] = map[string]any{"kind": 23187} },
		"quote malformed":          func(m map[string]any) { m["quote"] = "{}" },
		"no notify":                func(m map[string]any) { delete(m, "notify") },
		"notify upper":             func(m map[string]any) { m["notify"] = strings.ToUpper(m["notify"].(string)) },
		"remint on a pubkey slice": func(m map[string]any) { m["remint_commitment"] = mustKey(t) },
		"invoice":                  func(m map[string]any) { m["invoice"] = "lnbc1" },
		"amount":                   func(m map[string]any) { m["amount"] = 1000 },
		"idempotency_key":          func(m map[string]any) { m["idempotency_key"] = "k" },
		"I6 request_id":            func(m map[string]any) { m["request_id"] = "XYZ" },
	}
	for name, f := range cases {
		wantCode(t, name, s.raw(t, h, nipcash.MethodCashWithdraw, spoil(f), h.priv), nipcash.ErrCodeBadRequest, "")
	}
	wantCode(t, "I8 neither proof nor secret", s.raw(t, h, nipcash.MethodCashWithdraw, good, ""), nipcash.ErrCodeBadRequest, "")

	c := s.cashBill(t, wdAmount)
	cq := s.quoteOK(t, c, addr)
	cgood := withdrawParams(t, c, cq, nil)
	own, _ := nipcash.CashCommitment(c.secret)
	for name, f := range map[string]func(map[string]any){
		"cash-mode without remint_commitment": func(m map[string]any) { delete(m, "remint_commitment") },
		"remint_commitment its own":           func(m map[string]any) { m["remint_commitment"] = own },
		"remint_commitment malformed":         func(m map[string]any) { m["remint_commitment"] = "zz" },
	} {
		m := map[string]any{}
		for k, v := range cgood {
			m[k] = v
		}
		f(m)
		wantCode(t, name, s.raw(t, c, nipcash.MethodCashWithdraw, m, ""), nipcash.ErrCodeBadRequest, "")
	}
	res := s.raw(t, h, nipcash.MethodCashWithdraw, good, h.priv)
	if res == nil || res["error"] != nil {
		t.Fatalf("the same request_id after the refusals: %v, want the payout", res)
	}
}

// claimProof signs a kind-23198 claim proof with tags.
func claimProof(t *testing.T, priv string, tags ...[]string) string {
	t.Helper()
	ev, err := nip01.NewSignedEvent(nipcash.KindClaimProof, "", priv, tags...)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ev)
	return string(raw)
}

// CT-WD-06 (CASH-WD-09, CASH-WD-18): steps 1 and 2: no slice NOT_FOUND; a
// claim proof for cash_redeem or for another quote, or an item proof by
// another key, UNAUTHORIZED; once step 2 passes the id is used, also after a
// step-3 refusal.
func ctWd06(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	h := s.pubkeyBill(t, wdAmount, 0)
	q := s.quoteOK(t, h, addr)
	stranger, _ := keypair(t)
	sh := h
	sh.cred = nipcash.BySigning(stranger)
	wantCode(t, "no slice", s.raw(t, h, nipcash.MethodCashWithdraw, withdrawParams(t, sh, q, nil), stranger), nipcash.ErrCodeNotFound, "")

	m := withdrawParams(t, h, q, nil)
	m["identity_event"] = claimProof(t, h.priv, []string{"d", h.tok.WalletPubkey}, []string{"m", "cash_redeem"},
		[]string{"bolt11_hash", strings.Repeat("44", 32)})
	wantCode(t, "claim proof for cash_redeem", s.raw(t, h, nipcash.MethodCashWithdraw, m, h.priv), nipcash.ErrCodeUnauthorized, "")
	q2 := s.quoteOK(t, h, s.address(t, p2wpkh))
	m = withdrawParams(t, h, q, nil)
	m["identity_event"] = claimProof(t, h.priv, []string{"d", h.tok.WalletPubkey}, []string{"m", "cash_withdraw"}, []string{"q", q2.ID})
	wantCode(t, "claim proof for another quote", s.raw(t, h, nipcash.MethodCashWithdraw, m, h.priv), nipcash.ErrCodeUnauthorized, "")
	wantCode(t, "item proof by another key", s.raw(t, h, nipcash.MethodCashWithdraw, withdrawParams(t, h, q, nil), stranger),
		nipcash.ErrCodeUnauthorized, "")

	// Step 3 refuses another Hub's quote; the id is used all the same.
	otherHub, _ := keypair(t)
	foreign := signQuote(t, q.QuoteFields, otherHub)
	m = withdrawParams(t, h, foreign, nil)
	wantCode(t, "another Hub's quote", s.raw(t, h, nipcash.MethodCashWithdraw, m, h.priv), nipcash.ErrCodeRestricted, nipcash.DetailQuoteInvalid)
	again := withdrawParams(t, h, q, nil)
	again["request_id"] = m["request_id"]
	wantCode(t, "the id of a step-3 refusal", s.raw(t, h, nipcash.MethodCashWithdraw, again, h.priv), nipcash.ErrCodeRequestReused, "")
}

// CT-WD-07 (CASH-WD-09, CASH-S-25, CASH-S-26): step 3 in row order with its
// detail; each refusal leaves the slice claimable and its claim proof
// unconsumed.
func ctWd07(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	a, b := s.pubkeyPair(t, wdAmount)
	q := s.quoteOK(t, a, addr)
	otherHub, _ := keypair(t)
	other := s.pubkeyBill(t, wdAmount, 0)
	tampered := *q
	ev := *q.Event
	ev.Tags = slices.Clone(ev.Tags)
	for i, tag := range ev.Tags {
		if tag[0] == "payout_millis" {
			ev.Tags[i] = []string{"payout_millis", "1000"}
		}
	}
	tampered.Event, tampered.PayoutMillis = &ev, 1000
	for name, bad := range map[string]*nipcash.WithdrawQuote{
		"another Hub's quote":  signQuote(t, q.QuoteFields, otherHub),
		"another bill's quote": s.quoteOK(t, other, addr),
		"another slice's":      s.quoteOK(t, b, addr),
		"a tampered quote":     &tampered,
	} {
		wantCode(t, name, s.raw(t, a, nipcash.MethodCashWithdraw, paramsWithQuote(t, a, q, bad), a.priv), nipcash.ErrCodeRestricted, nipcash.DetailQuoteInvalid)
	}
	if row := s.status(t, a, nipcash.ScopeMine).Recipients[0]; row.Claimed {
		t.Fatalf("a step-3 refusal claimed the slice")
	}
	c, ok := s.h.(WithdrawChain)
	if !ok {
		return
	}
	// Each row paired with the next one's defect.
	c.SetUnconfirmedBound(t, 0)
	c.StarveCoins(t, true)
	t.Cleanup(func() { c.SetUnconfirmedBound(t, ^uint64(0)); c.StarveCoins(t, false) })
	expired := s.quoteOK(t, a, addr)
	c.Mine(t, int(expired.HoldsUntil-c.Tip(t))+1)
	wantCode(t, "expired quote", s.raw(t, a, nipcash.MethodCashWithdraw, withdrawParams(t, a, expired, nil), a.priv),
		nipcash.ErrCodeRestricted, nipcash.DetailQuoteExpired)
	own := withdrawParams(t, a, s.quoteOK(t, a, c.HubOwnAddress(t)), nil)
	wantCode(t, "at the bound", s.raw(t, a, nipcash.MethodCashWithdraw, own, a.priv), nipcash.ErrCodeRateLimited, "")
	c.SetUnconfirmedBound(t, ^uint64(0))
	own["request_id"], _ = nipcash.NewRequestID()
	wantCode(t, "starved", s.raw(t, a, nipcash.MethodCashWithdraw, own, a.priv), nipcash.ErrCodeInsufficientBalance, "")
	c.StarveCoins(t, false)
	own["request_id"], _ = nipcash.NewRequestID()
	wantCode(t, "own address", s.raw(t, a, nipcash.MethodCashWithdraw, own, a.priv), nipcash.ErrCodeRestricted, nipcash.DetailOwnAddress)
	// A refused call consumes nothing: its claim proof commits later.
	good := withdrawParams(t, a, s.quoteOK(t, a, addr), nil)
	c.SetUnconfirmedBound(t, 0)
	wantCode(t, "at the bound again", s.raw(t, a, nipcash.MethodCashWithdraw, good, a.priv), nipcash.ErrCodeRateLimited, "")
	c.SetUnconfirmedBound(t, ^uint64(0))
	if row := s.status(t, a, nipcash.ScopeMine).Recipients[0]; row.Claimed {
		t.Fatalf("a step-3 refusal claimed the slice")
	}
	good["request_id"], _ = nipcash.NewRequestID()
	if res := s.raw(t, a, nipcash.MethodCashWithdraw, good, a.priv); res == nil || res["error"] != nil {
		t.Errorf("the claim proof of a refused call did not commit later: %v", res)
	}
}

// CT-WD-27 (CASH-WD-09): step 3 binds the quote to the slice's amount, not
// just its identity. A slice is quoted; its holder moves it in place to
// another key, and the bill's other, smaller slice moves in place to the
// holder's key. The old quote names the same bill and identity, but another
// amount: quote_invalid, and the smaller slice stays claimable.
func ctWd27(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	pa, xa := keypair(t)
	pb, xb := keypair(t)
	_, xalt := keypair(t)
	big, small := uint64(2*wdAmount), uint64(wdAmount)
	tok := s.mint(t, 0, nipcash.Send(nipcash.Pubkey(xa), big), nipcash.Send(nipcash.Pubkey(xb), small))
	a, b := s.holderOf(t, tok), s.holderOf(t, tok)
	a.priv, a.cred, a.amount = pa, nipcash.BySigning(pa), big
	b.priv, b.cred, b.amount = pb, nipcash.BySigning(pb), small
	old := s.quoteOK(t, a, addr)
	if o, _ := s.transfer(t, a, nipcash.CashTransferParams{To: nipcash.Pubkey(xalt)}); o.Result == nil {
		t.Fatalf("in-place transfer of the quoted slice: %+v", o.Error)
	}
	if o, _ := s.transfer(t, b, nipcash.CashTransferParams{To: nipcash.Pubkey(xa)}); o.Result == nil {
		t.Fatalf("in-place transfer of the other slice to the quoted key: %+v", o.Error)
	}
	now := s.holderOf(t, tok)
	now.priv, now.cred, now.amount = pa, nipcash.BySigning(pa), small
	own := s.quoteOK(t, now, addr)
	wantCode(t, "a quote for the same identity at another amount", s.raw(t, now, nipcash.MethodCashWithdraw, paramsWithQuote(t, now, own, old), now.priv),
		nipcash.ErrCodeRestricted, nipcash.DetailQuoteInvalid)
	if row := s.status(t, now, nipcash.ScopeMine).Recipients[0]; row.Claimed {
		t.Fatalf("a quote_invalid refusal claimed the slice")
	}
}

// paramsWithQuote is a cash_withdraw request for h carrying bad as its quote,
// with a claim proof bound to bad's id, so it passes steps 1 and 2 and step 3
// judges the quote. own is a quote for h that builds the rest.
func paramsWithQuote(t *testing.T, h holder, own, bad *nipcash.WithdrawQuote) map[string]any {
	t.Helper()
	m := withdrawParams(t, h, own, nil)
	raw, err := bad.Raw()
	if err != nil {
		t.Fatal(err)
	}
	m["quote"] = raw
	m["identity_event"] = claimProof(t, h.priv, []string{"d", h.tok.WalletPubkey}, []string{"m", nipcash.MethodCashWithdraw}, []string{"q", bad.ID})
	return m
}

// CT-WD-08 (CASH-WD-11, CASH-WD-12, CASH-WD-25): success: queued, signed
// false, final_depth, a receipt that verifies; the slice redeemed; the row's
// withdraw_request_id only for the authorizer's item proof.
func ctWd08(t *testing.T, s *suite) {
	s.withdrawals(t)
	a, b := s.pubkeyPair(t, wdAmount)
	terms := s.wdTerms(t, a)
	p, pc := s.withdrawOK(t, a, s.address(t, p2wpkh))
	if p.State != nipcash.PayoutQueued || p.Signed || p.FinalDepth != uint32(terms.FinalDepth) || p.Tx != "" {
		t.Errorf("reply %+v, want queued, unsigned, final_depth %d", p, terms.FinalDepth)
	}
	if terms.FinalDepth < 6 {
		t.Logf("final_depth %d is below the 6 a Hub SHOULD use", terms.FinalDepth)
	}
	row := s.status(t, a, nipcash.ScopeMine).Recipients[0]
	if !row.Claimed || row.ClaimedAt == nil || row.WithdrawRequestID != pc.RequestID {
		t.Errorf("the authorizer's row %+v, want claimed with withdraw_request_id %s", row, pc.RequestID)
	}
	for _, r := range s.status(t, b, nipcash.ScopeAll).Recipients {
		if r.IdentityValue == row.IdentityValue && (r.WithdrawRequestID != "" || !r.Claimed) {
			t.Errorf("another holder sees %+v: claimed, without withdraw_request_id", r)
		}
	}
}

// CT-WD-09 (CASH-WD-09): races on one slice, exactly one call commits and the
// other is refused (RESTRICTED, or the tombstone of the bill it drained): two
// withdrawals with different ids, in one envelope and in two at once; a
// withdrawal against a cash_redeem (Payee); a withdrawal against a split. And
// a withdrawal whose commit is stalled past its deadline is refused
// BAD_REQUEST, the slice left claimable (Faulty).
func ctWd09(t *testing.T, s *suite) {
	sess := s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	n := 5
	if s.o.Long {
		n = 50
	}
	withdrawOne := func(h holder, q *nipcash.WithdrawQuote) func() client.ItemOutcome {
		return func() client.ItemOutcome {
			ctx, cancel := ctx15()
			defer cancel()
			outs, _ := sess.WithdrawMany(ctx, []client.BatchWithdraw{{ID: "1", Bill: h.bill,
				Params: nipcash.CashWithdrawParams{Quote: q, Credential: h.cred}}}, newMemJournal(), "conformance")
			if len(outs) != 1 || outs[0].Result == nil && outs[0].Error == nil && outs[0].Gone == nil {
				return client.ItemOutcome{State: client.OutcomeNotServed}
			}
			o := outs[0].ItemOutcome
			if outs[0].Result != nil {
				o.State = client.OutcomeResult
			}
			return o
		}
	}
	t.Run("two withdrawals", func(t *testing.T) {
		for i := range n {
			h := s.pubkeyBill(t, wdAmount, 0)
			q := s.quoteOK(t, h, addr)
			if i%2 == 0 {
				ctx, cancel := ctx15()
				outs, _ := sess.WithdrawMany(ctx, []client.BatchWithdraw{{ID: "1", Bill: h.bill, Params: nipcash.CashWithdrawParams{Quote: q, Credential: h.cred}},
					{ID: "2", Bill: h.bill, Params: nipcash.CashWithdrawParams{Quote: q, Credential: h.cred}}}, newMemJournal(), "conformance")
				cancel()
				wins := 0
				for _, o := range outs {
					if o.Result != nil {
						wins++
					}
				}
				if wins != 1 {
					t.Fatalf("race %d: %d withdrawals of one slice in one envelope committed, want exactly 1", i, wins)
				}
				continue
			}
			race(t, i, withdrawOne(h, q), withdrawOne(h, q))
		}
	})
	t.Run("withdraw and cash_redeem", func(t *testing.T) {
		payee, ok := s.h.(Payee)
		if !ok {
			t.Skip("the Hub does not implement Payee")
		}
		for i := range n {
			h := s.pubkeyBill(t, wdAmount, 0)
			net := s.status(t, h, nipcash.ScopeMine).Recipients[0].NetRedeemableMillis
			q := s.quoteOK(t, h, addr)
			inv := payee.Invoice(t, net)
			race(t, i, withdrawOne(h, q), func() client.ItemOutcome {
				ctx, cancel := ctx15()
				defer cancel()
				outs, _ := sess.RedeemMany(ctx, []client.BatchRedeem{{ID: "1", Bill: h.bill,
					Params: nipcash.CashRedeemParams{Invoice: inv, Credential: h.cred}}})
				if len(outs) != 1 {
					return client.ItemOutcome{State: client.OutcomeNotServed}
				}
				if r := outs[0].Result; r != nil && !preimageOf(r.Preimage, inv) {
					t.Errorf("race %d: the redemption's preimage does not hash to the invoice's payment hash", i)
				}
				return outs[0].ItemOutcome
			})
		}
	})
	t.Run("withdraw and split", func(t *testing.T) {
		split := uint64(wdAmount / 4)
		for i := range n {
			h := s.pubkeyBill(t, wdAmount, 0)
			q := s.quoteOK(t, h, addr)
			_, to := keypair(t)
			race(t, i, withdrawOne(h, q), func() client.ItemOutcome {
				ctx, cancel := ctx15()
				defer cancel()
				outs, _ := sess.TransferMany(ctx, []client.BatchTransfer{{ID: "1", Bill: h.bill, Params: nipcash.CashTransferParams{
					Credential: h.cred, To: nipcash.Pubkey(to), CurrentAmount: h.amount, SplitAmount: &split}}}, newMemJournal(), "conformance")
				if len(outs) != 1 {
					return client.ItemOutcome{State: client.OutcomeNotServed}
				}
				return outs[0].ItemOutcome
			})
		}
	})
	t.Run("stalled commit", func(t *testing.T) {
		f, ok := s.h.(Faulty)
		if !ok {
			t.Skip("the Hub does not implement Faulty")
		}
		h := s.pubkeyBill(t, wdAmount, 0)
		q := s.quoteOK(t, h, addr)
		e, nonce, replyTo, _ := s.newEnvelope(t)
		notAfter := time.Now().Add(3 * time.Second).Unix()
		e["not_after"] = notAfter
		e["items"] = []transport.Item{s.rawItem(t, h, "1", nipcash.MethodCashWithdraw, withdrawParams(t, h, q, nil), h.priv, nonce, notAfter)}
		l := s.listen(t, replyTo)
		f.InjectFault(t, FaultStallCommit)
		cleared := false
		t.Cleanup(func() {
			if !cleared {
				f.InjectFault(t, FaultNone)
			}
		})
		r := s.wrap(t, e, "")
		s.publish(t, 0, r.ev)
		time.Sleep(time.Until(time.Unix(notAfter+2, 0)))
		f.InjectFault(t, FaultNone)
		cleared = true
		got := l.wait(1, s.quiet()+5*time.Second)
		if len(got) == 0 {
			t.Fatal("no reply to a call whose commit was stalled past its deadline, want BAD_REQUEST")
		}
		var results []map[string]json.RawMessage
		if err := json.Unmarshal(r.open(t, got[0].ev)["results"], &results); err != nil || len(results) != 1 {
			t.Fatalf("results %v: %v", results, err)
		}
		if code := resultCode(results[0]); code != nipcash.ErrCodeBadRequest {
			t.Fatalf("a commit stalled past its deadline answered %v, want BAD_REQUEST", results[0])
		}
		// Nothing committed: the slice is still claimable.
		s.withdrawOK(t, h, addr)
	})
}

// race runs a and b at once on one slice: exactly one commits, and the other
// is refused RESTRICTED or with the tombstone of the bill the winner drained.
func race(t *testing.T, i int, a, b func() client.ItemOutcome) {
	t.Helper()
	var outs [2]client.ItemOutcome
	var wg sync.WaitGroup
	for k, f := range []func() client.ItemOutcome{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[k] = f()
		}()
	}
	wg.Wait()
	wins := 0
	for _, o := range outs {
		switch {
		case o.State == client.OutcomeResult:
			wins++
		case o.Gone != nil, o.Error != nil && o.Error.Code == nipcash.ErrCodeRestricted:
		default:
			t.Errorf("race %d: the losing call answered %+v, want RESTRICTED or the tombstone", i, o)
		}
	}
	if wins != 1 {
		t.Fatalf("race %d: %d calls on one slice committed, want exactly 1", i, wins)
	}
}

// preimageOf reports preimage hashing to bolt11's payment hash.
func preimageOf(preimage, bolt11 string) bool {
	inv, err := nip57.DecodeBolt11(bolt11)
	raw, herr := hex.DecodeString(preimage)
	if err != nil || herr != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]) == inv.PaymentHash
}

// CT-WD-10 (CASH-WD-22): a destroyed bill answers a quote and a withdrawal
// with its tombstone (withdraw_request_id only for the authorizer); a cancel
// request is not tombstoned.
func ctWd10(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	h := s.pubkeyBill(t, wdAmount, 0)
	q := s.quoteOK(t, h, addr)
	_, pc := s.withdrawOK(t, h, addr)
	o := s.quote(t, h, addr, nil)
	if o.Gone == nil || o.Gone.WithdrawRequestID != pc.RequestID {
		t.Errorf("the authorizer's quote on a destroyed bill: %+v, want the tombstone with withdraw_request_id", o.ItemOutcome)
	}
	stranger, _ := keypair(t)
	res := s.raw(t, h, nipcash.MethodCashWithdrawQuote, quoteParams(addr, nil), stranger)
	if tomb, ok := nipcash.ParseTombstone(res["result"]); !ok || tomb.WithdrawRequestID != "" {
		t.Errorf("another key's quote on a destroyed bill: %v, want the tombstone without withdraw_request_id", res)
	}
	res = s.raw(t, h, nipcash.MethodCashWithdraw, withdrawParams(t, h, q, nil), h.priv)
	if _, ok := nipcash.ParseTombstone(res["result"]); !ok {
		t.Errorf("a withdrawal on a destroyed bill: %v, want the tombstone", res)
	}
	if c := s.cancel(t, h, pc); c.Gone != nil || c.State == client.OutcomeNotServed {
		t.Errorf("a cancel request on a destroyed bill: %+v, want it served", c.ItemOutcome)
	}
}

// waitPayout looks pc up until cond holds, mining a block between tries when
// mine is set, else waiting; it fails after 40 tries.
func (s *suite) waitPayout(t *testing.T, h holder, pc nipcash.PendingCall, mine bool, cond func(*nipcash.Payout) bool) *nipcash.Payout {
	t.Helper()
	var p *nipcash.Payout
	for range 40 {
		p = s.payoutNow(t, h, pc)
		if cond(p) {
			return p
		}
		if mine {
			s.chain().Mine(t, 1)
		} else {
			time.Sleep(200 * time.Millisecond)
		}
	}
	t.Fatalf("the payout never reached the state the case waits for: %s %s depth %v", p.State, p.Txid, p.Depth)
	return nil
}

func isState(st nipcash.PayoutState) func(*nipcash.Payout) bool {
	return func(p *nipcash.Payout) bool { return p.State == st }
}

var stateRank = map[nipcash.PayoutState]int{nipcash.PayoutQueued: 0, nipcash.PayoutBroadcast: 1, nipcash.PayoutConfirmed: 2, nipcash.PayoutFinal: 3}

// CT-WD-11 (CASH-WD-19, CASH-WD-20): a lookup names the bill and its done is
// the payout now, through queued, broadcast, confirmed and final, whatever
// deadline it carries, after the bill was destroyed; another signer is
// UNAUTHORIZED; a cash-authorized call is looked up without its secret first.
func ctWd11(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	h := s.pubkeyBill(t, wdAmount, 0)
	_, pc := s.withdrawOK(t, h, addr)
	seen := map[nipcash.PayoutState]bool{}
	last := -1
	s.waitPayout(t, h, pc, true, func(p *nipcash.Payout) bool {
		if stateRank[p.State] < last {
			t.Errorf("the payout went back from rank %d to %s", last, p.State)
		}
		last = stateRank[p.State]
		seen[p.State] = true
		return p.State == nipcash.PayoutFinal
	})
	if !seen[nipcash.PayoutConfirmed] && !seen[nipcash.PayoutBroadcast] {
		t.Errorf("lookups never showed the payout between queued and final: %v", seen)
	}
	for _, d := range []int64{1, time.Now().Unix() - 3600, time.Now().Unix() + 60} {
		old := pc
		old.Deadline = d
		if lo := s.lookup(t, h, old, ""); lo.Status != nipcash.LookupDone {
			t.Errorf("lookup with deadline %d: %+v, want done", d, lo)
		}
	}
	stranger, _ := keypair(t)
	sh := h
	sh.priv = stranger
	if lo := s.lookup(t, sh, pc, ""); lo.Code != nipcash.ErrCodeUnauthorized {
		t.Errorf("lookup by another signer: %+v, want UNAUTHORIZED", lo)
	}
	c := s.cashBill(t, wdAmount)
	_, cpc := s.withdrawOK(t, c, addr)
	if lo := s.lookup(t, c, cpc, ""); lo.Code != nipcash.ErrCodeUnauthorized {
		t.Errorf("a cash-authorized call looked up without its secret: %+v, want UNAUTHORIZED", lo)
	}
	if lo := s.lookup(t, c, cpc, c.secret); lo.Status != nipcash.LookupDone {
		t.Errorf("with its secret: %+v, want done", lo)
	}
}

// heldPayout withdraws h and gets the payout broadcast (mining a block at a
// time), returning the call and its txid.
func (s *suite) heldPayout(t *testing.T, h holder, addr string) (nipcash.PendingCall, string) {
	t.Helper()
	_, pc := s.withdrawOK(t, h, addr)
	p := s.waitPayout(t, h, pc, true, func(p *nipcash.Payout) bool { return p.Txid != "" })
	return pc, p.Txid
}

// untilCancelServed advances the clock six hours at a time until a cancel
// request for pc is no longer RESTRICTED, and returns its answer.
func (s *suite) untilCancelServed(t *testing.T, h holder, pc nipcash.PendingCall) client.WithdrawCancelOutcome {
	t.Helper()
	for range 60 {
		o := s.cancel(t, h, pc)
		if o.Error == nil || o.Error.Code != nipcash.ErrCodeRestricted {
			return o
		}
		s.advance(t, 6*time.Hour)
	}
	t.Fatalf("a cancel request was still RESTRICTED 15 days on")
	return client.WithdrawCancelOutcome{}
}

// CT-WD-12 (CASH-WD-19): retention: a record not ended is kept past D+H; one
// ended is answered expired after its tombstone window (a window under 400
// days); one whose cancellation re-minted a live bill is kept (Faulty); a
// signer failure is INTERNAL and commits nothing (Faulty).
func ctWd12(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	h := s.pubkeyBill(t, wdAmount, 0)
	pc, txid := s.heldPayout(t, h, addr)
	s.chain().Withhold(t, txid, true)
	s.advance(t, time.Duration(s.limits.MaxRequestAgeSeconds+120)*time.Second)
	if lo := s.lookup(t, h, pc, ""); lo.Status != nipcash.LookupDone {
		t.Errorf("a record not ended, past D+H: %+v, want done", lo)
	}
	s.chain().Withhold(t, txid, false)
	s.waitPayout(t, h, pc, true, isState(nipcash.PayoutFinal))

	f, faulty := s.h.(Faulty)
	var rpc nipcash.PendingCall
	var r holder
	if faulty {
		f.InjectFault(t, FaultHoldSign)
		r = s.pubkeyBill(t, wdAmount, 0)
		_, rpc = s.withdrawOK(t, r, addr)
		s.advance(t, 2*24*time.Hour)
		f.InjectFault(t, FaultNone)
		s.waitPayout(t, r, rpc, false, isState(nipcash.PayoutCancelled))
	}
	s.advance(t, 400*24*time.Hour)
	switch lo := s.lookup(t, h, pc, ""); {
	case lo.NotServed:
		t.Logf("a final record past its tombstone window: omitted; a Hub that can derive the pairing key SHOULD answer expired")
	case lo.Status != nipcash.LookupExpired:
		t.Errorf("a final record past its tombstone window: %+v, want expired", lo)
	}
	if faulty {
		if lo := s.lookup(t, r, rpc, ""); lo.Status != nipcash.LookupDone {
			t.Errorf("a record whose re-minted bill lives: %+v, want done", lo)
		}
		g := s.pubkeyBill(t, wdAmount, 0)
		gq := s.quoteOK(t, g, addr)
		f.InjectFault(t, FaultBreakSigner)
		qo := s.quote(t, g, addr, nil)
		wo, _ := s.withdraw(t, g, gq)
		f.InjectFault(t, FaultNone)
		wantOutcome(t, "quote, signer broken", qo.ItemOutcome, nipcash.ErrCodeInternal, "")
		wantOutcome(t, "withdraw, signer broken", wo.ItemOutcome, nipcash.ErrCodeInternal, "")
		if row := s.status(t, g, nipcash.ScopeMine).Recipients[0]; row.Claimed {
			t.Errorf("a withdrawal answered INTERNAL claimed the slice")
		}
	}
}

// CT-WD-13 (CASH-WD-14, CASH-WD-22): a cancel request's shape: an extra field
// BAD_REQUEST; no record NOT_FOUND; repeated, the same answer, never
// REQUEST_REUSED, and its request_id never marked; another signer
// UNAUTHORIZED; served after the bill is destroyed.
func ctWd13(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	h := s.pubkeyBill(t, wdAmount, 0)
	_, pc := s.withdrawOK(t, h, addr)
	wantCode(t, "extra field", s.raw(t, h, nipcash.MethodCashWithdraw, map[string]any{"cancel": true, "request_id": pc.RequestID, "x": 1}, h.priv),
		nipcash.ErrCodeBadRequest, "")
	fresh, _ := nipcash.NewRequestID()
	wantCode(t, "no record", s.raw(t, h, nipcash.MethodCashWithdraw, map[string]any{"cancel": true, "request_id": fresh}, h.priv),
		nipcash.ErrCodeNotFound, "")
	first := s.cancel(t, h, pc)
	second := s.cancel(t, h, pc)
	c1, _ := codeOf(first.ItemOutcome)
	c2, _ := codeOf(second.ItemOutcome)
	if c1 != c2 || c2 == nipcash.ErrCodeRequestReused || (c1 == "" && first.Result == nil) {
		t.Errorf("a repeated cancel request: %+v then %+v", first.ItemOutcome, second.ItemOutcome)
	}
	stranger, _ := keypair(t)
	wantCode(t, "another signer", s.raw(t, h, nipcash.MethodCashWithdraw, map[string]any{"cancel": true, "request_id": pc.RequestID}, stranger),
		nipcash.ErrCodeUnauthorized, "")
	// The cancel request's id was never marked: a call with it commits.
	g := s.pubkeyBill(t, wdAmount, 0)
	p := withdrawParams(t, g, s.quoteOK(t, g, addr), nil)
	p["request_id"] = fresh
	if res := s.raw(t, g, nipcash.MethodCashWithdraw, p, g.priv); res == nil || res["error"] != nil {
		t.Errorf("a call with the request_id a cancel request carried: %v, want the payout", res)
	}
}

// CT-WD-14 (CASH-WD-14): a cancel request before sent_by + 604800 is
// RESTRICTED; at it, on a broadcast payout, it is answered with the payout,
// still broadcast.
func ctWd14(t *testing.T, s *suite) {
	s.withdrawals(t)
	a, b := s.pubkeyPair(t, wdAmount)
	pc, txid := s.heldPayout(t, a, s.address(t, p2wpkh))
	s.chain().Withhold(t, txid, true)
	t.Cleanup(func() { s.chain().Withhold(t, txid, false) })
	var committed int64
	for _, r := range s.status(t, b, nipcash.ScopeAll).Recipients {
		if r.ClaimedAt != nil {
			committed = *r.ClaimedAt
		}
	}
	p := s.payoutNow(t, a, pc)
	if committed == 0 {
		t.Fatal("no claimed_at on the withdrawn row")
	}
	s.advance(t, time.Duration(p.SentBy+nipcash.CancelRequestAfter-committed-3600)*time.Second)
	wantOutcome(t, "an hour before sent_by + 7 days", s.cancel(t, a, pc).ItemOutcome, nipcash.ErrCodeRestricted, "")
	s.advance(t, 3601*time.Second)
	o := s.cancel(t, a, pc)
	if o.Result == nil || o.Result.State != nipcash.PayoutBroadcast {
		t.Errorf("a cancel request at sent_by + 7 days: %+v, want the payout, still broadcast", o)
	}
}

// CT-WD-15 (CASH-WD-10, CASH-WD-27): the payout is broadcast; its version pays
// exactly payout_millis to the address; tx's id is txid and vout is right;
// signed is true from then on.
func ctWd15(t *testing.T, s *suite) {
	s.withdrawals(t)
	h := s.pubkeyBill(t, wdAmount, 0)
	pc, txid := s.heldPayout(t, h, s.address(t, p2wpkh))
	p := s.payoutNow(t, h, pc)
	if !p.Signed || p.Tx == "" || p.Txid != txid {
		t.Fatalf("broadcast payout %+v", p)
	}
	if err := nipcash.VerifyPayoutTx(p.Tx, p.Txid, *p.Vout, p.Address, "", p.PayoutMillis); err != nil {
		t.Errorf("the payout's tx: %v", err)
	}
	if raw, _ := s.chain().Tx(t, txid); raw != p.Tx {
		t.Errorf("the chain's transaction %s is not the payout's tx", txid)
	}
	s.waitPayout(t, h, pc, true, func(p *nipcash.Payout) bool {
		if !p.Signed {
			t.Errorf("signed went back to false")
		}
		return p.State == nipcash.PayoutFinal
	})
}

func decodeTx(t *testing.T, raw string) *wire.MsgTx {
	t.Helper()
	b, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	return &tx
}

func sharesInput(a, b *wire.MsgTx) bool {
	for _, x := range a.TxIn {
		for _, y := range b.TxIn {
			if x.PreviousOutPoint == y.PreviousOutPoint {
				return true
			}
		}
	}
	return false
}

// CT-WD-16 (CASH-WD-10, CASH-S-27): a version kept out of blocks is bumped:
// the new version spends an input of the earlier one and keeps the payout
// output; one version confirms.
func ctWd16(t *testing.T, s *suite) {
	s.withdrawals(t)
	h := s.pubkeyBill(t, wdAmount, 0)
	pc, v1 := s.heldPayout(t, h, s.address(t, p2wpkh))
	s.chain().Withhold(t, v1, true)
	t.Cleanup(func() { s.chain().Withhold(t, v1, false) })
	p := s.waitPayout(t, h, pc, true, func(p *nipcash.Payout) bool { return p.Txid != v1 })
	raw1, _ := s.chain().Tx(t, v1)
	t1, t2 := decodeTx(t, raw1), decodeTx(t, p.Tx)
	if !sharesInput(t1, t2) {
		t.Errorf("the bump %s spends no input of %s", p.Txid, v1)
	}
	out1, out2 := t1.TxOut[*p.Vout], t2.TxOut[*p.Vout]
	if !bytes.Equal(out1.PkScript, out2.PkScript) || out1.Value != out2.Value {
		t.Errorf("the bump changed the payout output")
	}
	s.waitPayout(t, h, pc, true, isState(nipcash.PayoutFinal))
	if _, d := s.chain().Tx(t, v1); d != 0 {
		t.Errorf("both versions confirmed")
	}
}

// CT-WD-17 (CASH-WD-10, CASH-WD-13): after a reorganisation the payout is
// broadcast again with the identical transaction; a version that confirmed
// once is never replaced, only bumped through a child.
func ctWd17(t *testing.T, s *suite) {
	s.withdrawals(t)
	h := s.pubkeyBill(t, wdAmount, 0)
	pc, txid := s.heldPayout(t, h, s.address(t, p2wpkh))
	s.waitPayout(t, h, pc, true, isState(nipcash.PayoutConfirmed))
	s.chain().Withhold(t, txid, true)
	t.Cleanup(func() { s.chain().Withhold(t, txid, false) })
	s.chain().Reorg(t, 1)
	p := s.payoutNow(t, h, pc)
	if p.State != nipcash.PayoutBroadcast || p.Txid != txid {
		t.Errorf("after the reorganisation: %s %s, want broadcast %s", p.State, p.Txid, txid)
	}
	s.chain().Mine(t, 10)
	if p := s.payoutNow(t, h, pc); p.Txid != txid {
		t.Errorf("a version that confirmed once was replaced by %s", p.Txid)
	}
	s.chain().Withhold(t, txid, false)
	p = s.waitPayout(t, h, pc, true, isState(nipcash.PayoutFinal))
	if p.Txid != txid {
		t.Errorf("final under %s, want %s", p.Txid, txid)
	}
}

// CT-WD-18 (CASH-WD-10): a version evicted from the mempool is rebroadcast or
// bumped, and the payout confirms.
func ctWd18(t *testing.T, s *suite) {
	s.withdrawals(t)
	h := s.pubkeyBill(t, wdAmount, 0)
	pc, txid := s.heldPayout(t, h, s.address(t, p2wpkh))
	s.chain().EvictTx(t, txid)
	s.waitPayout(t, h, pc, true, isState(nipcash.PayoutFinal))
}

// checkRemint checks a cancelled payout's re-minted bill: a token of this Hub
// for new_wallet_pubkey, one slice of the whole amount bound as want.
func (s *suite) checkRemint(t *testing.T, p *nipcash.Payout, cred nipcash.Credential, amount uint64) holder {
	t.Helper()
	if p.NewWalletToken.Token == "" {
		t.Fatalf("cancelled without a re-minted token: %+v", p)
	}
	tok, err := nipcash.Decode(p.NewWalletToken.Token)
	if err != nil {
		t.Fatalf("re-minted token: %v", err)
	}
	minter, ok := nipcash.VerifyProvenance(tok)
	if !ok || !nipcash.HubIdentityEqual(s.nodeXOnly, minter) || tok.WalletPubkey != p.NewWalletPubkey {
		t.Errorf("the re-minted token is not this Hub's bill %s", p.NewWalletPubkey)
	}
	r := s.holderOf(t, tok)
	r.cred, r.amount = cred, amount
	r.priv = ""
	return r
}

// CT-WD-19 (CASH-WD-14, CASH-WD-15): no about-to-sign record by sent_by + 1
// day: cancelled, the whole amount re-minted to remint_commitment with the
// slice's fee terms and expiry; the source's tombstone says transferred.
func ctWd19(t *testing.T, s *suite) {
	s.withdrawals(t)
	f := s.h.(Faulty)
	f.InjectFault(t, FaultHoldSign)
	t.Cleanup(func() { f.InjectFault(t, FaultNone) })
	c := s.cashBill(t, wdAmount)
	row := s.status(t, c, nipcash.ScopeMine).Recipients[0]
	addr := s.address(t, p2wpkh)
	_, pc := s.withdrawOK(t, c, addr)
	if len(pc.Secrets) != 1 {
		t.Fatalf("no re-mint secret written ahead")
	}
	for range 10 {
		if s.payoutNow(t, c, pc).State == nipcash.PayoutCancelled {
			break
		}
		s.advance(t, 6*time.Hour)
	}
	p := s.payoutNow(t, c, pc)
	if p.State != nipcash.PayoutCancelled {
		t.Fatalf("no about-to-sign record a day after sent_by: %s, want cancelled", p.State)
	}
	r := s.checkRemint(t, p, nipcash.BySecret(pc.Secrets[0].Secret), wdAmount)
	r.secret = pc.Secrets[0].Secret
	nr := s.status(t, r, nipcash.ScopeMine).Recipients[0]
	commit, _ := nipcash.CashCommitment(r.secret)
	if nr.IdentityType != "cash" || !nipcash.CommitmentsEqual(nr.IdentityValue, commit) || nr.AmountMillis != wdAmount ||
		nr.RedeemFeeMillis != row.RedeemFeeMillis || nr.MinTransferMillis != row.MinTransferMillis || nr.ExpiresAt != row.ExpiresAt {
		t.Errorf("re-minted row %+v, from %+v", nr, row)
	}
	if o := s.quote(t, c, addr, nil); o.Gone == nil || o.Gone.Reason != nipcash.ReasonTransferred {
		t.Errorf("the source bill's tombstone: %+v, want transferred", o.ItemOutcome)
	}
}

// CT-WD-20 (CASH-WD-14): an about-to-sign record and nothing broadcast
// (FaultCrashAfterSign): from sent_by + 1 day the Hub invalidates, then
// cancels once the invalidation is final.
func ctWd20(t *testing.T, s *suite) {
	s.withdrawals(t)
	f := s.h.(Faulty)
	f.InjectFault(t, FaultCrashAfterSign)
	t.Cleanup(func() { f.InjectFault(t, FaultNone) })
	h := s.pubkeyBill(t, wdAmount, 0)
	_, pc := s.withdrawOK(t, h, s.address(t, p2wpkh))
	p := s.waitPayout(t, h, pc, true, func(p *nipcash.Payout) bool { return p.Signed })
	if p.State != nipcash.PayoutQueued || p.Txid != "" {
		t.Fatalf("signed, never broadcast: %+v", p)
	}
	for range 10 {
		s.advance(t, 6*time.Hour)
		s.chain().Mine(t, 1)
	}
	p = s.waitPayout(t, h, pc, true, func(p *nipcash.Payout) bool { return p.State != nipcash.PayoutQueued })
	if p.State != nipcash.PayoutCancelled {
		t.Fatalf("after sent_by + 1 day and the invalidation: %s, want cancelled", p.State)
	}
	s.checkRemint(t, p, h.cred, wdAmount)
}

// CT-WD-21 (CASH-WD-11, CASH-WD-14, CASH-WD-15): a cancel request 7 days after
// sent_by on a version kept out of blocks: invalidated, then cancelled; the
// answers carry the re-minted bill and no transaction; a pubkey and a
// connection_key re-mint are encrypted to the claim-proof signer, a cash-mode
// one is bound to remint_commitment and the old secret is refused on it.
func ctWd21(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	holders := []holder{s.pubkeyBill(t, wdAmount, 0), s.ckBill(t, wdAmount), s.cashBill(t, wdAmount)}
	var pcs []nipcash.PendingCall
	for _, h := range holders {
		pc, txid := s.heldPayout(t, h, addr)
		s.chain().Withhold(t, txid, true)
		pcs = append(pcs, pc)
	}
	for i, h := range holders {
		o := s.untilCancelServed(t, h, pcs[i])
		if o.Result == nil || o.Result.State != nipcash.PayoutBroadcast {
			t.Errorf("holder %d: the cancel answer %+v, want broadcast while the invalidation confirms", i, o)
		}
	}
	for i, h := range holders {
		p := s.waitPayout(t, h, pcs[i], true, isState(nipcash.PayoutCancelled))
		r := s.checkRemint(t, p, h.cred, wdAmount)
		if p.Tx != "" || p.Txid != "" || p.Vout != nil || p.Depth != nil {
			t.Errorf("holder %d: a cancelled payout carries a transaction", i)
		}
		o := s.cancel(t, h, pcs[i])
		if o.Result == nil || o.Result.State != nipcash.PayoutCancelled || o.Result.NewWalletPubkey != p.NewWalletPubkey {
			t.Errorf("holder %d: the cancel answer after the cancellation: %+v", i, o.ItemOutcome)
		}
		if h.secret == "" {
			if _, err := (nipcash.CashWithdrawParams{Credential: nipcash.BySigning(mustKey(t))}).ParseLookupResult(s.lookup(t, h, pcs[i], "").Result); err == nil {
				t.Errorf("holder %d: the re-minted token decrypts with another key", i)
			}
			continue
		}
		rs := pcs[i].Secrets[0].Secret
		commit, _ := nipcash.CashCommitment(rs)
		r.secret, r.cred = rs, nipcash.BySecret(rs)
		if row := s.status(t, r, nipcash.ScopeMine).Recipients[0]; !nipcash.CommitmentsEqual(row.IdentityValue, commit) {
			t.Errorf("the cash-mode re-mint is not bound to remint_commitment")
		}
		rq := s.quoteOK(t, r, addr)
		old := r
		old.cred = nipcash.BySecret(h.secret)
		if wo, _ := s.withdraw(t, old, rq); wo.Error == nil || wo.Error.Code != nipcash.ErrCodeUnauthorized {
			t.Errorf("the old secret on the re-minted bill: %+v, want UNAUTHORIZED", wo.ItemOutcome)
		}
	}
}

// CT-WD-22 (CASH-WD-26): a re-minted slice (a payout cancelled for want of an
// about-to-sign record, as CT-WD-19): the owner's delete of its wallet is
// refused and, through SliceRemover, so is the slice's removal; the
// withdrawal's record stays while the slice is live, past its deadline plus
// H and the tombstone window.
func ctWd22(t *testing.T, s *suite) {
	s.withdrawals(t)
	f := s.h.(Faulty)
	f.InjectFault(t, FaultHoldSign)
	t.Cleanup(func() { f.InjectFault(t, FaultNone) })
	h := s.pubkeyBill(t, wdAmount, 0)
	_, pc := s.withdrawOK(t, h, s.address(t, p2wpkh))
	for range 10 {
		if s.payoutNow(t, h, pc).State == nipcash.PayoutCancelled {
			break
		}
		s.advance(t, 6*time.Hour)
	}
	p := s.payoutNow(t, h, pc)
	if p.State != nipcash.PayoutCancelled {
		t.Fatalf("no about-to-sign record a day after sent_by: %s, want cancelled", p.State)
	}
	r := s.checkRemint(t, p, h.cred, wdAmount)
	pub, err := utils.GetPublicKey(h.priv)
	if err != nil {
		t.Fatal(err)
	}
	live := func(what string) {
		t.Helper()
		st := s.status(t, r, nipcash.ScopeMine)
		if st.Tombstone != nil || len(st.Recipients) != 1 || st.Recipients[0].Claimed || st.Recipients[0].AmountMillis != wdAmount {
			t.Fatalf("after %s the re-minted slice is %+v, want it live and unclaimed", what, st)
		}
	}
	s.h.(Admin).DeleteBill(t, r.tok.WalletPubkey)
	live("the owner's delete of its wallet")
	if rm, ok := s.h.(SliceRemover); ok {
		if rm.RemoveSlice(t, r.tok.WalletPubkey, "pubkey", pub) == nil {
			t.Errorf("the owner removed a re-minted slice")
		}
		live("the owner's removal of the slice")
	} else {
		t.Log("the Hub does not implement SliceRemover: the removal is not exercised")
	}
	s.advance(t, 30*24*time.Hour)
	live("30 days")
	if p := s.payoutNow(t, h, pc); p.State != nipcash.PayoutCancelled || p.NewWalletPubkey != r.tok.WalletPubkey {
		t.Errorf("the record of a payout whose re-minted slice lives: %+v", p)
	}
}

// CT-WD-23 (CASH-WD-16): the state notice, kind 23189 by a fresh key with
// only ["p", notify], on the relay the call arrived on, at least 600 s after
// the first broadcast and none at confirmed or final; and at a cancellation
// (Faulty).
func ctWd23(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	h := s.pubkeyBill(t, wdAmount, 0)
	q := s.quoteOK(t, h, addr)
	params := withdrawParams(t, h, q, nil)
	notify := params["notify"].(string)
	l := s.listenNotices(t, notify)
	if res := s.raw(t, h, nipcash.MethodCashWithdraw, params, h.priv); res == nil || res["error"] != nil {
		t.Fatalf("withdraw: %v", res)
	}
	pc := nipcash.PendingCall{RequestID: params["request_id"].(string), Method: nipcash.MethodCashWithdraw, Target: h.tok.WalletPubkey,
		Deadline: time.Now().Unix() + 60, HubIdentity: s.nodeXOnly}
	s.waitPayout(t, h, pc, true, func(p *nipcash.Payout) bool { return p.State != nipcash.PayoutQueued })
	s.advance(t, 599*time.Second)
	if got := l.wait(1, s.quiet()/2); len(got) > 0 {
		t.Errorf("a notice within 599 s of the broadcast")
	}
	s.advance(t, 601*time.Second)
	got := l.wait(1, s.quiet())
	if len(got) != 1 {
		t.Fatalf("%d notices 20 minutes after the broadcast, want 1", len(got))
	}
	ev := got[0].ev
	if got[0].relay != 0 || ev.Kind != 23189 || ev.PubKey == s.nodeXOnly || ev.PubKey == s.inbox ||
		len(ev.Tags) != 1 || len(ev.Tags[0]) != 2 || ev.Tags[0][0] != "p" || ev.Tags[0][1] != notify {
		t.Errorf("notice on relay %d: kind %d by %s, tags %v", got[0].relay, ev.Kind, ev.PubKey, ev.Tags)
	}
	s.waitPayout(t, h, pc, true, isState(nipcash.PayoutFinal))
	s.advance(t, 30*time.Minute)
	if got := l.wait(2, s.quiet()); len(got) > 1 {
		t.Errorf("a notice at confirmed or final")
	}
	f, ok := s.h.(Faulty)
	if !ok {
		return
	}
	f.InjectFault(t, FaultHoldSign)
	t.Cleanup(func() { f.InjectFault(t, FaultNone) })
	g := s.pubkeyBill(t, wdAmount, 0)
	gp := withdrawParams(t, g, s.quoteOK(t, g, addr), nil)
	gl := s.listenNotices(t, gp["notify"].(string))
	if res := s.raw(t, g, nipcash.MethodCashWithdraw, gp, g.priv); res == nil || res["error"] != nil {
		t.Fatalf("withdraw: %v", res)
	}
	gpc := nipcash.PendingCall{RequestID: gp["request_id"].(string), Method: nipcash.MethodCashWithdraw, Target: g.tok.WalletPubkey,
		Deadline: time.Now().Unix() + 60, HubIdentity: s.nodeXOnly}
	for range 10 {
		if s.payoutNow(t, g, gpc).State == nipcash.PayoutCancelled {
			break
		}
		s.advance(t, 6*time.Hour)
	}
	s.advance(t, 20*time.Minute)
	if got := gl.wait(1, s.quiet()); len(got) != 1 || got[0].relay != 0 {
		t.Errorf("%d notices after the cancellation, want 1 on the arrival relay", len(got))
	}
}

// listenNotices subscribes to kind-23189 notices tagged notify on every relay.
func (s *suite) listenNotices(t *testing.T, notify string) *listener {
	t.Helper()
	return s.listenKind(t, 23189, notify)
}

// CT-WD-24 (CASH-WD-26): the Cash Hub's teardown is refused while a payout is
// not final or cancelled, and while its record is kept; allowed after.
func ctWd24(t *testing.T, s *suite) {
	s.withdrawals(t)
	d := s.h.(HubDeleter)
	h := s.pubkeyBill(t, wdAmount, 0)
	_, pc := s.withdrawOK(t, h, s.address(t, p2wpkh))
	if d.DeleteHub(t, true) == nil {
		t.Fatalf("teardown allowed with a payout queued")
	}
	s.waitPayout(t, h, pc, true, isState(nipcash.PayoutFinal))
	if d.DeleteHub(t, true) == nil {
		t.Errorf("teardown allowed while a final payout's record is kept")
	}
	s.advance(t, 400*24*time.Hour)
	if err := d.DeleteHub(t, true); err != nil {
		t.Errorf("teardown refused once the record ended (tombstone window under 400 days): %v", err)
	}
}

// CT-WD-25 (CASH-WD-10): a Hub restarted after the about-to-sign record, and
// one restarted after a broadcast, resumes: one version confirms and it pays
// exactly the payout.
func ctWd25(t *testing.T, s *suite) {
	s.withdrawals(t)
	f := s.h.(Faulty)
	t.Cleanup(func() { f.InjectFault(t, FaultNone) })
	addr := s.address(t, p2wpkh)
	f.InjectFault(t, FaultCrashAfterSign)
	h := s.pubkeyBill(t, wdAmount, 0)
	_, pc := s.withdrawOK(t, h, addr)
	s.waitPayout(t, h, pc, true, func(p *nipcash.Payout) bool { return p.Signed })
	f.InjectFault(t, FaultNone)
	p := s.waitPayout(t, h, pc, true, isState(nipcash.PayoutFinal))
	if err := nipcash.VerifyPayoutTx(p.Tx, p.Txid, *p.Vout, p.Address, "", p.PayoutMillis); err != nil {
		t.Errorf("restarted after the record: %v", err)
	}
	g := s.pubkeyBill(t, wdAmount, 0)
	gpc, txid := s.heldPayout(t, g, addr)
	f.InjectFault(t, FaultCrashAfterSign)
	f.InjectFault(t, FaultNone)
	p = s.waitPayout(t, g, gpc, true, isState(nipcash.PayoutFinal))
	if err := nipcash.VerifyPayoutTx(p.Tx, p.Txid, *p.Vout, p.Address, "", p.PayoutMillis); err != nil {
		t.Errorf("restarted after the broadcast: %v", err)
	}
	if p.Txid != txid {
		if _, d := s.chain().Tx(t, txid); d != 0 {
			t.Errorf("two versions of one payout confirmed")
		}
	}
}

// CT-WD-26 (CASH-WD-10, CASH-WD-14; review 3): a payout's only version
// confirms once and is reorganised out: broadcast again, the identical
// transaction, no bump replacing it; a cancel request 7 days after sent_by has
// it invalidated and cancelled, re-minted once. In a variant the old version
// confirms again before any cancel request: final, no re-mint.
func ctWd26(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	run := func(confirmAgain bool) {
		h := s.pubkeyBill(t, wdAmount, 0)
		pc, txid := s.heldPayout(t, h, addr)
		s.waitPayout(t, h, pc, true, isState(nipcash.PayoutConfirmed))
		s.chain().Withhold(t, txid, true)
		s.chain().Reorg(t, 1)
		s.chain().Mine(t, 8)
		if p := s.payoutNow(t, h, pc); p.State != nipcash.PayoutBroadcast || p.Txid != txid {
			t.Fatalf("after the reorganisation: %s %s, want broadcast %s", p.State, p.Txid, txid)
		}
		if confirmAgain {
			s.chain().Withhold(t, txid, false)
			s.waitPayout(t, h, pc, true, isState(nipcash.PayoutFinal))
			if o := s.untilCancelServed(t, h, pc); o.Result == nil || o.Result.State != nipcash.PayoutFinal {
				t.Errorf("a cancel request on a final payout: %+v", o.ItemOutcome)
			}
			return
		}
		s.untilCancelServed(t, h, pc)
		p := s.waitPayout(t, h, pc, true, isState(nipcash.PayoutCancelled))
		s.checkRemint(t, p, h.cred, wdAmount)
		if again := s.payoutNow(t, h, pc); again.NewWalletPubkey != p.NewWalletPubkey {
			t.Errorf("re-minted twice: %s then %s", p.NewWalletPubkey, again.NewWalletPubkey)
		}
		s.chain().Withhold(t, txid, false)
		s.chain().Mine(t, 2)
		if _, d := s.chain().Tx(t, txid); d != 0 {
			t.Errorf("the invalidated version confirmed after the cancellation")
		}
	}
	run(false)
	run(true)
}

// CT-STAT-13 (CASH-WD-25): cash_status' withdraw object: its fields,
// min_millis and max_millis omitted when unset (never null), script_types as
// pairs; absent once withdrawals are off (WithdrawToggle).
func ctStat13(t *testing.T, s *suite) {
	s.withdrawals(t)
	h := s.pubkeyBill(t, wdAmount, 0)
	res := s.raw(t, h, nipcash.MethodCashStatus, map[string]any{"scope": "mine"}, h.priv)
	var body struct {
		Withdraw map[string]json.RawMessage `json:"withdraw"`
	}
	if res == nil || json.Unmarshal(res["result"], &body) != nil || body.Withdraw == nil {
		t.Fatalf("cash_status: %v", res)
	}
	for _, k := range []string{"withdraw_fee_base", "withdraw_fee_ppm", "script_types", "final_depth"} {
		if _, ok := body.Withdraw[k]; !ok {
			t.Errorf("withdraw object lacks %s", k)
		}
	}
	for _, k := range []string{"min_millis", "max_millis"} {
		if v, ok := body.Withdraw[k]; ok && string(v) == "null" {
			t.Errorf("%s is null, not omitted", k)
		}
	}
	var pairs [][]int
	if json.Unmarshal(body.Withdraw["script_types"], &pairs) != nil {
		t.Errorf("script_types %s", body.Withdraw["script_types"])
	}
	for _, p := range pairs {
		if len(p) != 2 {
			t.Errorf("script type %v is not a pair", p)
		}
	}
	var w nipcash.WithdrawTerms
	raw, _ := json.Marshal(body.Withdraw)
	if err := json.Unmarshal(raw, &w); err != nil || w.Validate() != nil {
		t.Errorf("withdraw object %s: %v", raw, w.Validate())
	}
	if toggle, ok := s.h.(WithdrawToggle); ok {
		toggle.SetWithdrawals(t, false)
		defer toggle.SetWithdrawals(t, true)
		res := s.raw(t, h, nipcash.MethodCashStatus, map[string]any{}, h.priv)
		var off map[string]json.RawMessage
		if json.Unmarshal(res["result"], &off) != nil {
			t.Fatalf("cash_status: %v", res)
		}
		if _, has := off["withdraw"]; has {
			t.Errorf("withdrawals off: the withdraw object is still there")
		}
	}
}

// CT-ENV-16 (CASH-WD-22, CASH-WD-24): a kind-23187 quote in params counts one
// verification (K-VB-2), so an envelope over max_verify_budget only by it is
// refused whole QUOTA_EXCEEDED, and one at the budget is run; I8's shapes for
// a quote, a withdrawal and a cancel request.
func ctEnv16(t *testing.T, s *suite) {
	s.withdrawals(t)
	addr := s.address(t, p2wpkh)
	h := s.pubkeyBill(t, wdAmount, 0)
	q := s.quoteOK(t, h, addr)
	// Items costing exactly max_verify_budget + 1, the quote of the first
	// counting one: a bill proof, an item proof and an identity_event each, an
	// attestation_event where the count needs one, and two per source.
	budget, maxSources := s.limits.MaxVerifyBudget, s.limits.MaxConsolidateSources
	type slot struct {
		src int
		att bool
	}
	var plan []slot
	for left, i := budget+1, 0; left > 0; i++ {
		base := 3
		if i == 0 {
			base = 4
		}
		if left < base {
			t.Fatalf("test setup: %d verifications left for an item of %d", left, base)
		}
		src := min(maxSources, (left-base)/2)
		rest := left - base - 2*src
		if rest == 2 && src > 0 { // too little for another item: take a source back
			src, rest = src-1, rest+2
		}
		sl := slot{src: src, att: rest == 1}
		if sl.att {
			rest = 0
		}
		plan = append(plan, sl)
		left = rest
	}
	build := func(withQuote bool, nonce string, notAfter int64) []transport.Item {
		var items []transport.Item
		for i, sl := range plan {
			sources := make([]map[string]string, sl.src)
			for k := range sources {
				sources[k] = map[string]string{"identity_event": "x", "attestation_event": "x"}
			}
			p := withdrawParams(t, h, q, nil)
			p["request_id"] = "XYZ" // refused at I6 if it ever runs
			p["sources"] = sources
			if sl.att {
				p["attestation_event"] = "x"
			}
			if i > 0 || !withQuote {
				p["quote"] = ""
			}
			items = append(items, s.rawItem(t, h, string(rune('a'+i)), nipcash.MethodCashWithdraw, p, h.priv, nonce, notAfter))
		}
		return items
	}
	for _, withQuote := range []bool{true, false} {
		e, nonce, replyTo, notAfter := s.newEnvelope(t)
		items := build(withQuote, nonce, notAfter)
		cost := 0
		for _, it := range items {
			cost += it.VerificationCost()
		}
		want := budget + 1
		if !withQuote {
			want = budget
		}
		if cost != want || len(items) > s.limits.MaxItems {
			t.Fatalf("test setup: %d items cost %d, want %d", len(items), cost, want)
		}
		e["items"] = items
		l := s.listen(t, replyTo)
		r := s.wrap(t, e, "")
		s.publish(t, 0, r.ev)
		got := l.wait(1, s.quiet())
		if len(got) != 1 {
			t.Fatalf("no reply (quote %v)", withQuote)
		}
		code := envelopeErrorCode(t, r.open(t, got[0].ev))
		if withQuote && code != nipcash.ErrCodeQuotaExceeded {
			t.Errorf("one verification over the budget, the quote's: envelope error %q, want QUOTA_EXCEEDED", code)
		}
		if !withQuote && code != "" {
			t.Errorf("at the budget: envelope error %q, want the items run", code)
		}
	}
	// I8.
	c := s.cashBill(t, wdAmount)
	wantCode(t, "quote with a cash_secret", s.raw(t, c, nipcash.MethodCashWithdrawQuote, map[string]any{"address": addr, "cash_secret": c.secret}, ""),
		nipcash.ErrCodeBadRequest, "")
	p := withdrawParams(t, h, q, nil)
	wantCode(t, "withdraw with neither", s.raw(t, h, nipcash.MethodCashWithdraw, p, ""), nipcash.ErrCodeBadRequest, "")
	p["cash_secret"] = mustKey(t)
	wantCode(t, "withdraw with both", s.raw(t, h, nipcash.MethodCashWithdraw, p, h.priv), nipcash.ErrCodeBadRequest, "")
	rid, _ := nipcash.NewRequestID()
	if res := s.raw(t, h, nipcash.MethodCashWithdraw, map[string]any{"cancel": true, "request_id": rid}, ""); resultCode(res) == nipcash.ErrCodeBadRequest {
		t.Errorf("a proofless cancel request was refused at I8: %v (it is checked as a lookup)", res)
	}
	wantCode(t, "cancel with both", s.raw(t, h, nipcash.MethodCashWithdraw, map[string]any{"cancel": true, "request_id": rid, "cash_secret": mustKey(t)}, h.priv),
		nipcash.ErrCodeBadRequest, "")
}

// CT-SCOPE-05 (CASH-WD-01): a Hub offering withdrawals lists both
// cash_withdraw and cash_withdraw_quote in private_methods; one that does not
// lists neither. Checked on the Cash Hub connection, and on a bill's own
// connection when the suite read the offer there (see offersWithdrawals).
func ctScope05(t *testing.T, s *suite) {
	both := func(where string, pm []string) {
		quote := slices.Contains(pm, nipcash.MethodCashWithdrawQuote)
		call := slices.Contains(pm, nipcash.MethodCashWithdraw)
		if quote != call {
			t.Errorf("%s private_methods %v lists one withdrawal method without the other", where, pm)
		}
	}
	both("the Cash Hub connection's", s.info.PrivateMethods)
	if slices.Contains(s.info.Methods, nipcash.MethodMintCash) && s.offersWithdrawals(t) && s.wd.billInfo != nil {
		both("a bill's", s.wd.billInfo.PrivateMethods)
	}
}
