package nipcash

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chaincfg/chainhash"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/flokiorg/go-flokicoin/wire"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

func signWith(priv string) func(*nip01.Event) error {
	return func(ev *nip01.Event) error { return ev.Sign(priv) }
}

func kwq1Fields() QuoteFields {
	return QuoteFields{Wallet: wdBill, IdentityValue: wdSlice, Address: kAddr1, AmountMillis: 21000000, NetworkFeeMillis: 1200000,
		HubFeeMillis: 542000, PayoutMillis: 19258000, SentBy: 1720003600, HoldsUntil: 870413}
}

func kwq1(t *testing.T) *nip01.Event {
	t.Helper()
	ev, err := NewWithdrawQuoteEvent(kwq1Fields(), 1720000000, signWith(wdPriv1))
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func rawEvent(t *testing.T, ev *nip01.Event) string {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// T21-05: the quote event (K-WQ-1, K-WQ-2).
func TestT21_05_QuoteEvent(t *testing.T) {
	ev := kwq1(t)
	if ev.ID != kWQ1 || ev.Kind != KindWithdrawQuote || ev.Content != "" || ev.PubKey != wdHub {
		t.Errorf("K-WQ-1: %s kind %d", ev.ID, ev.Kind)
	}
	for i, n := range quoteTagNames {
		if ev.Tags[i][0] != n {
			t.Errorf("tag %d is %s, want %s", i, ev.Tags[i][0], n)
		}
	}
	ck := kwq1Fields()
	ck.IdentityValue, ck.IAPubkey = wdCK1, wdSlice
	ev2, err := NewWithdrawQuoteEvent(ck, 1720000000, signWith(wdPriv1))
	if err != nil || ev2.ID != kWQ2 {
		t.Errorf("K-WQ-2: %v %v", ev2, err)
	}
	q, err := ParseWithdrawQuote(rawEvent(t, ev))
	if err != nil || q.FeeMillis() != 1742000 {
		t.Errorf("fee_millis %v", err)
	}
}

// T21-07: ParseWithdrawQuote and VerifyWithdrawQuote (K-WQ-3).
func TestT21_07_ParseQuote(t *testing.T) {
	ev := kwq1(t)
	if _, err := ParseWithdrawQuote(rawEvent(t, ev)); err != nil {
		t.Fatalf("K-WQ-1: %v", err)
	}
	rev := ev.Copy()
	for i, j := 0, len(rev.Tags)-1; i < j; i, j = i+1, j-1 {
		rev.Tags[i], rev.Tags[j] = rev.Tags[j], rev.Tags[i]
	}
	if err := rev.Sign(wdPriv1); err != nil || rev.ID != kWQ3 {
		t.Fatalf("K-WQ-3 id %s %v", rev.ID, err)
	}
	q3, err := ParseWithdrawQuote(rawEvent(t, rev))
	if err != nil || VerifyWithdrawQuote(q3, wdHub) != nil || q3.ID != kWQ3 {
		t.Errorf("K-WQ-3: %v", err)
	}
	mutate := func(f func(*nip01.Event)) string {
		c := ev.Copy()
		f(c)
		_ = c.Sign(wdPriv1)
		return rawEvent(t, c)
	}
	for name, raw := range map[string]string{
		"extra tag":       mutate(func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"x", "1"}) }),
		"repeated d":      mutate(func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"d", wdBill}) }),
		"leading zero":    mutate(func(e *nip01.Event) { e.Tags[3][1] = "021000000" }),
		"content":         mutate(func(e *nip01.Event) { e.Content = "x" }),
		"kind 23188":      mutate(func(e *nip01.Event) { e.Kind = KindWithdrawReceipt }),
		"no holds_until":  mutate(func(e *nip01.Event) { e.Tags = e.Tags[:8] }),
		"i four elements": mutate(func(e *nip01.Event) { e.Tags[1] = []string{"i", wdSlice, wdSlice, wdSlice} }),
		"not json":        "{",
	} {
		var we *WithdrawError
		if _, err := ParseWithdrawQuote(raw); !errors.As(err, &we) || we.Code != ErrCodeBadRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	q, _ := ParseWithdrawQuote(rawEvent(t, ev))
	badSig := *q
	e := *q.Event
	e.Sig = strings.Repeat("0", 128)
	badSig.Event = &e
	badID := *q
	e2 := *q.Event
	e2.ID = strings.Repeat("a", 64)
	badID.Event, badID.ID = &e2, e2.ID
	other := *q
	e3 := *q.Event
	_ = e3.Sign(wdPriv3)
	other.Event, other.ID = &e3, e3.ID
	for name, qq := range map[string]*WithdrawQuote{"signature": &badSig, "id": &badID, "author": &other} {
		var we *WithdrawError
		if err := VerifyWithdrawQuote(qq, wdHub); !errors.As(err, &we) || we.Code != ErrCodeRestricted || we.Detail != DetailQuoteInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	// T21-33: a kind-23188 event is never a quote.
	if _, err := ParseWithdrawQuote(mutate(func(e *nip01.Event) { e.Kind = KindWithdrawReceipt })); err == nil {
		t.Error("a receipt parsed as a quote")
	}
}

func kwq1Answer(t *testing.T) (CashWithdrawQuoteResult, QuoteExpectation) {
	ev := kwq1(t)
	redeem := uint64(105000)
	return CashWithdrawQuoteResult{Quote: rawEvent(t, ev), Address: kAddr1, AmountMillis: 21000000, NetworkFeeMillis: 1200000,
			HubFeeMillis: 542000, FeeMillis: 1742000, PayoutMillis: 19258000, SentBy: 1720003600, HoldsUntil: 870413},
		QuoteExpectation{HubXOnly: wdHub, Wallet: wdBill, IdentityValue: wdSlice, Address: kAddr1, AmountMillis: 21000000, RedeemFeeMillis: &redeem}
}

// T21-08: VerifyQuoteAnswer.
func TestT21_08_VerifyQuoteAnswer(t *testing.T) {
	res, exp := kwq1Answer(t)
	if q, err := VerifyQuoteAnswer(res, exp); err != nil || q.ID != kWQ1 {
		t.Fatalf("K-WQ-1 answer: %v", err)
	}
	cases := map[string]func(*CashWithdrawQuoteResult, *QuoteExpectation){
		"address":            func(r *CashWithdrawQuoteResult, _ *QuoteExpectation) { r.Address = kAddr2 },
		"amount_millis":      func(r *CashWithdrawQuoteResult, _ *QuoteExpectation) { r.AmountMillis++ },
		"network_fee_millis": func(r *CashWithdrawQuoteResult, _ *QuoteExpectation) { r.NetworkFeeMillis++ },
		"hub_fee_millis":     func(r *CashWithdrawQuoteResult, _ *QuoteExpectation) { r.HubFeeMillis++ },
		"payout_millis":      func(r *CashWithdrawQuoteResult, _ *QuoteExpectation) { r.PayoutMillis++ },
		"fee_millis":         func(r *CashWithdrawQuoteResult, _ *QuoteExpectation) { r.FeeMillis++ },
		"sent_by":            func(r *CashWithdrawQuoteResult, _ *QuoteExpectation) { r.SentBy++ },
		"holds_until":        func(r *CashWithdrawQuoteResult, _ *QuoteExpectation) { r.HoldsUntil++ },
		"i":                  func(_ *CashWithdrawQuoteResult, e *QuoteExpectation) { e.IdentityValue = wdBill },
		"d":                  func(_ *CashWithdrawQuoteResult, e *QuoteExpectation) { e.Wallet = wdSlice },
		"address sent":       func(_ *CashWithdrawQuoteResult, e *QuoteExpectation) { e.Address = kAddr1[:len(kAddr1)-1] + "5" },
		"send_before":        func(_ *CashWithdrawQuoteResult, e *QuoteExpectation) { sb := int64(1720003599); e.SendBefore = &sb },
		"row amount":         func(_ *CashWithdrawQuoteResult, e *QuoteExpectation) { e.AmountMillis = 20000000 },
		"redeem fee floor":   func(_ *CashWithdrawQuoteResult, e *QuoteExpectation) { f := uint64(1742001); e.RedeemFeeMillis = &f },
		"hub":                func(_ *CashWithdrawQuoteResult, e *QuoteExpectation) { e.HubXOnly = wdSlice },
	}
	for name, f := range cases {
		r, e := kwq1Answer(t)
		f(&r, &e)
		_, err := VerifyQuoteAnswer(r, e)
		if !errors.Is(err, ErrQuoteMismatch) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), kAddr1) {
			t.Errorf("%s: the error carries the address", name)
		}
	}
	// A payout of 19,258,500: the quote itself carries it.
	f := kwq1Fields()
	f.PayoutMillis, f.HubFeeMillis = 19258500, 541500
	ev, _ := NewWithdrawQuoteEvent(f, 1720000000, signWith(wdPriv1))
	r, e := kwq1Answer(t)
	r.Quote, r.PayoutMillis, r.HubFeeMillis, r.FeeMillis = rawEvent(t, ev), 19258500, 541500, 1741500
	e.RedeemFeeMillis = nil
	if _, err := VerifyQuoteAnswer(r, e); !errors.Is(err, ErrQuoteMismatch) || !strings.Contains(err.Error(), "payout_millis") {
		t.Errorf("payout not whole base units: %v", err)
	}
}

// T21-13: QuoteValidAt (K-WHOLD-1).
func TestT21_13_QuoteValidAt(t *testing.T) {
	if !QuoteValidAt(870413, 870413) || QuoteValidAt(870413, 870414) {
		t.Error("K-WHOLD-1")
	}
}

// T21-04 and T21-06: the quote request and item.
func TestT21_04_QuoteRequest(t *testing.T) {
	sb := int64(1720007200)
	req, err := CashWithdrawQuoteParams{Address: kAddr1, SendBefore: &sb, Credential: BySigning(wdPriv3)}.Request(wdBill)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(req)
	if string(b) != `{"address":"`+kAddr1+`","send_before":1720007200}` {
		t.Errorf("pubkey request %s", b)
	}
	iaPriv := fmt.Sprintf("%064x", 7)
	userPub, _ := utils.GetPublicKey(wdPriv3)
	att := buildTestAttestation(t, iaPriv, userPub, testDiscordKey(t), 30)
	ck, err := CashWithdrawQuoteParams{Address: kAddr1, Credential: mustConnCred(t, wdPriv3, att)}.Request(wdBill)
	if err != nil || ck.IdentityValue != testDiscordKey(t).String() || ck.IAPubkey != att.PubKey || ck.AttestationEvent == "" {
		t.Errorf("CK request %+v %v", ck, err)
	}
	secret := strings.Repeat("ab", 32)
	cash, err := CashWithdrawQuoteParams{Address: kAddr1, Credential: BySecret(secret)}.Request(wdBill)
	if b, _ := json.Marshal(cash); err != nil || string(b) != `{"address":"`+kAddr1+`"}` {
		t.Errorf("cash request %s %v", b, err)
	}
	if _, err := (CashWithdrawQuoteParams{Address: strings.ToUpper(kAddr1), Credential: BySigning(wdPriv3)}).Request(wdBill); !errors.Is(err, ErrAddressMalformed) {
		t.Errorf("uppercase: %v", err)
	}
	// T21-06: the item.
	connSecret := strings.Repeat("cd", 32)
	b1 := ItemBinding{HubXOnly: wdHub, Nonce: strings.Repeat("0", 32), NotAfter: 1720000060}
	item, err := CashWithdrawQuoteParams{Address: kAddr1, Credential: BySigning(wdPriv3)}.Item("1", wdBill, connSecret, b1)
	if err != nil || item.Target != wdBill || item.Method != MethodCashWithdrawQuote || !item.HasProof() || item.VerificationCost() != 2 {
		t.Fatalf("pubkey item %+v %v", item, err)
	}
	var proof nip01.Event
	if json.Unmarshal(item.Proof, &proof) != nil || proof.PubKey != wdSlice {
		t.Errorf("item proof by %s", proof.PubKey)
	}
	bearer, err := CashWithdrawQuoteParams{Address: kAddr1, Credential: BySecret(secret)}.Item("1", wdBill, connSecret, b1)
	if err != nil || bearer.HasProof() || strings.Contains(string(bearer.Params), secret) || bearer.VerificationCost() != 1 {
		t.Errorf("bearer item %+v %v", bearer, err)
	}
	ckItem, err := CashWithdrawQuoteParams{Address: kAddr1, Credential: mustConnCred(t, wdPriv3, att)}.Item("1", wdBill, connSecret, b1)
	if err != nil || ckItem.VerificationCost() != 3 {
		t.Errorf("CK item cost %d %v", ckItem.VerificationCost(), err)
	}
}

func kwq1Quote(t *testing.T) *WithdrawQuote {
	t.Helper()
	q, err := ParseWithdrawQuote(rawEvent(t, kwq1(t)))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// T21-10: CashWithdrawParams.Request.
func TestT21_10_WithdrawRequest(t *testing.T) {
	q := kwq1Quote(t)
	notify := strings.Repeat("0123456789abcdef", 4)
	req, err := CashWithdrawParams{Quote: q, Credential: BySigning(wdPriv3), RequestID: wdRID1, Notify: notify}.Request(wdBill)
	if err != nil {
		t.Fatal(err)
	}
	var claim nip01.Event
	if err := json.Unmarshal([]byte(req.IdentityEvent), &claim); err != nil {
		t.Fatal(err)
	}
	if m := claim.GetTag("m"); len(m) != 1 || m[0] != MethodCashWithdraw {
		t.Errorf("m %v", m)
	}
	if qt := claim.GetTag("q"); len(qt) != 1 || qt[0] != kWQ1 {
		t.Errorf("q %v", qt)
	}
	var keys map[string]any
	b, _ := json.Marshal(req)
	_ = json.Unmarshal(b, &keys)
	for _, k := range []string{"quote", "request_id", "notify", "identity_type", "identity_value", "identity_event"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if len(keys) != 6 {
		t.Errorf("keys %v", keys)
	}
	secret := strings.Repeat("ab", 32)
	remint, _ := NewCashTarget()
	cash, err := CashWithdrawParams{Quote: q, Credential: BySecret(secret), RequestID: wdRID1, Notify: notify, Remint: remint}.Request(wdBill)
	if err != nil || cash.CashSecret != secret || cash.RemintCommitment != remint.Commitment() || cash.IdentityEvent != "" {
		t.Errorf("cash request %+v %v", cash, err)
	}
	if _, err := (CashWithdrawParams{Quote: q, Credential: BySecret(secret), RequestID: wdRID1, Notify: notify}).Request(wdBill); !errors.Is(err, ErrRemintRequired) {
		t.Errorf("no remint: %v", err)
	}
	if _, err := (CashWithdrawParams{Quote: q, Credential: BySigning(wdPriv3), RequestID: wdRID1, Notify: notify, Remint: remint}).Request(wdBill); !errors.Is(err, ErrRemintForbidden) {
		t.Errorf("remint on pubkey: %v", err)
	}
	own, _ := CashTargetFromSecret(secret)
	if _, err := (CashWithdrawParams{Quote: q, Credential: BySecret(secret), RequestID: wdRID1, Notify: notify, Remint: own}).Request(wdBill); !errors.Is(err, ErrRemintForbidden) {
		t.Errorf("remint equal: %v", err)
	}
	if _, err := (CashWithdrawParams{Quote: q, Credential: BySigning(wdPriv3), Notify: notify}).Request(wdBill); err == nil {
		t.Error("no request_id")
	}
	pc, err := CashWithdrawParams{Quote: q, Credential: BySecret(secret), RequestID: wdRID1, Notify: notify, Remint: remint}.Pending(wdBill)
	if err != nil || pc.Method != MethodCashWithdraw || pc.Target != wdBill || pc.Amount != 21000000 || pc.Address != kAddr1 ||
		pc.Quote == "" || pc.HoldsUntil != 870413 || pc.Notify != notify || pc.SourceSecret != secret ||
		len(pc.Secrets) != 1 || pc.Secrets[0].Role != SecretRoleRemint || strings.Contains(string(pc.Params), secret) {
		t.Errorf("pending %+v %v", pc, err)
	}
}

// T06-13: K-CLAIM-5.
func TestT06_13_KClaim5(t *testing.T) {
	b := ClaimBinding{Method: MethodCashWithdraw, Wallet: wdBill, QuoteID: kWQ1}
	if id := eventID(t, KindClaimProof, wdSlice, 1720000050, b.Tags()); id != "d21236b945c9ae88e23fe8fd9bc3559b08b9a6ec6d4a74acd15825314b3d7428" {
		t.Errorf("K-CLAIM-5 %s", id)
	}
}

// T21-11: ParseCashWithdrawRequest.
func TestT21_11_ParseWithdrawRequest(t *testing.T) {
	quote := rawEvent(t, kwq1(t))
	qs, _ := json.Marshal(quote)
	notify := strings.Repeat("0123456789abcdef", 4)
	commit := strings.Repeat("11", 32)
	ok := func(extra string) string {
		return `{"quote":` + string(qs) + `,"request_id":"` + wdRID1 + `","notify":"` + notify + `"` + extra + `}`
	}
	if _, err := ParseCashWithdrawRequest(json.RawMessage(ok(`,"identity_type":"pubkey","identity_value":"`+wdSlice+`","identity_event":"{}","other":1`)), WithdrawSlice{}); err != nil {
		t.Errorf("NIP example: %v", err)
	}
	if _, err := ParseCashWithdrawRequest(json.RawMessage(ok(`,"remint_commitment":"`+strings.Repeat("22", 32)+`","cash_secret":"x"`)), WithdrawSlice{CashMode: true, Commitment: commit}); err != nil {
		t.Errorf("cash mode: %v", err)
	}
	for name, c := range map[string]struct {
		raw   string
		slice WithdrawSlice
	}{
		"missing quote":      {`{"request_id":"` + wdRID1 + `","notify":"` + notify + `"}`, WithdrawSlice{}},
		"non-string quote":   {`{"quote":{},"request_id":"` + wdRID1 + `","notify":"` + notify + `"}`, WithdrawSlice{}},
		"malformed quote":    {`{"quote":"{}","request_id":"` + wdRID1 + `","notify":"` + notify + `"}`, WithdrawSlice{}},
		"notify 63":          {`{"quote":` + string(qs) + `,"request_id":"` + wdRID1 + `","notify":"` + notify[:63] + `"}`, WithdrawSlice{}},
		"notify uppercase":   {`{"quote":` + string(qs) + `,"request_id":"` + wdRID1 + `","notify":"` + strings.ToUpper(notify) + `"}`, WithdrawSlice{}},
		"remint missing":     {ok(""), WithdrawSlice{CashMode: true, Commitment: commit}},
		"remint on pubkey":   {ok(`,"remint_commitment":"` + strings.Repeat("22", 32) + `"`), WithdrawSlice{}},
		"remint equal":       {ok(`,"remint_commitment":"` + commit + `"`), WithdrawSlice{CashMode: true, Commitment: commit}},
		"remint malformed":   {ok(`,"remint_commitment":"zz"`), WithdrawSlice{CashMode: true, Commitment: commit}},
		"invoice":            {ok(`,"invoice":"lnbc1"`), WithdrawSlice{}},
		"amount":             {ok(`,"amount":1`), WithdrawSlice{}},
		"idempotency_key":    {ok(`,"idempotency_key":"k"`), WithdrawSlice{}},
		"request_id invalid": {`{"quote":` + string(qs) + `,"request_id":"XYZ","notify":"` + notify + `"}`, WithdrawSlice{}},
	} {
		var we *WithdrawError
		if _, err := ParseCashWithdrawRequest(json.RawMessage(c.raw), c.slice); !errors.As(err, &we) || we.Code != ErrCodeBadRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func payoutJSON(state string, extra string) []byte {
	return []byte(`{"state":"` + state + `","address":"` + kAddr1 + `","amount_millis":21000000,"fee_millis":1742000,"payout_millis":19258000,"sent_by":1720003600,"final_depth":6,"signed":false,"receipt":"{}"` + extra + `}`)
}

// T21-14: ParsePayout.
func TestT21_14_ParsePayout(t *testing.T) {
	txid := strings.Repeat("ab", 32)
	if p, err := ParsePayout(payoutJSON("queued", "")); err != nil || p.State != PayoutQueued || p.FinalDepth != 6 {
		t.Errorf("queued: %v", err)
	}
	b := []byte(strings.Replace(string(payoutJSON("broadcast", `,"tx":"00","txid":"`+txid+`","vout":1,"depth":0`)), `"signed":false`, `"signed":true`, 1))
	if p, err := ParsePayout(b); err != nil || *p.Vout != 1 || p.Txid != txid {
		t.Errorf("broadcast: %v", err)
	}
	if p, err := ParsePayout(payoutJSON("cancelled", `,"new_wallet_pubkey":"`+wdBill+`","new_wallet_token":"satscash1x"`)); err != nil || p.NewWalletToken.Token != "satscash1x" {
		t.Errorf("cancelled: %v", err)
	}
	for name, raw := range map[string][]byte{
		"cancelled txid": payoutJSON("cancelled", `,"txid":"`+txid+`","new_wallet_pubkey":"`+wdBill+`","new_wallet_token":"t"`),
		"no receipt":     []byte(strings.Replace(string(payoutJSON("queued", "")), `,"receipt":"{}"`, "", 1)),
		"failed":         payoutJSON("failed", ""),
		"no signed":      []byte(strings.Replace(string(payoutJSON("queued", "")), `"signed":false,`, "", 1)),
		"queued txid":    payoutJSON("queued", `,"txid":"`+txid+`","vout":0,"depth":0`),
		"broadcast bare": payoutJSON("broadcast", ""),
		"tx unsigned":    payoutJSON("queued", `,"tx":"00"`),
		"remint queued":  payoutJSON("queued", `,"new_wallet_pubkey":"`+wdBill+`"`),
	} {
		if _, err := ParsePayout(raw); !errors.Is(err, ErrPayoutMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// T21-23: ParseDetail (K-WDET-1..3).
func TestT21_23_ParseDetail(t *testing.T) {
	for _, d := range []Detail{DetailNetwork, DetailScriptType, DetailBelowMin, DetailTooSlow, DetailQuoteInvalid, DetailQuoteExpired, DetailUnfinal, DetailOwnAddress} {
		if ParseDetail(string(d)) != d {
			t.Errorf("%s", d)
		}
	}
	if ParseDetail("fee_over_cap") != "" || ParseDetail("") != "" || ParseDetail("OWN_ADDRESS") != "" {
		t.Error("unknown detail kept")
	}
}

func kwr2(t *testing.T) string {
	t.Helper()
	ev, err := NewWithdrawReceiptEvent(ReceiptFields{Wallet: wdBill, QuoteID: kWQ1, RequestID: wdRID1, Address: kAddr1, PayoutMillis: 19258000, SentBy: 1720003600}, 1720000100, signWith(wdPriv1))
	if err != nil {
		t.Fatal(err)
	}
	if ev.ID != kWR2 {
		t.Fatalf("K-WR-2 %s", ev.ID)
	}
	return rawEvent(t, ev)
}

func kwr2Expect() ReceiptExpectation {
	return ReceiptExpectation{HubXOnly: wdHub, Target: wdBill, QuoteID: kWQ1, RequestID: wdRID1, Address: kAddr1, PayoutMillis: 19258000, SentBy: 1720003600}
}

// T21-16: RequestHash and the receipt event (K-WR-1..3).
func TestT21_16_Receipt(t *testing.T) {
	if RequestHash(wdRID1) != "5947d7c33d783f94b3b4c1a96ebc8991ed28f1b069b71e03376cba8caa98a720" {
		t.Error("K-WR-1")
	}
	raw16, _ := hex.DecodeString(wdRID1)
	if RequestHash(string(raw16)) != "a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811" {
		t.Error("K-WR-4")
	}
	kwr2(t)
	did, _ := DerivedRequestID(wdRID1)
	if RequestHash(did) != "0f5019117b865df3d86a6856ba8cf5383850ae9d833ecf7cc9a609552cb6c413" {
		t.Errorf("K-WR-3 hash %s", RequestHash(did))
	}
	ev, err := NewWithdrawReceiptEvent(ReceiptFields{Wallet: wdBill, QuoteID: kWQ1, RequestID: did, Address: kAddr1, PayoutMillis: 19258000, SentBy: 1720003600}, 1720000200, signWith(wdPriv1))
	if err != nil || ev.ID != "7060d4c8e4f8ab862a5105a4d0573465a70f62f9ec8e11e6c8d22595f73f4c90" {
		t.Errorf("K-WR-3 id %v %v", ev, err)
	}
}

// T21-17, T21-31, T21-33: VerifyWithdrawReceipt and ReceiptQuoteID.
func TestT21_17_VerifyReceipt(t *testing.T) {
	raw := kwr2(t)
	if err := VerifyWithdrawReceipt(raw, kwr2Expect()); err != nil {
		t.Fatalf("K-WR-2: %v", err)
	}
	raw16, _ := hex.DecodeString(wdRID1)
	for name, f := range map[string]func(*ReceiptExpectation){
		"K-WR-4":        func(e *ReceiptExpectation) { e.RequestID = string(raw16) },
		"q":             func(e *ReceiptExpectation) { e.QuoteID = kWQ2 },
		"d":             func(e *ReceiptExpectation) { e.Target = wdSlice },
		"address":       func(e *ReceiptExpectation) { e.Address = kAddr2 },
		"payout_millis": func(e *ReceiptExpectation) { e.PayoutMillis++ },
		"sent_by":       func(e *ReceiptExpectation) { e.SentBy++ },
		"author":        func(e *ReceiptExpectation) { e.HubXOnly = wdSlice },
	} {
		e := kwr2Expect()
		f(&e)
		if err := VerifyWithdrawReceipt(raw, e); !errors.Is(err, ErrReceiptInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var ev nip01.Event
	_ = json.Unmarshal([]byte(raw), &ev)
	ev.Sig = strings.Repeat("0", 128)
	if err := VerifyWithdrawReceipt(rawEvent(t, &ev), kwr2Expect()); !errors.Is(err, ErrReceiptInvalid) {
		t.Errorf("bad signature: %v", err)
	}
	// T21-31: a recovered call.
	rec := kwr2Expect()
	rec.QuoteID = ""
	if err := VerifyWithdrawReceipt(raw, rec); err != nil {
		t.Errorf("recovered: %v", err)
	}
	rec.Address = kAddr2
	if err := VerifyWithdrawReceipt(raw, rec); !errors.Is(err, ErrReceiptInvalid) {
		t.Errorf("recovered address: %v", err)
	}
	if q, err := ReceiptQuoteID(raw); err != nil || q != kWQ1 {
		t.Errorf("ReceiptQuoteID %s %v", q, err)
	}
	if _, err := ReceiptQuoteID("{"); err == nil {
		t.Error("malformed receipt")
	}
	// T21-33: re-kinded 23187 → refused before any tag check.
	_ = json.Unmarshal([]byte(raw), &ev)
	ev.Kind = KindWithdrawQuote
	_ = ev.Sign(wdPriv1)
	if err := VerifyWithdrawReceipt(rawEvent(t, &ev), kwr2Expect()); !errors.Is(err, ErrReceiptInvalid) || !strings.Contains(err.Error(), "kind") {
		t.Errorf("re-kinded: %v", err)
	}
}

// T21-27: VerifyPayoutTx.
func TestT21_27_VerifyPayoutTx(t *testing.T) {
	_, prog, _ := DecodeWitnessAddress(kAddr1, "bc")
	build := func(value int64, script []byte) (string, string) {
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{1}, 0), nil, nil))
		tx.AddTxOut(wire.NewTxOut(5000, WitnessScript(0, bytes.Repeat([]byte{9}, 20))))
		tx.AddTxOut(wire.NewTxOut(value, script))
		var buf bytes.Buffer
		_ = tx.Serialize(&buf)
		return hex.EncodeToString(buf.Bytes()), tx.TxHash().String()
	}
	txHex, txid := build(19258, WitnessScript(0, prog))
	if err := VerifyPayoutTx(txHex, txid, 1, kAddr1, "", 19258000); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := VerifyPayoutTx(txHex, txid, 1, kAddr1, "bc", 19258000); err != nil {
		t.Errorf("hrp bc: %v", err)
	}
	if err := VerifyPayoutTx(txHex, txid, 0, kAddr1, "", 19258000); !errors.Is(err, ErrPayoutTx) {
		t.Errorf("vout 0: %v", err)
	}
	low, lowID := build(19257, WitnessScript(0, prog))
	if err := VerifyPayoutTx(low, lowID, 1, kAddr1, "", 19258000); !errors.Is(err, ErrPayoutTx) {
		t.Errorf("value: %v", err)
	}
	wsh, wshID := build(19258, WitnessScript(0, bytes.Repeat([]byte{1}, 32)))
	if err := VerifyPayoutTx(wsh, wshID, 1, kAddr1, "", 19258000); !errors.Is(err, ErrPayoutTx) {
		t.Errorf("p2wsh: %v", err)
	}
	if err := VerifyPayoutTx(txHex, lowID, 1, kAddr1, "", 19258000); !errors.Is(err, ErrPayoutTx) {
		t.Errorf("txid: %v", err)
	}
}

// T21-09: CheckQuoteRequest row order.
func TestT21_09_CheckQuoteRequest(t *testing.T) {
	max, min := uint64(1000), uint64(100)
	calls := 0
	payout := func(p, dust uint64) func(ScriptType) (uint64, uint64, error) {
		return func(ScriptType) (uint64, uint64, error) { calls++; return p, dust, nil }
	}
	base := func() QuoteCheck {
		return QuoteCheck{Found: true, Address: kAddr1, NetworkHRP: "bc", Pays: wdPays, Claimable: true, AmountMillis: 500,
			MinMillis: &min, MaxMillis: &max, PayoutFor: payout(400000, 1), EarliestSentBy: 100}
	}
	check := func(name string, c QuoteCheck, code string, detail Detail, row int) {
		t.Helper()
		err := CheckQuoteRequest(c)
		var we *WithdrawError
		if code == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			return
		}
		if !errors.As(err, &we) || we.Code != code || we.Detail != detail || we.Row != row {
			t.Errorf("%s: %v, want %s/%s row %d", name, err, code, detail, row)
		}
	}
	c := base()
	c.Found, c.Address = false, "x"
	check("not found + malformed", c, ErrCodeNotFound, "", 1)
	c = base()
	c.Claimable, c.AmountMillis = false, 5000
	check("untrusted IA + above max", c, ErrCodeRestricted, "", 5)
	c = base()
	c.Address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"
	check("malformed", c, ErrCodeBadRequest, "", 2)
	c = base()
	data, _ := bech32.ConvertBits(bytes.Repeat([]byte{7}, 16), 8, 5, true)
	c.Address, _ = bech32.EncodeM("tb", append([]byte{2}, data...))
	check("network + not paid", c, ErrCodeRestricted, DetailNetwork, 3)
	c = base()
	c.Address, c.Claimable = kAddr4, false
	check("not paid + claimed", c, ErrCodeRestricted, DetailScriptType, 4)
	c = base()
	c.Address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	check("no witness", c, ErrCodeRestricted, DetailScriptType, 4)
	c = base()
	c.AmountMillis, c.PayoutFor = 5000, payout(0, 1)
	check("above max + dust", c, ErrCodeQuotaExceeded, "", 6)
	c = base()
	c.AmountMillis = 50
	check("below min", c, ErrCodeRestricted, DetailBelowMin, 7)
	calls = 0
	c = base()
	c.PayoutFor = payout(1000, 2000)
	check("dust", c, ErrCodeRestricted, DetailBelowMin, 7)
	c = base()
	c.Address = kAddr6
	check("refused address", c, ErrCodeRestricted, DetailNetwork, 3)
	if calls != 1 {
		t.Errorf("PayoutFor called %d times", calls)
	}
	c = base()
	sb := int64(100)
	c.SendBefore = &sb
	check("send_before = earliest", c, "", "", 0)
	c.EarliestSentBy = 101
	check("too slow", c, ErrCodeRestricted, DetailTooSlow, 8)
}

// T21-12: CheckWithdrawPayout row order.
func TestT21_12_CheckWithdrawPayout(t *testing.T) {
	ok := PayoutCheck{QuoteOK: true, QuoteValid: true, CoinsSetAside: true}
	for name, c := range map[string]struct {
		check  PayoutCheck
		code   string
		detail Detail
	}{
		"quote invalid":   {PayoutCheck{QuoteValid: false, AtUnconfirmedBound: true, OwnAddress: true}, ErrCodeRestricted, DetailQuoteInvalid},
		"expired + bound": {PayoutCheck{QuoteOK: true, AtUnconfirmedBound: true}, ErrCodeRestricted, DetailQuoteExpired},
		"bound + coins":   {PayoutCheck{QuoteOK: true, QuoteValid: true, AtUnconfirmedBound: true}, ErrCodeRateLimited, ""},
		"coins + own":     {PayoutCheck{QuoteOK: true, QuoteValid: true, OwnAddress: true}, ErrCodeInsufficientBalance, ""},
		"unfinal kept":    {PayoutCheck{QuoteOK: true, QuoteValid: true, CoinsSetAside: true, OrderedUnfinal: true, OwnAddress: true}, ErrCodeRestricted, DetailOwnAddress},
		"unfinal refused": {PayoutCheck{QuoteOK: true, QuoteValid: true, CoinsSetAside: true, OrderedUnfinal: true, RefuseUnfinal: true, OwnAddress: true}, ErrCodeRestricted, DetailUnfinal},
	} {
		var we *WithdrawError
		if err := CheckWithdrawPayout(c.check); !errors.As(err, &we) || we.Code != c.code || we.Detail != c.detail {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckWithdrawPayout(ok); err != nil {
		t.Errorf("clear: %v", err)
	}
	clean := ok
	clean.OrderedUnfinal = true
	if err := CheckWithdrawPayout(clean); err != nil {
		t.Errorf("unfinal not refused: %v", err)
	}
}

// T21-15: PayoutStateOf and SpendsFromEach.
func TestT21_15_PayoutStateAndSpends(t *testing.T) {
	for want, f := range map[PayoutState]PayoutFacts{
		PayoutQueued:    {FinalDepth: 6},
		PayoutBroadcast: {Broadcast: true, FinalDepth: 6},
		PayoutConfirmed: {Broadcast: true, Depth: 1, FinalDepth: 6},
		PayoutFinal:     {Broadcast: true, Depth: 6, FinalDepth: 6},
		PayoutCancelled: {Cancelled: true, Broadcast: true, Depth: 3, FinalDepth: 6},
	} {
		if got := PayoutStateOf(f); got != want {
			t.Errorf("%+v: %s, want %s", f, got, want)
		}
	}
	if PayoutStateOf(PayoutFacts{Broadcast: true, Depth: 0, FinalDepth: 6}) != PayoutBroadcast {
		t.Error("reorg to depth 0")
	}
	if PayoutStateOf(PayoutFacts{Broadcast: true, FinalReached: true, FinalDepth: 6}) != PayoutFinal {
		t.Error("final reached, depth 0")
	}
	sets := [][]string{{"a:0", "b:0"}, {"c:0"}}
	if !SpendsFromEach(sets, []string{"a:0", "c:0"}) || SpendsFromEach(sets, []string{"a:0"}) || SpendsFromEach(sets, nil) || !SpendsFromEach(nil, nil) {
		t.Error("SpendsFromEach")
	}
}

// T21-18, T21-19: CancelDue and CancelRequestAnswer (K-WCAN-1..6).
func TestT21_18_Cancel(t *testing.T) {
	const s = 1720003600
	q := CancelFacts{State: PayoutQueued, SentBy: s}
	if CancelDue(q, 1720089999) != CancelNotDue || CancelDue(q, 1720090000) != CancelNow {
		t.Error("K-WCAN-1..2")
	}
	q.AboutToSign = true
	if CancelDue(q, 1720090000) != InvalidateThenCancel {
		t.Error("K-WCAN-3")
	}
	for _, st := range []PayoutState{PayoutConfirmed, PayoutFinal, PayoutCancelled} {
		if CancelDue(CancelFacts{State: st, SentBy: s}, 1<<40) != CancelNotDue {
			t.Errorf("%s due", st)
		}
	}
	b := CancelFacts{AboutToSign: true, Broadcast: true, State: PayoutBroadcast, SentBy: s}
	var we *WithdrawError
	if _, err := CancelRequestAnswer(b, 1720608399); !errors.As(err, &we) || we.Code != ErrCodeRestricted {
		t.Errorf("K-WCAN-4: %v", err)
	}
	if inv, err := CancelRequestAnswer(b, 1720608400); err != nil || !inv {
		t.Errorf("K-WCAN-5: %v %v", inv, err)
	}
	for _, st := range []PayoutState{PayoutConfirmed, PayoutQueued, PayoutCancelled} {
		if inv, err := CancelRequestAnswer(CancelFacts{State: st, SentBy: s}, 1720608400); err != nil || inv {
			t.Errorf("%s: %v %v", st, inv, err)
		}
	}
}

// T21-21: RemintExpiry (K-WREM-1..4).
func TestT21_21_RemintExpiry(t *testing.T) {
	p := func(v int64) *int64 { return &v }
	if got := RemintExpiry(p(1720086400), 1720090000, p(2592000)); got == nil || *got != 1722682000 {
		t.Errorf("K-WREM-1 %v", got)
	}
	if RemintExpiry(nil, 1720090000, p(2592000)) != nil {
		t.Error("K-WREM-2")
	}
	if got := RemintExpiry(p(1730000000), 1720090000, p(2592000)); got == nil || *got != 1730000000 {
		t.Errorf("K-WREM-3 %v", got)
	}
	if RemintExpiry(p(1720086400), 1720090000, nil) != nil {
		t.Error("K-WREM-4")
	}
}

// T21-22: WithdrawNoticeDelay.
func TestT21_22_NoticeDelay(t *testing.T) {
	r := bytes.NewReader(bytes.Repeat([]byte{0x5a, 0x01, 0xff, 0x00, 0x13, 0x77, 0x80, 0x22}, 64))
	for i := 0; i < 50; i++ {
		d, err := WithdrawNoticeDelay(r)
		if err != nil || d < 600e9 || d >= 1200e9 {
			t.Fatalf("delay %v %v", d, err)
		}
	}
	if _, err := WithdrawNoticeDelay(bytes.NewReader(nil)); err == nil {
		t.Error("reader error")
	}
}

// T21-25: WithdrawRecordRetained and WithdrawBlocksHubDelete (K-WRET-1..3).
func TestT21_25_Retention(t *testing.T) {
	r := WithdrawRetention{Deadline: 1720000060, Horizon: 300, TombstoneWindow: 2592000}
	if !WithdrawRecordRetained(r, 1<<40) || !WithdrawBlocksHubDelete(r, 1<<40) {
		t.Error("K-WRET-1")
	}
	r.EndedAt = 1720100000
	if !WithdrawRecordRetained(r, 1722692000) || WithdrawRecordRetained(r, 1722692001) {
		t.Error("K-WRET-2")
	}
	if WithdrawBlocksHubDelete(r, 1722692001) || !WithdrawBlocksHubDelete(r, 1722692000) {
		t.Error("blocks delete")
	}
	r.RemintLive = true
	if !WithdrawRecordRetained(r, 1<<40) {
		t.Error("K-WRET-3")
	}
	early := WithdrawRetention{Deadline: 1720000060, Horizon: 300, EndedAt: 1720000000}
	if !WithdrawRecordRetained(early, 1720000360) || WithdrawRecordRetained(early, 1720000361) {
		t.Error("D+H only")
	}
}

// ParseWithdrawCancel.
func TestParseWithdrawCancel(t *testing.T) {
	if r, ok, err := ParseWithdrawCancel(json.RawMessage(`{"cancel":true,"request_id":"` + wdRID1 + `"}`)); err != nil || !ok || r.RequestID != wdRID1 {
		t.Errorf("cancel: %v %v %v", r, ok, err)
	}
	if _, ok, err := ParseWithdrawCancel(json.RawMessage(`{"quote":"x"}`)); ok || err != nil {
		t.Error("a call is not a cancel")
	}
	for _, raw := range []string{`{"cancel":false,"request_id":"` + wdRID1 + `"}`, `{"cancel":true}`, `{"cancel":true,"request_id":"` + wdRID1 + `","notify":"x"}`, `{"cancel":true,"request_id":"` + wdRID1 + `","cash_secret":"zz"}`} {
		var we *WithdrawError
		if _, ok, err := ParseWithdrawCancel(json.RawMessage(raw)); !ok || !errors.As(err, &we) || we.Code != ErrCodeBadRequest {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

// F-WD-1.
func FuzzWithdrawParsers(f *testing.F) {
	f.Add(`{"kind":23187}`)
	f.Add(string(payoutJSON("queued", "")))
	f.Add(`{"cancel":true,"request_id":"` + wdRID1 + `"}`)
	f.Add(`{"quote":"{}","invoice":"x"}`)
	f.Fuzz(func(t *testing.T, s string) {
		if q, err := ParseWithdrawQuote(s); err == nil {
			id, herr := q.Event.HashID()
			_ = id
			if herr != nil {
				t.Fatal(herr)
			}
		}
		if p, err := ParsePayout([]byte(s)); err == nil && !p.State.Known() {
			t.Fatalf("state %q", p.State)
		}
		_, _, _ = ParseWithdrawCancel(json.RawMessage(s))
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(s), &fields) == nil {
			if _, forbidden := fields["invoice"]; forbidden {
				if _, err := ParseCashWithdrawRequest(json.RawMessage(s), WithdrawSlice{}); err == nil {
					t.Fatal("invoice accepted")
				}
			}
		}
	})
}

// QuoteForSlice binds the quote to the bill, the slice's identity and the
// slice's committed amount: the same identity with another amount (an in-place
// transfer gave it another slice) is quote_invalid.
func TestQuoteForSlice(t *testing.T) {
	q := kwq1Quote(t)
	if err := QuoteForSlice(q, wdHub, wdBill, wdSlice, "", 21000000); err != nil {
		t.Fatalf("matching quote: %v", err)
	}
	for name, err := range map[string]error{
		"another amount": QuoteForSlice(q, wdHub, wdBill, wdSlice, "", 10000),
		"another bill":   QuoteForSlice(q, wdHub, wdSlice, wdSlice, "", 21000000),
		"another slice":  QuoteForSlice(q, wdHub, wdBill, wdBill, "", 21000000),
		"another ia":     QuoteForSlice(q, wdHub, wdBill, wdSlice, wdBill, 21000000),
		"another hub":    QuoteForSlice(q, wdBill, wdBill, wdSlice, "", 21000000),
		"no quote":       QuoteForSlice(nil, wdHub, wdBill, wdSlice, "", 21000000),
	} {
		var we *WithdrawError
		if !errors.As(err, &we) || we.Code != ErrCodeRestricted || we.Detail != DetailQuoteInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}
