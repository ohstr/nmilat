package vectors

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/utils"
)

// vecRID is K-RID-1, the request_id the vectors use.
const vecRID = "00112233445566778899aabbccddeeff"

// claimKAT: K-CLAIM-*: a kind 23198 claim proof's NIP-01 id over Tags, or
// a hash the proofs bind.
type claimKAT struct {
	ID        string     `json:"id"`
	Kind      int        `json:"kind,omitempty"`
	Pubkey    string     `json:"pubkey,omitempty"`
	CreatedAt uint64     `json:"createdAt,omitempty"`
	Tags      [][]string `json:"tags,omitempty"`
	Input     any        `json:"input,omitempty"`
	Want      string     `json:"want"`
}

// verifyClaimCase: VerifyClaimProof(Proof, expectation, Now).
type verifyClaimCase struct {
	Name         string         `json:"name"`
	Proof        string         `json:"proof"`
	Expect       map[string]any `json:"expect"`
	Now          int64          `json:"now"`
	Signer       string         `json:"signer,omitempty"`
	RecomputedID string         `json:"recomputedId,omitempty"`
	Error        string         `json:"error,omitempty"`
}

// claimResultCase: a method's result as the client parses it: the tokens
// decrypted, a tombstone answered for a destroyed bill (gone), or an error.
type claimResultCase struct {
	Name   string             `json:"name"`
	Method string             `json:"method"`
	Lookup bool               `json:"lookup"`
	Inputs map[string]any     `json:"inputs"`
	Result string             `json:"result"`
	Error  string             `json:"error,omitempty"`
	Gone   *nipcash.Tombstone `json:"gone,omitempty"`
	Want   map[string]any     `json:"want,omitempty"`
}

// tombstoneCase: ParseTombstone(Input); Reason is "" for spent with no reason.
type tombstoneCase struct {
	Name      string             `json:"name"`
	Input     string             `json:"input"`
	Tombstone *nipcash.Tombstone `json:"tombstone"`
}

// tombstoneReasonCase: TombstoneReason(terminal state).
type tombstoneReasonCase struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

// orderedCase: OrderedResult over the sources' ordered flags.
type orderedCase struct {
	Name    string `json:"name"`
	Sources []bool `json:"sources"`
	Ordered bool   `json:"ordered"`
	Mixed   bool   `json:"mixed"`
}

const k1Pub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func eventID(kind int, pubkey string, createdAt uint64, tags [][]string) string {
	ev := &nip01.Event{Kind: kind, PubKey: pubkey, CreatedAt: createdAt, Tags: tags}
	id, err := ev.HashID()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(id)
}

func claimKATs() []claimKAT {
	ones, twos, fours := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("4", 64)
	nih := nipcash.NewIdentityHashOf("pubkey", k1Pub, "")
	amt := uint64(5000)
	redeem := nipcash.ClaimBinding{Method: nipcash.MethodCashRedeem, Wallet: ones, Bolt11Hash: fours}.Tags()
	transfer := nipcash.ClaimBinding{Method: nipcash.MethodCashTransfer, Wallet: ones, NewIdentityHash: nih, AmountMillis: &amt}.Tags()
	withdraw := nipcash.ClaimBinding{Method: nipcash.MethodCashWithdraw, Wallet: wdBill, QuoteID: kWQ1ID}.Tags()
	s, _ := nipcash.SourcesHash([]string{ones, twos})
	return []claimKAT{
		{ID: "K-CLAIM-1", Kind: nipcash.KindClaimProof, Pubkey: k1Pub, CreatedAt: 1720000000, Tags: redeem, Want: eventID(nipcash.KindClaimProof, k1Pub, 1720000000, redeem)},
		{ID: "K-CLAIM-2", Kind: nipcash.KindClaimProof, Pubkey: k1Pub, CreatedAt: 1720000000, Tags: transfer, Want: eventID(nipcash.KindClaimProof, k1Pub, 1720000000, transfer)},
		{ID: "K-CLAIM-3", Input: []string{ones, twos}, Want: s},
		{ID: "K-CLAIM-4", Input: "pubkey:" + k1Pub + ":", Want: nih},
		{ID: "K-CLAIM-4 (neg: refused)", Input: "pubkey:" + k1Pub, Want: sha256Hex("pubkey:" + k1Pub)},
		{ID: "K-CLAIM-5", Kind: nipcash.KindClaimProof, Pubkey: wdSlice, CreatedAt: 1720000050, Tags: withdraw, Want: eventID(nipcash.KindClaimProof, wdSlice, 1720000050, withdraw)},
	}
}

func verifyClaimCases() []verifyClaimCase {
	priv := claimantSecret
	pub := must(utils.GetPublicKey(priv))
	wallet := strings.Repeat("1", 64)
	b := nipcash.ClaimBinding{Method: nipcash.MethodCashRedeem, Wallet: wallet, Bolt11Hash: strings.Repeat("4", 64)}
	const now = 1720000000
	sign := func(secret string, kind int, at int64, tags [][]string) string {
		ev := nip01.Event{Kind: kind, CreatedAt: uint64(at), Tags: tags}
		if err := ev.Sign(secret); err != nil {
			panic(err)
		}
		raw, _ := json.Marshal(ev)
		return string(raw)
	}
	var out []verifyClaimCase
	add := func(name, proof string, want nipcash.ClaimExpectation, consumed bool) {
		want.Consumed = func(string) bool { return consumed }
		c := verifyClaimCase{Name: name, Proof: proof, Now: now, Expect: map[string]any{
			"method": want.Binding.Method, "wallet": want.Binding.Wallet, "bolt11Hash": want.Binding.Bolt11Hash, "quoteId": want.Binding.QuoteID,
			"sliceType": want.SliceType, "sliceValue": want.SliceValue, "consumed": consumed}}
		v, err := nipcash.VerifyClaimProof(proof, want, time.Unix(now, 0))
		c.Signer, c.RecomputedID, c.Error = v.Signer, v.RecomputedID, errString(err)
		out = append(out, c)
	}
	want := nipcash.ClaimExpectation{Binding: b, SliceType: "pubkey", SliceValue: pub}
	add("valid", sign(priv, nipcash.KindClaimProof, now, b.Tags()), want, false)
	add("already consumed", sign(priv, nipcash.KindClaimProof, now, b.Tags()), want, true)
	for _, d := range []int64{-300, -301, 60, 61} {
		add("created_at "+itoa(d)+" s from now", sign(priv, nipcash.KindClaimProof, now+d, b.Tags()), want, false)
	}
	add("wrong kind", sign(priv, 23192, now, b.Tags()), want, false)
	add("signed by another key", sign(strings.Repeat("0a", 32), nipcash.KindClaimProof, now, b.Tags()), want, false)
	other := b
	other.Wallet = strings.Repeat("2", 64)
	add("d names another wallet", sign(priv, nipcash.KindClaimProof, now, other.Tags()), want, false)
	other = b
	other.Method = nipcash.MethodCashTransfer
	add("m names another method", sign(priv, nipcash.KindClaimProof, now, other.Tags()), want, false)
	other = b
	other.Bolt11Hash = strings.Repeat("5", 64)
	add("bolt11_hash of another invoice", sign(priv, nipcash.KindClaimProof, now, other.Tags()), want, false)
	add("no m tag", sign(priv, nipcash.KindClaimProof, now, [][]string{{"d", wallet}, {"bolt11_hash", b.Bolt11Hash}}), want, false)
	add("m twice", sign(priv, nipcash.KindClaimProof, now, append(b.Tags(), []string{"m", "cash_redeem"})), want, false)
	add("non-empty content", func() string {
		ev := nip01.Event{Kind: nipcash.KindClaimProof, CreatedAt: now, Tags: b.Tags(), Content: "x"}
		_ = ev.Sign(priv)
		raw, _ := json.Marshal(ev)
		return string(raw)
	}(), want, false)
	add("not JSON", "{", want, false)
	wq := nipcash.ClaimBinding{Method: nipcash.MethodCashWithdraw, Wallet: wallet, QuoteID: kWQ1ID}
	add("cash_withdraw with q", sign(priv, nipcash.KindClaimProof, now, wq.Tags()), nipcash.ClaimExpectation{Binding: wq, SliceType: "pubkey", SliceValue: pub}, false)
	wq2 := wq
	wq2.QuoteID = strings.Repeat("6", 64)
	add("cash_withdraw with another quote", sign(priv, nipcash.KindClaimProof, now, wq2.Tags()), nipcash.ClaimExpectation{Binding: wq, SliceType: "pubkey", SliceValue: pub}, false)
	return out
}

func itoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func claimResultCases(userPub string, cred map[string]nipcash.Credential, targets []*nipcash.CashTarget) []claimResultCase {
	var out []claimResultCase
	newSecret := strings.Repeat("5a", 32)
	newPub := must(utils.GetPublicKey(newSecret))
	remSecret := strings.Repeat("5b", 32)
	remPub := must(utils.GetPublicKey(remSecret))
	seal := func(from, plain string) string {
		ct, err := nip44.EncryptHex(plain, from, userPub)
		if err != nil {
			panic(err)
		}
		return ct
	}
	tokNew, tokRem := "satscash1newwallettoken", "satscash1remaindertoken"
	wallet := strings.Repeat("ab", 32)
	add := func(name, method string, lookup bool, inputs map[string]any, result string, parse func([]byte) (any, error)) {
		c := claimResultCase{Name: name, Method: method, Lookup: lookup, Inputs: inputs, Result: result}
		r, err := parse([]byte(result))
		if err != nil {
			c.Error = err.Error()
			if g, ok := err.(*nipcash.BillGone); ok {
				c.Gone = &g.Tombstone
			}
		}
		if r != nil && err == nil {
			raw, _ := json.Marshal(r)
			_ = json.Unmarshal(raw, &c.Want)
		}
		out = append(out, c)
	}
	withSeededRand("claim-results", func() int {
		tp := nipcash.CashTransferParams{RequestID: vecRID, Credential: cred["signing"], To: nipcash.Pubkey(userPub), CurrentAmount: 21000}
		transfer := func(name string, p nipcash.CashTransferParams, inputs map[string]any, result string) {
			add(name, "cash_transfer", false, inputs, result, func(b []byte) (any, error) { return p.ParseResult(b) })
			add(name, "cash_transfer", true, inputs, result, func(b []byte) (any, error) { return p.ParseLookupResult(b) })
		}
		in := map[string]any{"credential": "signing", "to": "pubkey", "currentAmount": 21000}
		transfer("full transfer to a pubkey, answered in place", tp, in, `{"amount_millis":21000,"identity_type":"pubkey","identity_value":"`+userPub+`","new_wallet_token":""}`)
		transfer("full transfer to a pubkey already holding an unclaimed slice: a one-wallet spin-off", tp, in,
			`{"amount_millis":21000,"identity_type":"pubkey","identity_value":"`+userPub+`","new_wallet_pubkey":"`+newPub+`","new_wallet_token":"`+seal(newSecret, tokNew)+`"}`)
		split := uint64(5000)
		ps := tp
		ps.SplitAmount = &split
		transfer("partial split", ps, map[string]any{"credential": "signing", "to": "pubkey", "currentAmount": 21000, "splitAmount": 5000},
			`{"amount_millis":5000,"identity_type":"pubkey","identity_value":"`+userPub+`","remaining_amount_millis":16000,"new_wallet_pubkey":"`+newPub+`","new_wallet_token":"`+seal(newSecret, tokNew)+`","remainder_wallet_pubkey":"`+remPub+`","remainder_wallet_token":"`+seal(remSecret, tokRem)+`"}`)
		pc := tp
		pc.To = targets[0]
		transfer("full transfer to cash on a wallet that once had two recipients: spun off", pc, map[string]any{"credential": "signing", "to": "cash", "currentAmount": 21000},
			`{"amount_millis":21000,"identity_type":"cash","identity_value":"`+must(nipcash.CashCommitment(targets[0].Secret()))+`","new_wallet_pubkey":"`+newPub+`","new_wallet_token":"`+seal(newSecret, tokNew)+`"}`)
		transfer("zap transfer signed values", tp, in,
			`{"amount_millis":21000,"identity_type":"pubkey","identity_value":"`+userPub+`","new_wallet_pubkey":"`+newPub+`","new_wallet_token":"`+seal(newSecret, tokNew)+`","issued_at":1720000000,"expires_at":0}`)
		transfer("created bill already destroyed", ps, in,
			`{"amount_millis":5000,"identity_type":"pubkey","identity_value":"`+userPub+`","remaining_amount_millis":16000,"new_wallet_pubkey":"`+newPub+`","new_wallet_token":{"status":"spent","reason":"redeemed","retained_until":1722592000},"remainder_wallet_pubkey":"`+remPub+`","remainder_wallet_token":"`+seal(remSecret, tokRem)+`"}`)
		transfer("the source is gone: tombstone", tp, in, `{"status":"spent","reason":"transferred","retained_until":1722592000}`)
		transfer("the source was written off: tombstone without reason", tp, in, `{"status":"spent","retained_until":1722592000}`)
		transfer("a Hub returned a secret", tp, in, `{"amount_millis":21000,"identity_type":"pubkey","identity_value":"`+userPub+`","new_wallet_token":"","secret":"x"}`)
		transfer("token sealed by another key", tp, in,
			`{"amount_millis":21000,"identity_type":"pubkey","identity_value":"`+userPub+`","new_wallet_pubkey":"`+newPub+`","new_wallet_token":"`+seal(remSecret, tokNew)+`"}`)

		cp := nipcash.CashConsolidateParams{RequestID: vecRID, To: nipcash.Pubkey(userPub), Sources: []nipcash.Source{
			nipcash.From(wallet, 1000, cred["signing"]), nipcash.From(strings.Repeat("cd", 32), 2000, cred["signing"])}}
		cons := func(name, result string) {
			inputs := map[string]any{"to": "pubkey", "sources": []map[string]any{{"wallet": wallet, "amount": 1000, "credential": "signing"}, {"wallet": strings.Repeat("cd", 32), "amount": 2000, "credential": "signing"}}}
			add(name, "cash_consolidate", false, inputs, result, func(b []byte) (any, error) { return cp.ParseResult(b) })
			add(name, "cash_consolidate", true, inputs, result, func(b []byte) (any, error) { return cp.ParseLookupResult(b) })
		}
		cons("merged", `{"amount_millis":3000,"new_wallet_pubkey":"`+newPub+`","new_wallet_token":"`+seal(newSecret, tokNew)+`","expires_at":1730000000}`)
		cons("merged, never expires", `{"amount_millis":3000,"new_wallet_pubkey":"`+newPub+`","new_wallet_token":"`+seal(newSecret, tokNew)+`"}`)
		cons("merged bill already destroyed", `{"amount_millis":3000,"new_wallet_pubkey":"`+newPub+`","new_wallet_token":{"status":"spent","reason":"consolidated"}}`)
		cons("a source is gone", `{"status":"spent","reason":"expired"}`)

		redeem := func(name, result string) {
			add(name, "cash_redeem", false, map[string]any{}, result, func(b []byte) (any, error) { return nipcash.ParseCashRedeemResult(b) })
		}
		redeem("preimage and fees", `{"preimage":"`+strings.Repeat("ab", 32)+`","fees_paid":210}`)
		redeem("same-node redeem, no fee", `{"preimage":"`+strings.Repeat("ab", 32)+`","fees_paid":0}`)
		redeem("no preimage", `{"fees_paid":210}`)
		redeem("short preimage", `{"preimage":"abcd","fees_paid":210}`)
		redeem("uppercase preimage", `{"preimage":"`+strings.Repeat("AB", 32)+`","fees_paid":210}`)
		redeem("fees_paid as a string", `{"preimage":"`+strings.Repeat("ab", 32)+`","fees_paid":"210"}`)
		redeem("negative fees_paid", `{"preimage":"`+strings.Repeat("ab", 32)+`","fees_paid":-1}`)
		redeem("not JSON", `[`)
		redeem("a tombstone", `{"status":"spent","reason":"redeemed"}`)
		return 0
	})
	return out
}

func tombstoneCases() ([]tombstoneCase, []tombstoneReasonCase) {
	var ts []tombstoneCase
	for _, c := range [][2]string{
		{"redeemed", `{"status":"spent","reason":"redeemed","retained_until":1722592000}`},
		{"transferred", `{"status":"spent","reason":"transferred"}`},
		{"consolidated", `{"status":"spent","reason":"consolidated"}`},
		{"expired", `{"status":"spent","reason":"expired"}`},
		{"reclaimed", `{"status":"spent","reason":"reclaimed"}`},
		{"written-off: no reason, spent", `{"status":"spent"}`},
		{"unknown reason reads as spent with no reason", `{"status":"spent","reason":"written-off"}`},
		{"ended by a cash_withdraw", `{"status":"spent","withdraw_request_id":"` + vecRID + `"}`},
		{"not spent", `{"status":"live"}`},
		{"not JSON", `[`},
	} {
		t, _ := nipcash.ParseTombstone(json.RawMessage(c[1]))
		ts = append(ts, tombstoneCase{c[0], c[1], t})
	}
	var rs []tombstoneReasonCase
	for _, s := range []string{"redeemed", "transferred", "consolidated", "expired", "reclaimed", "written-off", "withdrawn", ""} {
		rs = append(rs, tombstoneReasonCase{s, nipcash.TombstoneReason(s)})
	}
	return ts, rs
}

func orderedCases() []orderedCase {
	var out []orderedCase
	for _, c := range []struct {
		name string
		s    []bool
	}{
		{"one ordered source: the result inherits ordered", []bool{true}},
		{"no ordered source", []bool{false, false}},
		{"every source ordered", []bool{true, true, true}},
		{"mixed consolidate", []bool{true, false}},
		{"mixed consolidate, ordered last", []bool{false, false, true}},
	} {
		o, m := nipcash.OrderedResult(c.s)
		out = append(out, orderedCase{c.name, c.s, o, m})
	}
	return out
}
