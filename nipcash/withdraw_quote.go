package nipcash

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// CashWithdrawQuoteParams is cash_withdraw_quote's friendly request. Credential
// only names the slice and signs the item proof: a pubkey slice's key; a
// connection_key slice's credential, which also supplies identity_value,
// ia_pubkey and attestation_event; BySecret for a cash-mode slice, whose quote
// carries neither proof nor cash_secret (served on its bill proof alone).
// Status is optional: the caller's own cash_status answer, from which
// (*client.Client).QuoteWithdraw takes the terms and the slice's amount and
// redeem fee instead of reading cash_status again.
type CashWithdrawQuoteParams struct {
	// Address is the destination, lowercase (NormalizeAddress a typed one).
	Address string
	// SendBefore is the latest unix time the caller needs the payout
	// broadcast by; nil for none.
	SendBefore *int64
	Credential Credential
	Status     *CashStatusResult
}

// CashWithdrawQuoteRequest is cash_withdraw_quote's wire request.
type CashWithdrawQuoteRequest struct {
	Address          string `json:"address"`
	SendBefore       *int64 `json:"send_before,omitempty"`
	IdentityValue    string `json:"identity_value,omitempty"`
	IAPubkey         string `json:"ia_pubkey,omitempty"`
	AttestationEvent string `json:"attestation_event,omitempty"`
}

// Request builds the wire request for the bill walletPubkey: the address (which
// must be lowercase: ErrAddressMalformed otherwise), any send_before, and for a
// connection_key slice its identity_value, ia_pubkey and attestation.
func (p CashWithdrawQuoteParams) Request(walletPubkey string) (CashWithdrawQuoteRequest, error) {
	if p.Address == "" || strings.ToLower(p.Address) != p.Address || strings.TrimSpace(p.Address) != p.Address {
		return CashWithdrawQuoteRequest{}, fmt.Errorf("%w: the address is sent lowercase and trimmed", ErrAddressMalformed)
	}
	if !isLowerHex64(walletPubkey) {
		return CashWithdrawQuoteRequest{}, fmt.Errorf("nipcash: wallet pubkey is 64 lowercase hex")
	}
	req := CashWithdrawQuoteRequest{Address: p.Address, SendBefore: p.SendBefore}
	switch c := p.Credential.(type) {
	case connectionKeyCredential:
		att, err := json.Marshal(c.attestation.Event)
		if err != nil {
			return CashWithdrawQuoteRequest{}, fmt.Errorf("nipcash: marshal attestation: %w", err)
		}
		req.IdentityValue, req.IAPubkey, req.AttestationEvent = c.attestation.ConnectionKey.String(), c.attestation.PubKey, string(att)
	case signingCredential, secretCredential:
	default:
		return CashWithdrawQuoteRequest{}, errors.New("nipcash: a quote needs the slice's credential")
	}
	return req, nil
}

// Item builds the cash_withdraw_quote item against the bill target: the item
// proof by the credential's key (none for BySecret, whose secret is never sent
// with a quote), the bill proof by connSecret.
func (p CashWithdrawQuoteParams) Item(id, target, connSecret string, b ItemBinding) (transport.Item, error) {
	req, err := p.Request(target)
	if err != nil {
		return transport.Item{}, err
	}
	return buildItem(id, target, connSecret, MethodCashWithdrawQuote, req, p.Credential, b)
}

// SliceIdentity is the slice a credential names, as a quote's i tag carries it:
// identity_value, and ia_pubkey for a connection_key slice. A BySecret
// credential names the cash commitment of its secret.
func SliceIdentity(cred Credential) (identityValue, iaPubkey string, err error) {
	switch c := cred.(type) {
	case signingCredential:
		pub, err := utils.GetPublicKey(c.privKeyHex)
		return pub, "", err
	case connectionKeyCredential:
		return c.attestation.ConnectionKey.String(), c.attestation.PubKey, nil
	case secretCredential:
		commit, err := CashCommitment(c.secret)
		return commit, "", err
	}
	return "", "", errors.New("nipcash: no slice for this credential")
}

// CashWithdrawQuoteResult is cash_withdraw_quote's answer.
type CashWithdrawQuoteResult struct {
	Quote            string `json:"quote"`
	Address          string `json:"address"`
	AmountMillis     uint64 `json:"amount_millis"`
	NetworkFeeMillis uint64 `json:"network_fee_millis"`
	HubFeeMillis     uint64 `json:"hub_fee_millis"`
	FeeMillis        uint64 `json:"fee_millis"`
	PayoutMillis     uint64 `json:"payout_millis"`
	SentBy           int64  `json:"sent_by"`
	HoldsUntil       int64  `json:"holds_until"`
}

// ParseCashWithdrawQuoteResult reads a quote answer: a tombstone is *BillGone;
// every field present and of its type.
func ParseCashWithdrawQuoteResult(data []byte) (*CashWithdrawQuoteResult, error) {
	if err := goneIf(MethodCashWithdrawQuote, data); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("nipcash: cash_withdraw_quote answer: %w", err)
	}
	for _, k := range []string{"quote", "address", "amount_millis", "network_fee_millis", "hub_fee_millis", "fee_millis", "payout_millis", "sent_by", "holds_until"} {
		if _, ok := fields[k]; !ok {
			return nil, fmt.Errorf("nipcash: cash_withdraw_quote answer has no %s", k)
		}
	}
	var r CashWithdrawQuoteResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("nipcash: cash_withdraw_quote answer: %w", err)
	}
	return &r, nil
}

// QuoteFields are what a quote event binds.
type QuoteFields struct {
	// Wallet is the bill's wallet pubkey (d).
	Wallet string
	// IdentityValue and IAPubkey are the slice (i); IAPubkey only for a
	// connection_key slice.
	IdentityValue, IAPubkey                                    string
	Address                                                    string
	AmountMillis, NetworkFeeMillis, HubFeeMillis, PayoutMillis uint64
	SentBy, HoldsUntil                                         int64
}

// WithdrawQuote is a parsed kind-23187 quote: the event, its id and its tags.
type WithdrawQuote struct {
	Event *nip01.Event
	ID    string
	QuoteFields
}

// FeeMillis is amount − payout.
func (q *WithdrawQuote) FeeMillis() uint64 { return q.AmountMillis - q.PayoutMillis }

// Raw is the quote event JSON-encoded, as cash_withdraw carries it.
func (q *WithdrawQuote) Raw() (string, error) {
	if q == nil || q.Event == nil {
		return "", errors.New("nipcash: no quote")
	}
	b, err := json.Marshal(q.Event)
	return string(b), err
}

// quoteTagNames are the quote's nine tags, in the spec's table order.
var quoteTagNames = []string{"d", "i", "address", "amount_millis", "network_fee_millis", "hub_fee_millis", "payout_millis", "sent_by", "holds_until"}

func (f QuoteFields) tags() [][]string {
	i := []string{"i", f.IdentityValue}
	if f.IAPubkey != "" {
		i = append(i, f.IAPubkey)
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	return [][]string{
		{"d", f.Wallet}, i, {"address", f.Address},
		{"amount_millis", u(f.AmountMillis)}, {"network_fee_millis", u(f.NetworkFeeMillis)},
		{"hub_fee_millis", u(f.HubFeeMillis)}, {"payout_millis", u(f.PayoutMillis)},
		{"sent_by", strconv.FormatInt(f.SentBy, 10)}, {"holds_until", strconv.FormatInt(f.HoldsUntil, 10)},
	}
}

// NewWithdrawQuoteEvent builds the Hub's quote event: kind 23187, created_at,
// the nine tags in table order, empty content, signed by sign (the node
// identity: it sets pubkey, id and sig).
func NewWithdrawQuoteEvent(f QuoteFields, createdAt int64, sign func(*nip01.Event) error) (*nip01.Event, error) {
	switch {
	case !isLowerHex64(f.Wallet), !isLowerHex64(f.IdentityValue), f.IAPubkey != "" && !isLowerHex64(f.IAPubkey):
		return nil, errors.New("nipcash: a quote's d and i are 64 lowercase hex")
	case f.Address == "", f.SentBy < 0, f.HoldsUntil < 0, createdAt < 0:
		return nil, errors.New("nipcash: a quote needs an address and non-negative times")
	case f.PayoutMillis > f.AmountMillis:
		return nil, errors.New("nipcash: a quote's payout exceeds its amount")
	}
	ev := &nip01.Event{Kind: KindWithdrawQuote, CreatedAt: uint64(createdAt), Tags: f.tags(), Content: ""}
	if err := sign(ev); err != nil {
		return nil, fmt.Errorf("nipcash: sign quote: %w", err)
	}
	return ev, nil
}

// ParseWithdrawQuote reads a quote's structure (NIP-CASH §Quoting a
// Withdrawal): a JSON event of kind 23187 with empty content and exactly the
// nine tags, each once, in any order; d and i values 64 lowercase hex (i with
// two or three elements); numbers unsigned decimal without leading zeros. It
// does not check the signature (VerifyWithdrawQuote does). A refusal is a
// *WithdrawError with code BAD_REQUEST.
func ParseWithdrawQuote(raw string) (*WithdrawQuote, error) {
	bad := func(reason string) error {
		return withdrawErr(ErrCodeBadRequest, "", 0, "malformed quote: "+reason)
	}
	var ev nip01.Event
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return nil, bad("not an event")
	}
	switch {
	case ev.Kind != KindWithdrawQuote:
		return nil, bad("kind " + strconv.Itoa(ev.Kind))
	case ev.Content != "":
		return nil, bad("content is not empty")
	case !isLowerHex64(ev.ID), !isLowerHex64(ev.PubKey), len(ev.Sig) != 128 || !isLowerHex(ev.Sig):
		return nil, bad("id, pubkey or sig")
	}
	vals, err := uniqueTags(ev.Tags, quoteTagNames, map[string]int{"i": 3})
	if err != nil {
		return nil, bad(err.Error())
	}
	q := &WithdrawQuote{Event: &ev, ID: ev.ID}
	q.Wallet, q.Address = vals["d"][0], vals["address"][0]
	q.IdentityValue = vals["i"][0]
	if len(vals["i"]) == 2 {
		q.IAPubkey = vals["i"][1]
		if !isLowerHex64(q.IAPubkey) {
			return nil, bad("i ia_pubkey")
		}
	}
	if !isLowerHex64(q.Wallet) || !isLowerHex64(q.IdentityValue) {
		return nil, bad("d or i")
	}
	if q.Address == "" {
		return nil, bad("empty address")
	}
	for _, n := range []struct {
		name string
		dst  *uint64
	}{{"amount_millis", &q.AmountMillis}, {"network_fee_millis", &q.NetworkFeeMillis}, {"hub_fee_millis", &q.HubFeeMillis}, {"payout_millis", &q.PayoutMillis}} {
		v, ok := canonicalUint(vals[n.name][0])
		if !ok {
			return nil, bad(n.name)
		}
		*n.dst = v
	}
	for _, n := range []struct {
		name string
		dst  *int64
	}{{"sent_by", &q.SentBy}, {"holds_until", &q.HoldsUntil}} {
		v, ok := canonicalUint(vals[n.name][0])
		if !ok || v > math.MaxInt64 {
			return nil, bad(n.name)
		}
		*n.dst = int64(v)
	}
	if q.PayoutMillis > q.AmountMillis {
		return nil, bad("payout exceeds amount")
	}
	return q, nil
}

// uniqueTags requires exactly the named tags, each once, each with one value
// (or up to maxLen[name] elements), and returns their values.
func uniqueTags(tags [][]string, names []string, maxLen map[string]int) (map[string][]string, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string][]string{}
	for _, t := range tags {
		if len(t) == 0 {
			return nil, errors.New("empty tag")
		}
		name := t[0]
		if !want[name] {
			return nil, fmt.Errorf("unexpected tag %q", name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("repeated tag %q", name)
		}
		limit := 2
		if l, ok := maxLen[name]; ok {
			limit = l
		}
		if len(t) < 2 || len(t) > limit {
			return nil, fmt.Errorf("tag %q has %d elements", name, len(t))
		}
		out[name] = t[1:]
	}
	for _, n := range names {
		if _, ok := out[n]; !ok {
			return nil, fmt.Errorf("missing tag %q", n)
		}
	}
	return out, nil
}

// canonicalUint parses an unsigned decimal with no leading zeros.
func canonicalUint(s string) (uint64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// VerifyWithdrawQuote checks a parsed quote's recomputed id, its signature and
// that its author is hubXOnly, the Hub's node identity. A failure is
// RESTRICTED with detail quote_invalid.
func VerifyWithdrawQuote(q *WithdrawQuote, hubXOnly string) error {
	invalid := func(reason string) error {
		return withdrawErr(ErrCodeRestricted, DetailQuoteInvalid, 1, reason)
	}
	if q == nil || q.Event == nil {
		return invalid("no quote")
	}
	if err := q.Event.Verify(nip01.WithoutPowCheck()); err != nil || q.ID != q.Event.ID {
		return invalid("the quote's id or signature does not verify")
	}
	if !HubIdentityEqual(hubXOnly, q.Event.PubKey) {
		return invalid("the quote is not signed by this Hub")
	}
	return nil
}

// QuoteForSlice is the Hub's cash_withdraw step-3 row-1 check (NIP-CASH
// §Processing Algorithm): q verifies as VerifyWithdrawQuote with hubXOnly, and
// it is for this bill and slice: d is wallet, i is the slice's identity value
// and IA pubkey (empty unless connection_key), and amount_millis is the slice's
// committed amount now. The amount matters: an in-place transfer can give the
// same identity another slice of another amount on the same wallet, and a
// quote for the old amount must not pay out against it. A failure is
// RESTRICTED with detail quote_invalid.
func QuoteForSlice(q *WithdrawQuote, hubXOnly, wallet, identityValue, iaPubkey string, amountMillis uint64) error {
	if err := VerifyWithdrawQuote(q, hubXOnly); err != nil {
		return err
	}
	if q.Wallet != wallet || q.IdentityValue != identityValue || q.IAPubkey != iaPubkey || q.AmountMillis != amountMillis {
		return withdrawErr(ErrCodeRestricted, DetailQuoteInvalid, 1, "the quote is not for this bill and slice")
	}
	return nil
}

// QuoteExpectation is what the client asked about, to check a quote answer
// against: the Hub's identity (x-only), the bill, the slice, the address as
// sent, any send_before, and from the caller's own cash_status row the slice's
// amount and redeem fee (nil: not checked).
type QuoteExpectation struct {
	HubXOnly, Wallet, IdentityValue, IAPubkey, Address string
	SendBefore                                         *int64
	AmountMillis                                       uint64
	RedeemFeeMillis                                    *uint64
}

// ErrQuoteMismatch is a quote answer that fails a client check; it wraps the
// name of the field, never its value.
var ErrQuoteMismatch = errors.New("nipcash: the withdraw quote does not match")

// VerifyQuoteAnswer runs the client's checks on a quote answer (NIP-CASH
// §Quoting a Withdrawal): the quote parses, its id and signature verify and it
// is by HubXOnly; each tag equals its answer field (fee_millis as amount −
// payout); d and i name the slice asked about, exactly; address is the one
// sent, byte for byte; sent_by is no later than any send_before. Then the
// plan's checks: a payout of whole base units, the amount of the caller's own
// row, and a fee no lower than the slice's redeem fee.
func VerifyQuoteAnswer(res CashWithdrawQuoteResult, e QuoteExpectation) (*WithdrawQuote, error) {
	mismatch := func(field string) error { return fmt.Errorf("%w: %s", ErrQuoteMismatch, field) }
	q, err := ParseWithdrawQuote(res.Quote)
	if err != nil {
		return nil, mismatch("quote")
	}
	if VerifyWithdrawQuote(q, e.HubXOnly) != nil {
		return nil, mismatch("signature")
	}
	switch {
	case res.Address != q.Address:
		return nil, mismatch("address")
	case res.AmountMillis != q.AmountMillis:
		return nil, mismatch("amount_millis")
	case res.NetworkFeeMillis != q.NetworkFeeMillis:
		return nil, mismatch("network_fee_millis")
	case res.HubFeeMillis != q.HubFeeMillis:
		return nil, mismatch("hub_fee_millis")
	case res.PayoutMillis != q.PayoutMillis:
		return nil, mismatch("payout_millis")
	case res.FeeMillis != q.FeeMillis():
		return nil, mismatch("fee_millis")
	case res.SentBy != q.SentBy:
		return nil, mismatch("sent_by")
	case res.HoldsUntil != q.HoldsUntil:
		return nil, mismatch("holds_until")
	case q.Wallet != e.Wallet:
		return nil, mismatch("d")
	case q.IdentityValue != e.IdentityValue, q.IAPubkey != e.IAPubkey:
		return nil, mismatch("i")
	case q.Address != e.Address:
		return nil, mismatch("address")
	case e.SendBefore != nil && q.SentBy > *e.SendBefore:
		return nil, mismatch("sent_by")
	case q.PayoutMillis%1000 != 0:
		return nil, mismatch("payout_millis")
	case q.AmountMillis != e.AmountMillis:
		return nil, mismatch("amount_millis")
	case e.RedeemFeeMillis != nil && q.FeeMillis() < *e.RedeemFeeMillis:
		return nil, mismatch("fee_millis")
	}
	return q, nil
}

// QuoteValidAt reports a quote valid at a chain tip: tip ≤ holds_until.
func QuoteValidAt(holdsUntil, tipHeight int64) bool { return tipHeight <= holdsUntil }
