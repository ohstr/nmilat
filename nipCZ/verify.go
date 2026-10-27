package nipCZ

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
)

// Trust is the reader's own minter trust, for the one network its wallet runs
// on: neither a token nor its signature names the network, so trust is never
// keyed across networks (NIP-CZ §Kind 10522).
type Trust interface {
	// TrustsMinter reports a minter (x-only, 64 lowercase hex) trusted for chain.
	TrustsMinter(minterXOnly, chain string) bool
}

// ProxyTrust is an optional Trust extension: the Proxy Agents (9522 signers)
// whose P a client credits. Without it no P is credited.
type ProxyTrust interface {
	TrustsProxy(signerPubkey string) bool
}

// RuleResult is one rule of the §Verification Algorithm. Skipped is a rule not
// evaluated, because an earlier one failed or (rule 9) the minter may not be
// contacted or no check was supplied. Err is rule 9's own error, so a caller
// can tell a timeout (never "spent") from a refusal.
type RuleResult struct {
	N           int
	OK, Skipped bool
	Reason      string
	Err         error
}

// Verdict is the outcome of VerifyClient or VerifyWallet.
type Verdict struct {
	Rules []RuleResult
	// Minter is the key the token's signature recovers (33-byte compressed, hex),
	// "" when rule 6 fails.
	Minter string
	// ZapSigned is a token with TLV 8 = 2 whose zap signature recovers over the
	// payload rebuilt from this event, with a target and both times (rule 7).
	// Recovery over a payload the Minter never signed (a re-tagged copy) yields
	// some other key, which rule 8 then refuses: only ExpiresAtTrusted and
	// Countable say the Minter is one the reader accepts.
	ZapSigned bool
	// Countable is a client verdict passing rules 1-8 with no NIP-40 expiration
	// tag; Reason says why not. A wallet verdict is never Countable.
	Countable bool
	// ExpiresAtTrusted is issued_at/expires_at proven by a zap signature from a
	// minter the reader trusts or the recipient lists (or, for a wallet, the
	// user approved); otherwise they are informational and a wallet takes
	// expires_at from cash_status.
	ExpiresAtTrusted bool
	// CreditSender is a P the reader may credit: the signer is a Proxy Agent the
	// reader trusts (ProxyTrust). Otherwise the zap shows as sent via the signer.
	CreditSender bool
	// MinterUnlisted is a minter neither trusted by the reader nor listed in the
	// recipient's 10522 for the zap's chain: only the user's approval can pass
	// rule 8, after a warning that the minter's network cannot be verified.
	MinterUnlisted bool
	// Reason is why a client verdict is not Countable, "" when it is.
	Reason string
}

// Rule returns rule n's result, and false when the verdict has none.
func (v Verdict) Rule(n int) (RuleResult, bool) {
	for _, r := range v.Rules {
		if r.N == n {
			return r, true
		}
	}
	return RuleResult{}, false
}

// Valid reports rules 1-6 met: the event is well formed and its token's
// signature recovers a Minter for its amount. A relay that validates refuses
// anything else.
func (v Verdict) Valid() bool {
	for n := 1; n <= 6; n++ {
		if r, ok := v.Rule(n); !ok || !r.OK {
			return false
		}
	}
	return true
}

// Received reports that a wallet verdict passed every rule including rule 9,
// the only one that proves the cash is the recipient's. A client verdict is
// never Received: clients MUST NOT present a 9522 as value received.
func (v Verdict) Received() bool {
	r9, ok := v.Rule(9)
	if !ok || !r9.OK || !v.Valid() {
		return false
	}
	r8, ok := v.Rule(8)
	return ok && r8.OK
}

// MayContactMinter reports whether a wallet may contact the zap's Minter: rules
// 1-6 met and the minter trusted or listed, or approved by the user.
func (v Verdict) MayContactMinter(approved bool) bool {
	return v.Valid() && v.Minter != "" && (!v.MinterUnlisted || approved)
}

// verifier accumulates rule results.
type verifier struct{ v Verdict }

func (w *verifier) pass(n int) { w.v.Rules = append(w.v.Rules, RuleResult{N: n, OK: true}) }
func (w *verifier) fail(n int, reason string) {
	w.v.Rules = append(w.v.Rules, RuleResult{N: n, Reason: reason})
}
func (w *verifier) skip(reason string, ns ...int) {
	for _, n := range ns {
		w.v.Rules = append(w.v.Rules, RuleResult{N: n, Skipped: true, Reason: reason})
	}
}

// structural runs rules 1-6 shared by both columns. It returns the parsed zap
// and the recovered minter, or nil after recording the failure and skipping
// the rest of the column (rest).
func (w *verifier) structural(ev, target *nip01.Event, rest []int) *CashZap {
	if ev == nil || ev.Kind != KindCashZap {
		w.fail(1, "not a kind 9522 event")
		w.skip("rule 1 failed", rest...)
		return nil
	}
	if err := ev.Verify(); err != nil {
		w.fail(1, fmt.Sprintf("signature: %v", err))
		w.skip("rule 1 failed", rest...)
		return nil
	}
	w.pass(1)
	z, rerr := parseCashZap(ev)
	if rerr == nil && target != nil && z.E != "" && z.A != "" {
		if want, err := ZapTargetFor(target); err != nil || z.A != want || z.E != target.ID {
			rerr = ruleErr(2, "e and a do not both name the target event")
		}
	}
	if rerr != nil {
		for n := 2; n < rerr.Rule; n++ {
			w.pass(n)
		}
		w.fail(rerr.Rule, rerr.Reason)
		w.skip(fmt.Sprintf("rule %d failed", rerr.Rule), after(rest, rerr.Rule)...)
		return nil
	}
	w.pass(2)
	w.pass(3)
	if c, known := ChainForHRP(z.Token.HRP); known && c.Name != z.Chain {
		w.fail(4, fmt.Sprintf("token prefix %s is chain %s, not %s", z.Token.HRP, c.Name, z.Chain))
		w.skip("rule 4 failed", after(rest, 4)...)
		return nil
	}
	w.pass(4)
	if z.Token.IdentityRequired != nil && !*z.Token.IdentityRequired {
		w.fail(5, "the token's identity-required hint (TLV 3) is not 1")
		w.skip("rule 5 failed", after(rest, 5)...)
		return nil
	}
	w.pass(5)
	minter, reason := provenance(z)
	if minter == "" {
		w.fail(6, reason)
		w.skip("rule 6 failed", after(rest, 6)...)
		return nil
	}
	w.pass(6)
	w.v.Minter = minter
	return z
}

func after(rules []int, n int) []int {
	var out []int
	for _, r := range rules {
		if r > n {
			out = append(out, r)
		}
	}
	return out
}

// provenance is rule 6: the token's signature recovers a Minter over the
// payload of its own scheme (a scheme-2 payload rebuilt from the event), and
// its attested amount equals amount. No legacy payload is tried.
func provenance(z *CashZap) (minter, reason string) {
	var ok bool
	switch z.Token.Scheme {
	case nipcash.SchemeMintV1:
		minter, ok = nipcash.VerifyProvenance(z.Token)
	case nipcash.SchemeZapV1:
		zc, err := ZapContextFromEvent(z)
		if err != nil {
			return "", fmt.Sprintf("the zap payload cannot be rebuilt: %v", err)
		}
		minter, ok = nipcash.VerifyZapProvenance(z.Token, zc)
	default:
		return "", "the token carries no valid provenance (TLV 8 absent or malformed)"
	}
	if !ok {
		return "", "the token's signature recovers no Minter (unknown prefix or bad signature)"
	}
	if z.Token.AttestedAmountMillis == nil || *z.Token.AttestedAmountMillis != z.Amount {
		return "", "the token's attested amount (TLV 6) is not amount"
	}
	return minter, ""
}

// zapSignature is rule 7: a pubkey p, an e or a tag, both times, a zap
// signature over the rebuilt payload (rule 6 already recovered it), p the
// target's author and, on an e target, issued_at not before its created_at.
// target may be nil: an a tag names its author; an e tag alone then cannot be
// checked and fails.
func zapSignature(z *CashZap, target *nip01.Event) (bool, string) {
	switch {
	case z.Token.Scheme != nipcash.SchemeZapV1:
		return false, "the token carries no zap signature (TLV 8 is not 2)"
	case z.Recipient.IsConnectionKey():
		return false, "a ConnectionKey zap carries no zap signature"
	case z.E == "" && z.A == "":
		return false, "the zap names no target event"
	case z.IssuedAt == nil || z.ExpiresAt == nil:
		return false, "issued_at or expires_at is missing"
	}
	var author string
	switch {
	case target != nil:
		want, err := ZapTargetFor(target)
		if err != nil {
			return false, "the target event has no zap target"
		}
		if (z.A != "" && z.A != want) || (z.A == "" && z.E != target.ID) {
			return false, "the zap does not name the target event"
		}
		author = target.PubKey
		if z.A == "" && *z.IssuedAt < target.CreatedAt {
			return false, "issued_at is earlier than the target's created_at"
		}
	case z.A != "":
		_, pk, _, ok := parseCoordinate(z.A)
		if !ok {
			return false, "the a tag is not a coordinate"
		}
		author = pk
	default:
		return false, "the target event is needed to check its author"
	}
	if author != z.Recipient.Value {
		return false, "p is not the target's author"
	}
	return true, ""
}

// minterTrust is rule 8 without approval.
func minterTrust(minter, chain string, info *CashZapInfo, trust Trust, recipient Identity) (trusted bool) {
	x := minterKey(minter)
	if x == "" {
		return false
	}
	if trust != nil && trust.TrustsMinter(x, chain) {
		return true
	}
	if info != nil && !recipient.IsConnectionKey() && (info.Pubkey == "" || info.Pubkey == recipient.Value) {
		return info.ListsMinter(x, chain)
	}
	return false
}

// VerifyClient applies the Client column, rules 1-8, to a 9522 with its target
// event (nil when it has none or the reader lacks it), the recipient's 10522
// (nil without one) and the reader's trust. Rules 1-6 decide validity (a relay
// that validates refuses the rest); rules 7 and 8 only decide counting. Rule 9
// is never run: a client never presents a 9522 as value received.
func VerifyClient(ev, target *nip01.Event, info *CashZapInfo, trust Trust) Verdict {
	w := &verifier{}
	z := w.structural(ev, target, []int{2, 3, 4, 5, 6, 7, 8})
	if z == nil {
		w.v.Reason = "invalid"
		return w.v
	}
	ok7, reason7 := zapSignature(z, target)
	if ok7 {
		w.pass(7)
	} else {
		w.fail(7, reason7)
	}
	trusted := minterTrust(w.v.Minter, z.Chain, info, trust, z.Recipient)
	w.v.MinterUnlisted = !trusted
	if trusted {
		w.pass(8)
	} else {
		w.fail(8, "the Minter is neither trusted by the reader nor listed in the recipient's 10522 for "+z.Chain)
	}
	w.v.ZapSigned = ok7
	w.v.ExpiresAtTrusted = ok7 && trusted
	w.v.CreditSender = creditSender(z, trust)
	switch {
	case !ok7:
		w.v.Reason = "rule 7: " + reason7
	case !trusted:
		w.v.Reason = "rule 8: the Minter is not trusted"
	case z.HasExpirationTag:
		w.v.Reason = "a Cash Zap carries no NIP-40 expiration tag"
	default:
		w.v.Countable = true
	}
	return w.v
}

func creditSender(z *CashZap, trust Trust) bool {
	if z.Sender == nil || !z.Sender.IsConnectionKey() {
		return false
	}
	pt, ok := trust.(ProxyTrust)
	return ok && pt.TrustsProxy(z.Event.PubKey)
}

// Rule9 is a wallet's rule 9 check, run only once rules 1-6 and 8 pass: for a
// pubkey p, cash_status with scope mine (CheckStatus); for a ConnectionKey p, a
// full in-place cash_transfer to the recipient's pubkey with the attestation
// from ia (CheckInPlaceTransfer). An error, a timeout included, is "not
// received", never "spent".
type Rule9 func(context.Context, *CashZap) error

// VerifyWallet applies the Recipient wallet column, rules 1-6, 8 and 9.
// approved is the user's approval of an unlisted minter. rule9 is never called
// unless the wallet may contact the minter; nil leaves rule 9 skipped.
func VerifyWallet(ctx context.Context, ev *nip01.Event, info *CashZapInfo, trust Trust, approved bool, rule9 func(context.Context, *CashZap) error) Verdict {
	w := &verifier{}
	z := w.structural(ev, nil, []int{2, 3, 4, 5, 6, 8, 9})
	if z == nil {
		return w.v
	}
	trusted := minterTrust(w.v.Minter, z.Chain, info, trust, z.Recipient)
	w.v.MinterUnlisted = !trusted
	// The wallet column has no rule 7: rule 6 already recovered a scheme-2
	// signature over the payload rebuilt from this event, which is what proves
	// its issued_at and expires_at.
	ok7 := z.Token.Scheme == nipcash.SchemeZapV1
	w.v.ZapSigned = ok7
	w.v.ExpiresAtTrusted = ok7 && (trusted || approved)
	w.v.CreditSender = creditSender(z, trust)
	if !trusted && !approved {
		w.fail(8, "the Minter is not trusted or listed, and the user has not approved it")
		w.skip("the Minter may not be contacted", 9)
		return w.v
	}
	w.pass(8)
	if rule9 == nil {
		w.skip("no rule 9 check supplied", 9)
		return w.v
	}
	if err := rule9(ctx, z); err != nil {
		w.v.Rules = append(w.v.Rules, RuleResult{N: 9, Reason: rule9Reason(err), Err: err})
		return w.v
	}
	w.pass(9)
	return w.v
}

func rule9Reason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "no answer: the state is unknown, never spent"
	}
	return err.Error()
}

// Rule 9 failures.
var (
	// ErrRule9Gone is a bill the Hub reports destroyed (a tombstone).
	ErrRule9Gone = errors.New("nipCZ: rule 9: the bill is gone")
	// ErrRule9NoRow is a cash_status answer with no row for the recipient.
	ErrRule9NoRow = errors.New("nipCZ: rule 9: no slice of the bill is the recipient's")
	// ErrRule9Claimed is the recipient's slice already claimed.
	ErrRule9Claimed = errors.New("nipCZ: rule 9: the recipient's slice is claimed")
	// ErrRule9Amount is the recipient's slice not equal to amount: others share
	// the bill.
	ErrRule9Amount = errors.New("nipCZ: rule 9: the recipient's slice is not the zap amount")
	// ErrRule9NotInPlace is a ConnectionKey claim that was not a full in-place
	// transfer of amount.
	ErrRule9NotInPlace = errors.New("nipCZ: rule 9: the claim was not a full in-place transfer of the zap amount")
)

// CheckStatus is rule 9 for a pubkey p on a cash_status (scope mine) answer:
// the recipient's own row, unclaimed, for exactly amount. A nil result is an
// error, never "spent".
func CheckStatus(z *CashZap, res *nipcash.CashStatusResult) error {
	if res == nil {
		return errors.New("nipCZ: rule 9: no cash_status answer")
	}
	if res.Tombstone != nil {
		return ErrRule9Gone
	}
	for _, row := range res.Recipients {
		if row.IdentityType != "pubkey" || row.IdentityValue != z.Recipient.Value {
			continue
		}
		switch {
		case row.Claimed:
			return ErrRule9Claimed
		case row.AmountMillis != z.Amount:
			return ErrRule9Amount
		}
		return nil
	}
	return ErrRule9NoRow
}

// CheckInPlaceTransfer is rule 9 for a ConnectionKey p on the reply to its
// full in-place cash_transfer to the recipient's pubkey: no new wallet, and
// exactly amount moved.
func CheckInPlaceTransfer(z *CashZap, res *nipcash.CashTransferResult) error {
	if res == nil || res.NewWalletPubkey != "" || res.NewWalletToken != "" || res.AmountMillis != z.Amount {
		return ErrRule9NotInPlace
	}
	return nil
}

// BelowRedeemFee reports a zap at or below the Hub's base redeem fee, which can
// only be consolidated or redeemed same-node; a wallet MAY show it as "below
// the redeem fee, combine with others" (NIP-CZ §Receiving).
func BelowRedeemFee(amountMillis, baseFeeMillis uint64) bool { return amountMillis <= baseFeeMillis }

// ValidateForRelay is what a relay that validates a 9522 applies: the Client
// column's rules 1-6, which refuse. Rules 7 and 8 only decide counting, so
// they never refuse an event, and rule 9 is never run (a relay never contacts a
// Minter). The error is the first failing rule's *RuleError.
func ValidateForRelay(ev *nip01.Event) error {
	for _, r := range VerifyClient(ev, nil, nil, nil).Rules {
		if r.N <= 6 && !r.OK && !r.Skipped {
			return &RuleError{Rule: r.N, Reason: r.Reason}
		}
	}
	return nil
}
