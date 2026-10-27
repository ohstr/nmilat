// Package nipCZ implements NIP-CZ (Cash Zaps): a zap paid with a NIP-CASH cash
// token instead of a Lightning invoice.
//
// A sender transfers a bill it holds to the recipient's identity (ZapTransfer,
// sent through nipcash/client) and publishes the new token in a kind 9522 event
// (NewCashZap). A recipient lists the chains, minters and relays it accepts in a
// kind 10522 event (ParseCashZapInfo). A client verifies a 9522 with
// VerifyClient (rules 1-8) and may total it (Count); a recipient's wallet
// verifies it with VerifyWallet (rules 1-6, 8 and 9) before treating the cash as
// its own. Rules 1-8 show that a trusted Hub issued the amount to the recipient,
// never that the value is still there: only rule 9 does.
//
// Spec: https://github.com/ohstr/nips/blob/main/NIP-CZ.md
package nipCZ

import (
	"errors"
	"fmt"
	"strconv"
)

// Event kinds (NIP-CZ §Event Kinds).
const (
	// KindCashZap is a Cash Zap, signed by the sender or a Proxy Agent (regular).
	KindCashZap = 9522
	// KindCashZapInfo is a recipient's Cash Zap Info (replaceable).
	KindCashZapInfo = 10522
)

var (
	// ErrWrongKind is an event of another kind given to a parser.
	ErrWrongKind = errors.New("nipCZ: unexpected event kind")
	// ErrChainNotAccepted is a send to a recipient whose 10522 lists none of the
	// chains the sender holds bills on (NIP-CZ §Sending 1).
	ErrChainNotAccepted = errors.New("nipCZ: the recipient accepts none of these chains")
	// ErrZapNeedsPubkeyBill is a zap on an event from a bill bound to a
	// ConnectionKey: a Hub refuses zap_target on it, so the sender first moves it
	// to the pubkey that will sign the 9522 with a full cash_transfer.
	ErrZapNeedsPubkeyBill = errors.New("nipCZ: a zap on an event needs a bill bound to the signing pubkey; move the bill to that pubkey first")
	// ErrZapCashTarget is a zap whose new_identity would be cash mode: its secret
	// is not in the token, so only the sender could redeem it.
	ErrZapCashTarget = errors.New("nipCZ: a Cash Zap is never sent to a cash-mode identity")
	// ErrZapTargetForConnectionKey is a zap on an event to a ConnectionKey:
	// zap_target requires a pubkey recipient.
	ErrZapTargetForConnectionKey = errors.New("nipCZ: a zap to a ConnectionKey carries no zap_target")
	// ErrZapIARequired is a ConnectionKey recipient without the IA that vouches
	// for it.
	ErrZapIARequired = errors.New("nipCZ: a zap to a ConnectionKey names its Identity Authority")
	// ErrZapIAForPubkey is an IA given for a pubkey recipient.
	ErrZapIAForPubkey = errors.New("nipCZ: a zap to a pubkey carries no ia")
	// ErrAmount is a zero amount, or one that differs from the token's attested
	// amount.
	ErrAmount = errors.New("nipCZ: the zap amount is positive and equals the token's attested amount")
	// ErrIdentity is a p or P value that is not 64 lowercase hex, or a platform
	// name outside [a-z0-9._-]+.
	ErrIdentity = errors.New("nipCZ: malformed identity")
	// ErrNoTransferResult is a Cash Zap built without the transfer reply that
	// created its bill: no 9522 exists without a reply.
	ErrNoTransferResult = errors.New("nipCZ: a Cash Zap is built from its transfer's reply")
	// ErrTokenWallet is a token whose wallet pubkey (TLV 0) is not the w the
	// transfer reply names.
	ErrTokenWallet = errors.New("nipCZ: the token's wallet pubkey is not the transfer's new wallet")
	// ErrZapNotSigned is a zap bill (TLV 8 = 2) whose transfer reply lacks the
	// signed issued_at and expires_at the 9522 must carry.
	ErrZapNotSigned = errors.New("nipCZ: a zap bill needs its signed issued_at and expires_at")
	// ErrNoTarget is a zap context asked of a Cash Zap with neither e nor a.
	ErrNoTarget = errors.New("nipCZ: the Cash Zap names no target event")
	// ErrNotPubkeyZap is a zap context asked of a Cash Zap to a ConnectionKey.
	ErrNotPubkeyZap = errors.New("nipCZ: only a zap to a pubkey carries a zap signature")
	// ErrNoVerifiedCopy is a set of copies none of which has a token whose
	// signature recovers a Minter (rule 6).
	ErrNoVerifiedCopy = errors.New("nipCZ: no copy of the token verifies")
	// ErrCopiesDisagree is copies whose tokens recover different Minters; a
	// caller resolves it by trust (SelectTrustedCopy) and never dials the rest.
	ErrCopiesDisagree = errors.New("nipCZ: copies of the token recover different minters")
	// ErrCopiesOfDifferentTokens is copies whose w tags differ.
	ErrCopiesOfDifferentTokens = errors.New("nipCZ: the copies carry different tokens")
)

// RuleError is a Cash Zap that fails one rule of the §Verification Algorithm.
type RuleError struct {
	Rule   int
	Reason string
}

func (e *RuleError) Error() string { return fmt.Sprintf("nipCZ: rule %d: %s", e.Rule, e.Reason) }

func ruleErr(n int, format string, args ...any) *RuleError {
	return &RuleError{Rule: n, Reason: fmt.Sprintf(format, args...)}
}

// parseDecimal reads unsigned decimal ASCII with no leading zeros ("0" for
// zero), refusing a sign, a fraction, whitespace and an overflow.
func parseDecimal(s string) (uint64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// minterKey is a key's x-only form for comparison with a Minter: a 33-byte
// compressed key (66 hex, prefix 02 or 03) loses its prefix byte; a 64-hex
// x-only key (an announcement author, a get_info pubkey) is kept. Anything else
// is "" and matches nothing.
func minterKey(s string) string {
	switch {
	case len(s) == 66 && (s[:2] == "02" || s[:2] == "03") && isLowerHex(s, 66):
		return s[2:]
	case isLowerHex(s, 64):
		return s
	}
	return ""
}

// SameMinter reports whether two keys name the same Minter, comparing their
// x-only parts only (NIP-CZ §Terminology): a compressed key with either prefix,
// an x-only author and a Cash Hub get_info pubkey all match when their last 32
// bytes do. Keys are lowercase hex; any other form matches nothing.
func SameMinter(a, b string) bool {
	x := minterKey(a)
	return x != "" && x == minterKey(b)
}
