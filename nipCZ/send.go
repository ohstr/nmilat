package nipCZ

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
)

// ZapTransfer builds the cash_transfer of a Cash Zap (NIP-CZ §Sending 2): the
// zap amount (amount_millis) to the recipient's identity, with zap_target for a
// pubkey recipient and a target event, and a fresh request_id (replace it with
// the one the caller's journal holds when re-sending). src proves control of
// the bill; srcIsPubkey says it is bound to a pubkey (the one that will sign the
// 9522). The claim and item proofs are both signed with src's key when the
// params are sent through nipcash/client.
//
// It refuses a bill bound to a ConnectionKey with a target
// (ErrZapNeedsPubkeyBill: move it to the signing pubkey first), a cash-mode
// recipient, a ConnectionKey recipient with a target or without ia, and ia for a
// pubkey recipient. CurrentAmount is set to amount; a caller holding a larger
// slice may raise it, which changes nothing on the wire.
func ZapTransfer(src nipcash.Credential, srcIsPubkey bool, to Identity, ia string, amount uint64, target *nip01.Event) (nipcash.CashTransferParams, error) {
	var params nipcash.CashTransferParams
	if src == nil {
		return params, fmt.Errorf("nipCZ: no credential for the bill")
	}
	if amount == 0 {
		return params, ErrAmount
	}
	if to.Platform == "cash" {
		return params, ErrZapCashTarget
	}
	if !to.valid() {
		return params, ErrIdentity
	}
	var newIdentity nipcash.Target
	if to.IsConnectionKey() {
		switch {
		case target != nil:
			return params, ErrZapTargetForConnectionKey
		case ia == "":
			return params, ErrZapIARequired
		}
		ck, err := nipcash.ResolvedConnectionKey(nipIC.ConnectionKey(to.Value), nipIC.WebIdentity(to.Platform), ia)
		if err != nil {
			return params, err
		}
		newIdentity = ck
	} else {
		if ia != "" {
			return params, ErrZapIAForPubkey
		}
		newIdentity = nipcash.Pubkey(to.Value)
	}
	zapTarget := ""
	if target != nil {
		if !srcIsPubkey {
			return params, ErrZapNeedsPubkeyBill
		}
		t, err := ZapTargetFor(target)
		if err != nil {
			return params, err
		}
		zapTarget = t
	}
	rid, err := nipcash.NewRequestID()
	if err != nil {
		return params, err
	}
	amt := amount
	return nipcash.CashTransferParams{
		Credential: src, To: newIdentity, CurrentAmount: amount, SplitAmount: &amt,
		ZapTarget: zapTarget, RequestID: rid,
	}, nil
}

// CashZapParams is what a kind 9522 is built from: the transfer's reply and the
// zap context the sender wrote ahead with the call.
type CashZapParams struct {
	Recipient Identity
	// Sender is the P tag, set only by a Proxy Agent: a ConnectionKey.
	Sender *Identity
	// Amount is the zap amount; 0 takes the reply's amount_millis. It must equal
	// the token's attested amount.
	Amount uint64
	// Chain is the token's chain; "" takes it from the token's prefix.
	Chain string
	// IA is the Identity Authority for a ConnectionKey recipient.
	IA      string
	Target  *nip01.Event
	Content string
	// Transfer is the cash_transfer reply (or its lookup's done result).
	Transfer *nipcash.CashTransferResult
	// Token is the recipient's token; "" takes the reply's new_wallet_token.
	Token string
}

// NewCashZap builds and signs a kind 9522. issued_at and expires_at are copied
// from the transfer reply exactly; a zap bill (TLV 8 = 2) whose reply lacks them
// is refused (ErrZapNotSigned). It refuses a missing reply (no 9522 exists
// without one), a token whose wallet pubkey (TLV 0) is not the reply's
// new_wallet_pubkey, an amount other than the token's attested one, and a chain
// other than the token's. It never writes a NIP-40 expiration tag.
func NewCashZap(p CashZapParams, signerPriv string) (*nip01.Event, error) {
	if p.Transfer == nil {
		return nil, ErrNoTransferResult
	}
	tokStr := p.Token
	if tokStr == "" {
		tokStr = p.Transfer.NewWalletToken
	}
	if tokStr == "" {
		return nil, ErrNoTransferResult
	}
	tok, err := nipcash.Decode(tokStr)
	if err != nil {
		return nil, err
	}
	if p.Transfer.NewWalletPubkey != "" && p.Transfer.NewWalletPubkey != tok.WalletPubkey {
		return nil, ErrTokenWallet
	}
	if !p.Recipient.valid() {
		return nil, ErrIdentity
	}
	if p.Recipient.IsConnectionKey() != (p.IA != "") {
		if p.IA == "" {
			return nil, ErrZapIARequired
		}
		return nil, ErrZapIAForPubkey
	}
	if p.Sender != nil && (!p.Sender.IsConnectionKey() || !p.Sender.valid()) {
		return nil, ErrIdentity
	}
	amount := p.Amount
	if amount == 0 {
		amount = p.Transfer.AmountMillis
	}
	if amount == 0 || tok.AttestedAmountMillis == nil || *tok.AttestedAmountMillis != amount {
		return nil, ErrAmount
	}
	c, ok := ChainForHRP(tok.HRP)
	if !ok || (p.Chain != "" && p.Chain != c.Name) {
		return nil, fmt.Errorf("nipCZ: the token's prefix %q is not chain %q", tok.HRP, p.Chain)
	}
	if tok.Scheme == nipcash.SchemeZapV1 && !p.Transfer.ZapSigned() {
		return nil, ErrZapNotSigned
	}

	var tags [][]string
	if p.Target != nil {
		zt, err := ZapTargetFor(p.Target)
		if err != nil {
			return nil, err
		}
		tags = append(tags, []string{"e", p.Target.ID})
		if zt != p.Target.ID {
			tags = append(tags, []string{"a", zt})
		}
		tags = append(tags, []string{"k", strconv.Itoa(p.Target.Kind)})
	}
	tags = append(tags, p.Recipient.tag("p"))
	if p.Sender != nil {
		tags = append(tags, p.Sender.tag("P"))
	}
	tags = append(tags,
		[]string{"amount", strconv.FormatUint(amount, 10)},
		[]string{"chain", c.Name},
		[]string{"cash", tokStr},
		[]string{"w", tok.WalletPubkey},
	)
	if p.IA != "" {
		tags = append(tags, []string{"ia", p.IA})
	}
	if p.Transfer.IssuedAt != nil {
		tags = append(tags, []string{"issued_at", strconv.FormatUint(*p.Transfer.IssuedAt, 10)})
	}
	if p.Transfer.ExpiresAt != nil {
		tags = append(tags, []string{"expires_at", strconv.FormatUint(*p.Transfer.ExpiresAt, 10)})
	}
	return nip01.NewSignedEvent(KindCashZap, p.Content, signerPriv, tags...)
}

// SendCandidate is a bill the sender holds: its token and its expiry as
// cash_status reports it (absent or 0 = never).
type SendCandidate struct {
	Token  nipcash.Token
	Expiry nipcash.Expiry
}

// PlanSend orders the bills a sender may zap a recipient with (NIP-CZ §Sending
// 1): only bills on a chain the recipient's 10522 accepts (any without one),
// a bill whose minter the recipient lists first, then the longest remaining
// life. Without expiry information every bill is treated as never expiring;
// PlanSendCandidates takes it. ErrChainNotAccepted when none qualifies.
func PlanSend(info *CashZapInfo, bills []nipcash.Token, now time.Time) ([]nipcash.Token, error) {
	cands := make([]SendCandidate, len(bills))
	for i, b := range bills {
		cands[i] = SendCandidate{Token: b}
	}
	planned, err := PlanSendCandidates(info, cands, now)
	if err != nil {
		return nil, err
	}
	out := make([]nipcash.Token, len(planned))
	for i, c := range planned {
		out[i] = c.Token
	}
	return out, nil
}

// PlanSendCandidates is PlanSend with each bill's expiry; a bill already
// expired at now is dropped. A bill's minter is read from its scheme-1
// signature; a zap bill's (scheme 2) needs its own 9522 and counts as
// unlisted here.
func PlanSendCandidates(info *CashZapInfo, cands []SendCandidate, now time.Time) ([]SendCandidate, error) {
	type ranked struct {
		c      SendCandidate
		listed bool
		i      int
	}
	var keep []ranked
	for i, c := range cands {
		row, ok := ChainForHRP(c.Token.HRP)
		if !ok || !info.Accepts(row.Name) {
			continue
		}
		if !c.Expiry.Never() && c.Expiry.At <= now.Unix() {
			continue
		}
		listed := false
		if m, ok := nipcash.VerifyProvenance(c.Token); ok {
			listed = info.ListsMinter(m, row.Name)
		}
		keep = append(keep, ranked{c: c, listed: listed, i: i})
	}
	if len(keep) == 0 {
		return nil, ErrChainNotAccepted
	}
	sort.SliceStable(keep, func(a, b int) bool {
		x, y := keep[a], keep[b]
		if x.listed != y.listed {
			return x.listed
		}
		xn, yn := x.c.Expiry.Never(), y.c.Expiry.Never()
		if xn != yn {
			return xn
		}
		if !xn && x.c.Expiry.At != y.c.Expiry.At {
			return x.c.Expiry.At > y.c.Expiry.At
		}
		return x.i < y.i
	})
	out := make([]SendCandidate, len(keep))
	for i, r := range keep {
		out[i] = r.c
	}
	return out, nil
}
