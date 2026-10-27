package client

import (
	"context"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nipcash"
)

// lookupDeadline is the deadline a withdrawal lookup carries: the call's, or
// now for a call recovered from withdraw_request_id, which has none (a Hub
// answers a withdrawal's lookup done whatever deadline it carries).
func lookupDeadline(pc nipcash.PendingCall) int64 {
	if pc.Deadline > 0 {
		return pc.Deadline
	}
	return time.Now().Unix()
}

// LookupWithdraw looks a withdrawal up on this client's bill (NIP-CASH
// §Withdrawals): the item proof by cred, the claim-proof signer; a
// cash-authorized call first without its secret, and again with it only after
// UNAUTHORIZED. A done is the payout's current state, returned when its receipt
// verifies against the call (else the outcome is Malformed and no payout is
// returned): for a call recovered from withdraw_request_id (no quote) the
// receipt is checked against the payout's own address, payout and sent_by, and
// nipcash.ReceiptQuoteID gives the quote id to store. Under cancelled the
// re-minted bill's token is decrypted with cred (a cash-mode bill's arrives in
// the clear) and its provenance verified against the bill's Hub. A tx that fails
// nipcash.VerifyPayoutTx is reported in Payout.TxErr; the payout and its state
// are kept. The client never infers confirmed or final itself: poll until
// PayoutFinished.
func (c *Client) LookupWithdraw(ctx context.Context, pc nipcash.PendingCall, cred nipcash.Credential) (LookupOutcome, *nipcash.Payout, error) {
	bill, err := c.bill()
	if err != nil {
		return LookupOutcome{}, nil, err
	}
	s, err := c.billSession(ctx)
	if err != nil {
		return LookupOutcome{}, nil, err
	}
	return s.lookupWithdraw(ctx, bill, pc, cred)
}

func (s *BatchSession) lookupWithdraw(ctx context.Context, bill Bill, pc nipcash.PendingCall, cred nipcash.Credential) (LookupOutcome, *nipcash.Payout, error) {
	one := func(secret string) (LookupOutcome, error) {
		outs, err := s.LookupWithdrawMany(ctx, []BatchWithdrawLookup{{ID: "1", Bill: bill, Call: pc, Credential: cred, CashSecret: secret}})
		if len(outs) == 0 {
			return LookupOutcome{}, err
		}
		return outs[0], err
	}
	lo, err := one("")
	if err == nil && lo.Code == nipcash.ErrCodeUnauthorized && pc.SourceSecret != "" {
		lo, err = one(pc.SourceSecret)
	}
	if err != nil || lo.Status != nipcash.LookupDone || lo.Malformed || lo.Code != "" || lo.NotServed {
		return lo, nil, err
	}
	p, err := s.checkPayout(withHub(pc, s.HubIdentity()), cred, lo.Result)
	if err != nil {
		return LookupOutcome{Malformed: true}, nil, nil
	}
	return lo, p, nil
}

// checkPayout reads a payout answered for the call pc: parsed (its re-minted
// token decrypted with cred), its receipt verified against the call, a
// re-minted bill's provenance verified against the Hub, and any tx checked
// into TxErr.
func (s *BatchSession) checkPayout(pc nipcash.PendingCall, cred nipcash.Credential, data []byte) (*nipcash.Payout, error) {
	p, err := nipcash.CashWithdrawParams{Credential: cred}.ParseLookupResult(data)
	if err != nil {
		return nil, err
	}
	if err := verifyCallReceipt(pc, p); err != nil {
		return nil, err
	}
	if tok := p.NewWalletToken.Token; tok != "" {
		t, err := nipcash.Decode(tok)
		if err != nil {
			return nil, fmt.Errorf("nipcash/client: the re-minted token does not decode: %w", err)
		}
		minter, ok := nipcash.VerifyProvenance(t)
		if !ok || !nipcash.HubIdentityEqual(pc.HubIdentity, minter) || t.WalletPubkey != p.NewWalletPubkey {
			return nil, fmt.Errorf("nipcash/client: the re-minted token is not this Hub's bill")
		}
	}
	if p.Tx != "" && p.Txid != "" && p.Vout != nil {
		p.TxErr = nipcash.VerifyPayoutTx(p.Tx, p.Txid, *p.Vout, p.Address, "", p.PayoutMillis)
	}
	return p, nil
}
