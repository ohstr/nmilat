package client

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nipcash"
)

// On-chain withdrawals (NIP-CASH §Redeeming On-chain). A holder SHOULD
// withdraw only a bill whose amount others do not know, splitting it first:
// the payout's value on chain is the slice's amount less the fee.

// ErrWithdrawNotOffered is a Hub that does not offer on-chain withdrawals: its
// cash_status carries no withdraw object, or it refused a quote
// NOT_IMPLEMENTED. Nothing was sent to withdraw.
var ErrWithdrawNotOffered = errors.New("nipcash/client: this Hub does not offer on-chain withdrawals")

// WithWithdrawHRP sets the witness HRP of the Hub's network: the local address
// check is then nipcash.ClassifyAddress under exactly it. Unset, an address of
// any network of the bill's coin passes locally and the Hub's network decides.
func WithWithdrawHRP(hrp string) SessionOption {
	return func(c *sessionConfig) { c.withdrawHRP = strings.ToLower(hrp) }
}

// WithdrawTerms reads the Hub's current withdrawal terms from cash_status (for
// display only; a quote fixes a payout). nil terms are ErrWithdrawNotOffered.
// cred is the slice's credential (as for CashStatus); without one the read
// carries the bill proof alone, which a Hub serves for a cash-mode bill.
func (c *Client) WithdrawTerms(ctx context.Context, cred ...nipcash.Credential) (*nipcash.WithdrawTerms, error) {
	credential := billProofOnly()
	if len(cred) > 0 && cred[0] != nil {
		credential = cred[0]
	}
	status, err := c.CashStatus(ctx, credential, nipcash.ScopeMine)
	if err != nil {
		return nil, err
	}
	return termsOf(status)
}

// billProofOnly stands for no slice credential: a cash_status item with the bill
// proof alone. A bearer credential signs no item proof, and cash_status never
// carries a secret, so the placeholder secret is never sent.
func billProofOnly() nipcash.Credential { return nipcash.BySecret(strings.Repeat("0", 64)) }

func termsOf(status *nipcash.CashStatusResult) (*nipcash.WithdrawTerms, error) {
	if status == nil {
		return nil, errors.New("nipcash/client: no cash_status answer")
	}
	if status.Tombstone != nil {
		return nil, &nipcash.BillGone{Method: nipcash.MethodCashStatus, Tombstone: *status.Tombstone}
	}
	if status.Withdraw == nil {
		return nil, ErrWithdrawNotOffered
	}
	return status.Withdraw, nil
}

// chain is the coin of this client's bill, "" when unknown.
func (c *Client) chain() string {
	if c.token == nil {
		return ""
	}
	ch, _ := nipcash.ChainForHRP(c.token.HRP)
	return ch
}

// QuoteWithdraw asks the Hub what withdrawing the caller's slice to p.Address
// would pay, and checks the answer. The terms and the caller's own row come from
// p.Status when set (no second cash_status read), else from one cash_status
// read; no terms is ErrWithdrawNotOffered, nothing sent. The address is
// normalized (nipcash.NormalizeAddress) and checked locally: under the session's
// WithWithdrawHRP when set, else among the networks of the bill's coin, and its
// script type against the terms (nipcash.ErrScriptTypeNotPaid); min_millis and
// max_millis are for display, the Hub decides. The answer passes
// nipcash.VerifyQuoteAnswer against the Hub's identity, the bill, the slice, the
// address as sent, any send_before, and the row's amount and redeem fee (else
// nipcash.ErrQuoteMismatch). A refusal is a *FinalError carrying its code and
// detail (a quote has no request_id; the caller may quote again), NOT_IMPLEMENTED
// is ErrWithdrawNotOffered.
func (c *Client) QuoteWithdraw(ctx context.Context, p nipcash.CashWithdrawQuoteParams) (*nipcash.WithdrawQuote, error) {
	bill, err := c.bill()
	if err != nil {
		return nil, err
	}
	s, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	return s.quoteWithdraw(ctx, bill, c.chain(), p)
}

func (s *BatchSession) quoteWithdraw(ctx context.Context, bill Bill, chain string, p nipcash.CashWithdrawQuoteParams) (*nipcash.WithdrawQuote, error) {
	if p.Credential == nil {
		return nil, errors.New("nipcash/client: a quote needs the slice's credential")
	}
	status := p.Status
	if status == nil {
		outs, err := s.StatusMany(ctx, []BatchStatus{{ID: "1", Bill: bill, Credential: p.Credential, Scope: nipcash.ScopeMine}})
		if len(outs) == 0 {
			if err == nil {
				err = &NotServedError{Method: nipcash.MethodCashStatus}
			}
			return nil, err
		}
		if err := oneItemOutcome(outs[0].State, outs[0].Error, err, nipcash.MethodCashStatus); err != nil {
			return nil, err
		}
		status = outs[0].Result
	}
	terms, err := termsOf(status)
	if err != nil {
		return nil, err
	}
	addr, err := nipcash.NormalizeAddress(p.Address)
	if err != nil {
		return nil, err
	}
	st, err := s.classifyWithdrawAddress(addr, chain)
	if err != nil {
		return nil, err
	}
	if !nipcash.PaysScriptType(terms.ScriptTypeList(), st) {
		return nil, nipcash.ErrScriptTypeNotPaid
	}
	row, err := nipcash.OwnRow(status.Recipients, p.Credential, nipcash.ScopeMine)
	if err != nil {
		return nil, err
	}
	identity, ia, err := nipcash.SliceIdentity(p.Credential)
	if err != nil {
		return nil, err
	}
	p.Address = addr
	outs, sendErr := s.WithdrawQuoteMany(ctx, []BatchWithdrawQuote{{ID: "1", Bill: bill, Params: p}})
	if len(outs) == 0 {
		if sendErr == nil {
			sendErr = &NotServedError{Method: nipcash.MethodCashWithdrawQuote}
		}
		return nil, sendErr
	}
	o := outs[0]
	if o.Result == nil {
		if o.Gone != nil {
			return nil, &nipcash.BillGone{Method: nipcash.MethodCashWithdrawQuote, Tombstone: *o.Gone}
		}
		if o.State == OutcomeError && o.Error != nil && !o.Undecodable {
			if o.Error.Code == nipcash.ErrCodeNotImplemented {
				return nil, ErrWithdrawNotOffered
			}
			return nil, &FinalError{Method: nipcash.MethodCashWithdrawQuote, Code: o.Error.Code, Message: o.Error.Message,
				Detail: string(nipcash.ParseDetail(o.Error.Detail))}
		}
		if err := oneItemOutcome(o.State, o.Error, sendErr, nipcash.MethodCashWithdrawQuote); err != nil {
			return nil, err
		}
		return nil, &NotServedError{Method: nipcash.MethodCashWithdrawQuote}
	}
	redeemFee := row.RedeemFeeMillis
	return nipcash.VerifyQuoteAnswer(*o.Result, nipcash.QuoteExpectation{
		HubXOnly: s.HubIdentity(), Wallet: bill.target, IdentityValue: identity, IAPubkey: ia, Address: addr,
		SendBefore: p.SendBefore, AmountMillis: row.AmountMillis, RedeemFeeMillis: &redeemFee,
	})
}

// classifyWithdrawAddress is the local address check: under the configured HRP,
// else among chain's HRPs, else (an unknown chain) the address's own.
func (s *BatchSession) classifyWithdrawAddress(addr, chain string) (nipcash.ScriptType, error) {
	if hrp := s.cfg.withdrawHRP; hrp != "" {
		return nipcash.ClassifyAddress(addr, hrp)
	}
	if hrps, ok := nipcash.WithdrawHRPs(chain); ok {
		st, _, err := nipcash.ClassifyAddressAmong(addr, hrps)
		return st, err
	}
	v, prog, err := nipcash.DecodeWitnessAddress(addr, "")
	if err != nil {
		return nipcash.ScriptType{}, err
	}
	return nipcash.ScriptType{Version: v, ProgramLen: uint8(len(prog))}, nil
}

// Withdraw accepts a quote and ends the slice (NIP-CASH §Redeeming On-chain).
// p.Quote must be the one QuoteWithdraw returned, and the caller MUST have had
// its user confirm its Address, PayoutMillis, FeeMillis() and AmountMillis
// first. request_id and notify are generated when empty, and for a BySecret
// credential the re-mint target when p.Remint is nil. The call is written ahead
// to j, as device's, with its deadline, quote, address, notify, re-mint secret
// and source secret, before it is sent; a Journal implementing AcceptedRecorder
// is told the accepting relays, which WatchPayout uses.
//
// The answer is a queued payout whose receipt verified against the call. A
// reply without a valid receipt is an *IndeterminateError wrapping
// nipcash.ErrReceiptInvalid: keep the call pending and do not mark the source
// spent. BAD_REQUEST is a *FinalError; any other code (NOT_IMPLEMENTED
// included) or no answer an *IndeterminateError: look the call up with
// LookupWithdraw, never resend it.
func (c *Client) Withdraw(ctx context.Context, p nipcash.CashWithdrawParams, j Journal, device string) (*nipcash.Payout, error) {
	bill, err := c.bill()
	if err != nil {
		return nil, err
	}
	s, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	return s.withdraw(ctx, bill, p, j, device)
}

func (s *BatchSession) withdraw(ctx context.Context, bill Bill, p nipcash.CashWithdrawParams, j Journal, device string) (*nipcash.Payout, error) {
	if p.Credential == nil {
		return nil, errors.New("nipcash/client: a withdrawal needs the slice's credential")
	}
	outs, sendErr := s.WithdrawMany(ctx, []BatchWithdraw{{ID: "1", Bill: bill, Params: p}}, j, device)
	if len(outs) == 0 {
		if sendErr == nil {
			sendErr = &NotServedError{Method: nipcash.MethodCashWithdraw}
		}
		return nil, sendErr
	}
	o := outs[0]
	if len(o.Accepted) > 0 {
		if pc, ok := o.Pending(); ok {
			s.keepAccepted(pc.Notify, o.Accepted)
		}
	}
	if err := o.CallError(sendErr); err != nil {
		return nil, err
	}
	return o.Result, nil
}

// PayoutFinished reports a payout that ended: final or cancelled.
func PayoutFinished(p *nipcash.Payout) bool {
	return p != nil && (p.State == nipcash.PayoutFinal || p.State == nipcash.PayoutCancelled)
}

// CancelRefusedError is a cancel request the Hub refused (RESTRICTED before 7
// days after sent_by, NOT_FOUND once its record is gone, ...), or one this
// client refused before sending (Local). Repeating it is harmless.
type CancelRefusedError struct {
	Code, Message string
	Local         bool
}

func (e *CancelRefusedError) Error() string {
	if e.Local {
		return "nipcash/client: cancel request not sent: " + e.Message
	}
	return fmt.Sprintf("nipcash/client: cancel request refused: %s: %s", e.Code, e.Message)
}
