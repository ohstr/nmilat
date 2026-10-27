package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipcash"
)

// ErrInvoiceAmount is a redeem whose invoice (or amount param) asks for another
// amount than the one the bill pays out (nipcash.RedeemInvoiceMillis), or a row
// with nothing to pay out. Nothing was sent: the Hub would refuse it with
// BAD_REQUEST, or RESTRICTED for nothing to pay out (NIP-CASH §Redeeming a Slice,
// step 3).
var ErrInvoiceAmount = errors.New("nipcash/client: the invoice's amount is not what this bill pays out")

// RedeemOptions tunes CashRedeemWith.
type RedeemOptions struct {
	// AutoAmount reads the caller's own row first (cash_status, scope mine, with
	// the redeem's credential) and takes the invoice amount from
	// nipcash.RedeemInvoiceMillis: an amountless invoice is sent with that
	// amount, and an invoice or amount param asking for another is refused with
	// ErrInvoiceAmount before anything is sent.
	AutoAmount bool
	// Payee is the identity of the node the invoice pays (x-only, or 66-hex
	// compressed), compared with the bill's minter: the same node is paid the
	// row's full amount, fee-free; any other, its net redeemable amount. "" reads
	// as another node. Used only with AutoAmount.
	Payee string
}

// CashRedeem collects one recipient's exact slice by presenting a fresh Lightning
// invoice.
//
// Travels over the private transport, as every bill method does — it is the only
// transport that serves them (NIP-CASH §The Private Transport). The session is opened
// on first use and reused; a caller never sees it.
//
// A hub that returns no answer for this item is an ERROR here, not a nil result. An
// omission is information-free by design, so "the redeem may or may not have happened"
// is the honest report — and for a method that moves money it is the difference
// between asking and double-paying.
//
// Such an answer — an omission, an unanswered or conflicting item, a timeout
// after publish, a result that does not decode, or INTERNAL (answered while the
// payment may still settle) — is a *NeedsStatusError (errors.Is ErrNeedsStatus;
// it unwraps to the underlying error too). The redeem is never resent: the
// caller reads its own row with RedeemFollowUp. Any other code is definitive
// (PAYMENT_FAILED: the slice is still claimable, retry with a fresh invoice and
// proof; RATE_LIMITED: try later, the slice is not spent).
func (c *Client) CashRedeem(ctx context.Context, params nipcash.CashRedeemParams) (*nipcash.CashRedeemResult, error) {
	return c.CashRedeemWith(ctx, params, RedeemOptions{})
}

// CashRedeemWith is CashRedeem with options. With o.AutoAmount the bill's own
// row is read first and the invoice amount checked or set against it; a read
// that fails, a tombstone (*nipcash.BillGone) or a mismatch (ErrInvoiceAmount)
// returns before the redeem is sent.
func (c *Client) CashRedeemWith(ctx context.Context, params nipcash.CashRedeemParams, o RedeemOptions) (*nipcash.CashRedeemResult, error) {
	bill, err := c.bill()
	if err != nil {
		return nil, err
	}
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	if o.AutoAmount {
		params, err = c.autoRedeemAmount(ctx, session, params, o.Payee)
		if err != nil {
			return nil, err
		}
	}
	outcomes, sendErr := session.RedeemMany(ctx, []BatchRedeem{{
		ID: "1", Bill: bill, Params: params,
	}})
	if len(outcomes) == 0 {
		return nil, oneItemOutcome(OutcomeNotServed, nil, sendErr, nipcash.MethodCashRedeem)
	}
	out := outcomes[0]
	err = oneItemOutcome(out.State, out.Error, sendErr, nipcash.MethodCashRedeem)
	if out.NeedsStatus() {
		return nil, needsStatus(out, err)
	}
	if err != nil {
		return nil, err
	}
	return out.Result, nil
}

// autoRedeemAmount reads the caller's own row and applies redeemAmount with
// what RedeemInvoiceMillis says the invoice must carry.
func (c *Client) autoRedeemAmount(ctx context.Context, session *BatchSession, params nipcash.CashRedeemParams, payee string) (nipcash.CashRedeemParams, error) {
	invoice, err := nip57.DecodeBolt11(params.Invoice)
	if err != nil {
		return params, fmt.Errorf("nipcash: decode invoice: %w", err)
	}
	status, err := c.CashStatus(ctx, params.Credential, nipcash.ScopeMine)
	if err != nil {
		return params, err
	}
	if status.Tombstone != nil {
		return params, &nipcash.BillGone{Method: nipcash.MethodCashRedeem, Tombstone: *status.Tombstone}
	}
	row, err := nipcash.OwnRow(status.Recipients, params.Credential, nipcash.ScopeMine)
	if err != nil {
		return params, err
	}
	millis, _ := nipcash.RedeemInvoiceMillis(row, payee, session.HubIdentity())
	return redeemAmount(params, invoice.AmountMloki, millis)
}

// redeemAmount checks an invoice of invoiceMillis (0: amountless) against the
// amount the bill pays out: an invoice carrying an amount must carry that one;
// an amountless one is sent with it, and an amount param, when given, must equal
// it. Nothing to pay out is refused too.
func redeemAmount(params nipcash.CashRedeemParams, invoiceMillis int64, millis uint64) (nipcash.CashRedeemParams, error) {
	if millis == 0 {
		return params, fmt.Errorf("%w: the bill has nothing to pay out", ErrInvoiceAmount)
	}
	if invoiceMillis != 0 {
		if invoiceMillis < 0 || uint64(invoiceMillis) != millis {
			return params, fmt.Errorf("%w: the invoice asks for %d millis, the bill pays out %d", ErrInvoiceAmount, invoiceMillis, millis)
		}
		return params, nil
	}
	if params.Amount != nil && *params.Amount != millis {
		return params, fmt.Errorf("%w: the amount param is %d millis, the bill pays out %d", ErrInvoiceAmount, *params.Amount, millis)
	}
	m := millis
	params.Amount = &m
	return params, nil
}
