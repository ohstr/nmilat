package nipCP

import (
	"fmt"

	"github.com/ohstr/nmilat/nipcash"
)

// ApplyWithdraw applies one answer about a cash_withdraw (its reply, a lookup's
// done result or a cancel answer, as nipcash.Payout with any re-minted token
// already decrypted) to its pending entry (NIP-CP §Writing, Withdrawals).
// source is the entry of the bill the call named (w = entry's target); hubXOnly
// is the Hub's node identity.
//
// Every answer's receipt is verified first against the entry: its id and
// signature by hubXOnly, d = target, q = the stored quote's id, request_hash =
// the sha256 of request_id, and address, payout_millis and sent_by equal to the
// quote's (the payout's own must equal them too). An answer without a valid
// receipt counts as no answer: the error wraps nipcash.ErrReceiptInvalid and
// nothing is written.
//
// writes are written in one batch and read back before done is written:
//   - on the first verified receipt (the entry has none yet), the pending entry
//     at its next rev carrying receipt, and source at its next rev spent,
//     keeping its token and any secret for the lookups;
//   - under cancelled, an entry for the re-minted bill: live with its token and
//     the whole amount, bound to the source's identity, or for a cash-mode slice
//     cash carrying the remint secret (a tombstone in its place gives an entry
//     without cash in its mapped final state). The payout carries no
//     expires_at: refresh it with cash_status (WithExpiry).
//
// done is the entry at its next rev in state done, only once the payout is
// final or cancelled; queued, broadcast and confirmed leave it pending. Once
// the payout is final, WithdrawDoneRewrite gives the done entry's rewrite.
func ApplyWithdraw(entry Entry, source Entry, p *nipcash.Payout, hubXOnly string) (writes []Entry, done *Entry, err error) {
	if !entry.IsCall() || entry.State != StatePending || entry.Quote == "" {
		return nil, nil, ErrNotPending
	}
	if p == nil {
		return nil, nil, bad("no payout")
	}
	if source.W != entry.Target {
		return nil, nil, bad("the source is not the bill the withdrawal named")
	}
	if err := verifyEntryReceipt(entry, p, hubXOnly); err != nil {
		return nil, nil, err
	}
	at := now()
	cur := entry
	if entry.Receipt == "" {
		cur = rewrite(entry, at)
		cur.Receipt = p.Receipt
		writes = append(writes, cur)
		if source.State != StateSpent {
			writes = append(writes, WithState(source, StateSpent, at))
		}
	}
	switch p.State {
	case nipcash.PayoutCancelled:
		b, err := remintEntry(entry, source, p, at)
		if err != nil {
			return nil, nil, err
		}
		writes = append(writes, b)
	case nipcash.PayoutFinal:
	default:
		return writes, nil, nil
	}
	d := WithState(cur, StateDone, at)
	return writes, &d, nil
}

// verifyEntryReceipt checks p and its receipt against the entry's stored quote.
func verifyEntryReceipt(entry Entry, p *nipcash.Payout, hubXOnly string) error {
	q, err := nipcash.ParseWithdrawQuote(entry.Quote)
	if err != nil {
		return fmt.Errorf("%w: the entry's quote", nipcash.ErrReceiptInvalid)
	}
	if p.Address != q.Address || p.PayoutMillis != q.PayoutMillis || p.SentBy != q.SentBy || p.AmountMillis != q.AmountMillis {
		return fmt.Errorf("%w: the payout differs from the quote", nipcash.ErrReceiptInvalid)
	}
	return nipcash.VerifyWithdrawReceipt(p.Receipt, nipcash.ReceiptExpectation{
		HubXOnly: hubXOnly, Target: entry.Target, QuoteID: q.ID, RequestID: entry.RequestID,
		Address: q.Address, PayoutMillis: q.PayoutMillis, SentBy: q.SentBy,
	})
}

// remintEntry is the entry for a cancelled payout's re-minted bill.
func remintEntry(entry, source Entry, p *nipcash.Payout, at int64) (Entry, error) {
	e := Entry{W: p.NewWalletPubkey, Rev: 1, Amount: p.AmountMillis, Chain: entry.Chain, Identity: source.Identity, CheckedAt: at}
	for _, s := range entry.Secrets {
		if s.Role == SecretRoleRemint {
			e.Identity = EntryIdentity{Type: IdentityCash}
			e.Secrets = []nipcash.PendingSecret{{Secret: s.Secret}}
		}
	}
	if t := p.NewWalletToken.Tombstone; t != nil {
		e.Secrets = nil
		e.State, _ = MapStatus(StatusInput{Tombstone: t})
	} else {
		e.Cash, e.State = p.NewWalletToken.Token, StateLive
	}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// WithdrawDoneRewrite is a cash_withdraw's done entry at its next rev without
// address, quote and receipt, which a wallet SHOULD write once the payout is
// final (NIP-CP §Writing, Withdrawals). It keeps request_id, target, notify and
// any secret.
func WithdrawDoneRewrite(done Entry) (Entry, error) {
	if !done.IsCall() || done.State != StateDone || done.Quote == "" {
		return Entry{}, bad("not a cash_withdraw done entry with its quote")
	}
	n := rewrite(done, now())
	n.Address, n.Quote, n.Receipt = "", "", ""
	return n, nil
}
