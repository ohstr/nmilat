package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// The batch methods below are the point of the private transport: one relay event for
// many bills, instead of one event per bill.
//
// What that buys is not only speed. On the standard transport every request is p-tagged
// with a bill's own pubkey, so a holder's bills are a public, linkable set — and a
// holder consolidating fifty of them publishes fifty events that resolve to one, which
// ties them together for anyone watching, without decrypting anything. Batched, the
// count stops being public and the timing correlation disappears.
//
// Every method returns one outcome per requested item, in the order requested, whatever
// happened. None of them retries: cash_redeem has no idempotency key and a double
// redemption is unrecoverable, so the caller decides, and ItemOutcome.SafeToResend says
// which items they safely may.
//
// Each can return outcomes AND a non-nil error together, which is worth expecting rather
// than treating as a contradiction: it means a hub's reply arrived in fewer chunks than it
// sent (ErrIncompleteReply), so the outcomes present are genuine while the rest are
// unknown. Discarding them on seeing the error would throw away real answers — including,
// for RedeemMany, confirmation of redemptions that succeeded.

// BatchStatus asks one bill for its state.
type BatchStatus struct {
	// ID is the caller's own handle for this item, echoed back on its outcome. Optional
	// — an index is used when empty — but supplying something meaningful (a ledger row
	// id) is what lets a caller map outcomes back to their own records without
	// depending on ordering.
	ID string
	// Bill is which bill this item acts on, plus the secret proving the sender holds
	// it. Build it with BillFor(token) — the two halves come from one token and are
	// deliberately not separately settable (see Bill).
	Bill       Bill
	Credential nipcash.Credential
	// Scope selects how much of the roster to ask for (nipcash.ScopeAll /
	// ScopeMine). Empty asks for this transport's default, which is ScopeMine:
	// the caller's own row, and nothing about their co-recipients
	// (NIP-CASH §Scoping the Roster).
	//
	// Worth setting deliberately when batching, because it is what decides reply
	// size. A 100-recipient bill answers in roughly 300 bytes scoped to one row
	// and roughly 28,500 unscoped — so a batch of unscoped reads is the common
	// way to make a reply outgrow its envelope and need chunking.
	Scope string
}

// StatusOutcome is one bill's status answer.
type StatusOutcome struct {
	ItemOutcome
	// Result is set only when the item Succeeded. Nil for an error or an omission,
	// which is why State must be consulted rather than Result's nil-ness: a nil Result
	// means "no answer OR a refusal", and those are different facts.
	Result *nipcash.CashStatusResult
}

// StatusMany reads several bills in one request.
//
// The cheapest useful batch, and a good first call for a client adopting the transport:
// it moves no money, so a mistake costs a round trip rather than funds.
func (s *BatchSession) StatusMany(ctx context.Context, items []BatchStatus) ([]StatusOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	for i, it := range items {
		it := it
		builders = append(builders, itemBuilder{
			ID: itemID(it.ID, i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if !it.Bill.ok() {
					return transport.Item{}, fmt.Errorf("nipcash/client: item %q has no bill; build one with BillFor(token)", id)
				}
				return nipcash.StatusItem(id, it.Bill.target, it.Bill.connSecret, nipcash.CashStatusParams{Scope: it.Scope}, it.Credential, b)
			},
		})
	}

	// sendBatch can return outcomes AND an error, when a reply arrived in fewer chunks
	// than the hub sent. Those outcomes are real answers and must not be discarded —
	// the error says part of the picture is missing, not that none of it is.
	outcomes, sendErr := s.sendBatch(ctx, builders)
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]StatusOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		so := StatusOutcome{ItemOutcome: o}
		if o.Succeeded() {
			var result nipcash.CashStatusResult
			if err := json.Unmarshal(o.Result, &result); err != nil {
				// A served item whose body will not decode is a hub-side problem, not
				// an omission. Downgrading it to an error keeps the distinction honest:
				// the hub DID answer, and the answer was unusable.
				so.State = OutcomeError
				so.Error = decodeError(o.ID, err)
			} else {
				so.Result = &result
			}
		}
		out = append(out, so)
	}
	return out, sendErr
}

// BatchRedeem redeems one bill to an invoice.
type BatchRedeem struct {
	ID string
	// Bill is which bill this item acts on, plus the secret proving the sender holds
	// it. Build it with BillFor(token) — the two halves come from one token and are
	// deliberately not separately settable (see Bill).
	Bill   Bill
	Params nipcash.CashRedeemParams
}

// RedeemOutcome is one bill's redemption answer.
type RedeemOutcome struct {
	ItemOutcome
	Result *nipcash.CashRedeemResult
}

// RedeemMany redeems several bills in one request.
//
// Each bill needs its own invoice — a redemption pays out to one, and a slice pays
// exactly once — so the caller generates as many invoices as bills. That is deliberate
// rather than a limitation: an invoice per bill is what keeps each payout independently
// verifiable.
//
// Note the outcome states carefully here, because this method moves money. An
// OutcomeError is the hub declining, and is safe to resend. An OutcomeNotServed is NOT:
// the hub said nothing, which is indistinguishable from an item that executed and whose
// reply was lost. A caller who needs to know MUST ask — StatusMany on the same bill
// will say whether it is still live.
func (s *BatchSession) RedeemMany(ctx context.Context, items []BatchRedeem) ([]RedeemOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	for i, it := range items {
		it := it
		builders = append(builders, itemBuilder{
			ID: itemID(it.ID, i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if !it.Bill.ok() {
					return transport.Item{}, fmt.Errorf("nipcash/client: item %q has no bill; build one with BillFor(token)", id)
				}
				return it.Params.Item(id, it.Bill.target, it.Bill.connSecret, b)
			},
		})
	}

	// sendBatch can return outcomes AND an error, when a reply arrived in fewer chunks
	// than the hub sent. Those outcomes are real answers and must not be discarded —
	// the error says part of the picture is missing, not that none of it is.
	outcomes, sendErr := s.sendBatch(ctx, builders)
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]RedeemOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		ro := RedeemOutcome{ItemOutcome: o}
		if o.Succeeded() {
			var result nipcash.CashRedeemResult
			if err := json.Unmarshal(o.Result, &result); err != nil {
				ro.State = OutcomeError
				ro.Error = decodeError(o.ID, err)
			} else {
				ro.Result = &result
			}
		}
		out = append(out, ro)
	}
	return out, sendErr
}

// BatchTransfer transfers or splits one bill.
type BatchTransfer struct {
	ID string
	// Bill is which bill this item acts on, plus the secret proving the sender holds
	// it. Build it with BillFor(token) — the two halves come from one token and are
	// deliberately not separately settable (see Bill).
	Bill   Bill
	Params nipcash.CashTransferParams
}

// TransferOutcome is one bill's transfer answer.
type TransferOutcome struct {
	ItemOutcome
	Result *nipcash.CashTransferResult
}

// TransferMany transfers or splits several bills in one request.
func (s *BatchSession) TransferMany(ctx context.Context, items []BatchTransfer) ([]TransferOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	// Kept so each result can be parsed through the SAME params that authorized it —
	// the delivered token is encrypted to that credential.
	paramsByID := make(map[string]nipcash.CashTransferParams, len(items))
	for i, it := range items {
		it := it
		paramsByID[itemID(it.ID, i)] = it.Params
		builders = append(builders, itemBuilder{
			ID: itemID(it.ID, i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if !it.Bill.ok() {
					return transport.Item{}, fmt.Errorf("nipcash/client: item %q has no bill; build one with BillFor(token)", id)
				}
				return it.Params.Item(id, it.Bill.target, it.Bill.connSecret, b)
			},
		})
	}

	// sendBatch can return outcomes AND an error, when a reply arrived in fewer chunks
	// than the hub sent. Those outcomes are real answers and must not be discarded —
	// the error says part of the picture is missing, not that none of it is.
	outcomes, sendErr := s.sendBatch(ctx, builders)
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]TransferOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		to := TransferOutcome{ItemOutcome: o}
		if o.Succeeded() {
			// ParseResult, never a plain unmarshal: a spun-off wallet's token
			// arrives ENCRYPTED to its new owner, and only the credential that
			// authorized this item can open it. Unmarshalling would return
			// ciphertext in a field named for a token — usable-looking and useless.
			result, err := paramsByID[o.ID].ParseResult(o.Result)
			if err != nil {
				to.State = OutcomeError
				to.Error = decodeError(o.ID, err)
			} else {
				to.Result = result
			}
		}
		out = append(out, to)
	}
	return out, sendErr
}

// BatchConsolidate merges several slices into one new bill.
type BatchConsolidate struct {
	ID string
	// Target is the wallet this call is made AGAINST — the entry point. It need not be
	// one of Params.Sources: NIP-CASH lets a caller consolidate slices it does not
	// otherwise hold, as long as it can prove control of each.
	// Bill is which bill this item acts on, plus the secret proving the sender holds
	// it. Build it with BillFor(token) — the two halves come from one token and are
	// deliberately not separately settable (see Bill).
	Bill Bill
	// Credential authorizes the call itself, separately from each source's own
	// credential inside Params.
	Credential nipcash.Credential
	Params     nipcash.CashConsolidateParams
}

// ConsolidateOutcome is one consolidation's answer.
type ConsolidateOutcome struct {
	ItemOutcome
	Result *nipcash.CashConsolidateResult
}

// ConsolidateMany performs several consolidations in one request.
//
// Worth knowing how this interacts with splitting. A consolidate item grows with its
// source count, so a batch of consolidations can exceed one envelope far sooner than a
// batch of redemptions — and the SDK splits across envelopes rather than refusing. A
// single consolidation whose sources alone exceed the hub's announced max_bytes cannot
// be split at all and returns ErrItemTooLarge: the caller must consolidate in stages.
func (s *BatchSession) ConsolidateMany(ctx context.Context, items []BatchConsolidate) ([]ConsolidateOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	// Same reason as TransferMany: the merged wallet's token is delivered encrypted.
	paramsByID := make(map[string]nipcash.CashConsolidateParams, len(items))
	for i, it := range items {
		it := it
		paramsByID[itemID(it.ID, i)] = it.Params
		builders = append(builders, itemBuilder{
			ID: itemID(it.ID, i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if !it.Bill.ok() {
					return transport.Item{}, fmt.Errorf("nipcash/client: item %q has no bill; build one with BillFor(token)", id)
				}
				return it.Params.Item(id, it.Bill.target, it.Bill.connSecret, it.Credential, b)
			},
		})
	}

	// sendBatch can return outcomes AND an error, when a reply arrived in fewer chunks
	// than the hub sent. Those outcomes are real answers and must not be discarded —
	// the error says part of the picture is missing, not that none of it is.
	outcomes, sendErr := s.sendBatch(ctx, builders)
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]ConsolidateOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		co := ConsolidateOutcome{ItemOutcome: o}
		if o.Succeeded() {
			// ParseResult for the reason TransferMany uses it: the merged wallet's
			// token is delivered encrypted to its new owner.
			result, err := paramsByID[o.ID].ParseResult(o.Result)
			if err != nil {
				co.State = OutcomeError
				co.Error = decodeError(o.ID, err)
			} else {
				co.Result = result
			}
		}
		out = append(out, co)
	}
	return out, sendErr
}

// itemID falls back to the index when a caller supplied no id of their own.
//
// Ids must be unique across the whole batch, not merely within an envelope: packing
// decides envelope boundaries, so a caller cannot know which items will share one, and
// a collision would be caught late and confusingly.
func itemID(given string, index int) string {
	if given != "" {
		return given
	}
	return "#" + strconv.Itoa(index)
}

func decodeError(id string, err error) *transport.ResultError {
	return &transport.ResultError{
		Code:    "INTERNAL",
		Message: fmt.Sprintf("hub answered item %q with a body this client could not decode: %v", id, err),
	}
}
