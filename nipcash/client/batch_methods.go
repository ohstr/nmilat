package client

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

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
				if err := it.Bill.check(id, s.HubIdentity()); err != nil {
					return transport.Item{}, err
				}
				return nipcash.StatusItem(id, it.Bill.target, it.Bill.connSecret, nipcash.CashStatusParams{Scope: it.Scope}, it.Credential, b)
			},
		})
	}

	// sendBatch can return outcomes AND an error, when a reply arrived in fewer chunks
	// than the hub sent. Those outcomes are real answers and must not be discarded —
	// the error says part of the picture is missing, not that none of it is.
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]StatusOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		so := StatusOutcome{ItemOutcome: o}
		if o.Succeeded() {
			result, err := nipcash.ParseCashStatusResult(o.Result)
			if err != nil {
				// A served item whose body will not decode is a hub-side problem, not
				// an omission: the hub DID answer, and the answer was unusable.
				so.State = OutcomeError
				so.Error = decodeError(o.ID, err)
				so.Undecodable = true
			} else {
				so.Result = result
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
				if err := it.Bill.check(id, s.HubIdentity()); err != nil {
					return transport.Item{}, err
				}
				return it.Params.Item(id, it.Bill.target, it.Bill.connSecret, b)
			},
		})
	}

	// sendBatch can return outcomes AND an error, when a reply arrived in fewer chunks
	// than the hub sent. Those outcomes are real answers and must not be discarded —
	// the error says part of the picture is missing, not that none of it is.
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]RedeemOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		ro := RedeemOutcome{ItemOutcome: o}
		if o.Succeeded() {
			result, err := nipcash.ParseCashRedeemResult(o.Result)
			if err != nil {
				ro.ItemOutcome = parseFailure(ro.ItemOutcome, err)
			} else {
				ro.Result = result
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
	// Ordered is the item's Bill.Ordered, a local mark the bills the transfer
	// makes keep (NIP-CASH §Data Model: a new wallet made from an ordered slice
	// is ordered, and an in-place reassignment keeps the mark).
	Ordered bool
}

// TransferMany transfers or splits several bills in one request. Every item
// carries a request_id (one is generated when Params has none) and is written
// ahead to j, as device's, with its envelope's exact deadline before anything is
// published. Outcomes carry the request_id; NeedsLookup says which to look up.
func (s *BatchSession) TransferMany(ctx context.Context, items []BatchTransfer, j Journal, device string) ([]TransferOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	// Kept so each result can be parsed through the SAME params that authorized it —
	// the delivered token is encrypted to that credential.
	paramsByID := make(map[string]nipcash.CashTransferParams, len(items))
	orderedByID := make(map[string]bool, len(items))
	for i, it := range items {
		it := it
		if it.Params.RequestID == "" {
			rid, err := nipcash.NewRequestID()
			if err != nil {
				return nil, err
			}
			it.Params.RequestID = rid
		}
		if err := it.Bill.check(itemID(it.ID, i), s.HubIdentity()); err != nil {
			return nil, err
		}
		pc, err := it.Params.Pending(it.Bill.target)
		if err != nil {
			return nil, err
		}
		paramsByID[itemID(it.ID, i)] = it.Params
		orderedByID[itemID(it.ID, i)] = it.Bill.Ordered
		builders = append(builders, itemBuilder{
			ID: itemID(it.ID, i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if err := it.Bill.check(id, s.HubIdentity()); err != nil {
					return transport.Item{}, err
				}
				return it.Params.Item(id, it.Bill.target, it.Bill.connSecret, b)
			},
			RequestID: it.Params.RequestID,
			Pending:   s.pendingAt(pc),
		})
	}

	// sendBatch can return outcomes AND an error, when a reply arrived in fewer chunks
	// than the hub sent. Those outcomes are real answers and must not be discarded —
	// the error says part of the picture is missing, not that none of it is.
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{journal: j, device: device})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]TransferOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		to := TransferOutcome{ItemOutcome: o, Ordered: orderedByID[o.ID]}
		if o.Succeeded() {
			// ParseResult, never a plain unmarshal: a spun-off wallet's token
			// arrives ENCRYPTED to its new owner, and only the credential that
			// authorized this item can open it. Unmarshalling would return
			// ciphertext in a field named for a token — usable-looking and useless.
			result, err := paramsByID[o.ID].ParseResult(o.Result)
			if err != nil {
				to.ItemOutcome = parseFailure(to.ItemOutcome, err)
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
	// Params' Sources[0] is the item's target and signs its item proof.
	Params nipcash.CashConsolidateParams
}

// ConsolidateOutcome is one consolidation's answer.
type ConsolidateOutcome struct {
	ItemOutcome
	Result *nipcash.CashConsolidateResult
	// Ordered is set when every source was ordered: the merged bill is ordered
	// too (NIP-CASH §Consolidating Tokens). A local mark, never on the wire.
	Ordered bool
}

// ConsolidateMany performs several consolidations in one request.
//
// Worth knowing how this interacts with splitting. A consolidate item grows with its
// source count, so a batch of consolidations can exceed one envelope far sooner than a
// batch of redemptions — and the SDK splits across envelopes rather than refusing. A
// single consolidation whose sources alone exceed the hub's announced max_bytes cannot
// be split at all and returns ErrItemTooLarge: the caller must consolidate in stages.
//
// Every item carries a request_id and is written ahead to j, as TransferMany's.
//
// Each item is checked on its own before anything is written or sent: sources
// over the Hub's announced max_consolidate_sources are refused with
// ErrTooManySources, and an item that fits no envelope with ErrItemTooLarge
// (NIP-CASH §Envelopes; both wrap ErrItemTooLarge). The caller splits such an
// item into several consolidates, each a new call.
//
// An item whose sources' ordered marks differ (nipcash.Source.Ordered, or the
// item's Bill.Ordered for the source that is its bill) is refused with
// ErrMixedOrdered before anything is written or sent: a Hub refuses that mix
// with RESTRICTED (NIP-CASH §Consolidating Tokens, step 3).
func (s *BatchSession) ConsolidateMany(ctx context.Context, items []BatchConsolidate, j Journal, device string) ([]ConsolidateOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	// Same reason as TransferMany: the merged wallet's token is delivered encrypted.
	paramsByID := make(map[string]nipcash.CashConsolidateParams, len(items))
	orderedByID := make(map[string]bool, len(items))
	for i, it := range items {
		it := it
		if it.Params.RequestID == "" {
			rid, err := nipcash.NewRequestID()
			if err != nil {
				return nil, err
			}
			it.Params.RequestID = rid
		}
		if err := it.Bill.check(itemID(it.ID, i), s.HubIdentity()); err != nil {
			return nil, err
		}
		ordered, err := consolidateOrdered(it.Bill, it.Params.Sources)
		if err != nil {
			return nil, mixedItem(itemID(it.ID, i))
		}
		pc, err := it.Params.Pending()
		if err != nil {
			return nil, err
		}
		paramsByID[itemID(it.ID, i)] = it.Params
		orderedByID[itemID(it.ID, i)] = ordered
		builders = append(builders, itemBuilder{
			ID: itemID(it.ID, i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if err := it.Bill.check(id, s.HubIdentity()); err != nil {
					return transport.Item{}, err
				}
				return it.Params.Item(id, it.Bill.target, it.Bill.connSecret, b)
			},
			RequestID: it.Params.RequestID,
			Pending:   s.pendingAt(pc),
		})
	}

	if err := s.checkConsolidateItems(items, builders); err != nil {
		return nil, err
	}

	// sendBatch can return outcomes AND an error, when a reply arrived in fewer chunks
	// than the hub sent. Those outcomes are real answers and must not be discarded —
	// the error says part of the picture is missing, not that none of it is.
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{journal: j, device: device})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]ConsolidateOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		co := ConsolidateOutcome{ItemOutcome: o, Ordered: orderedByID[o.ID]}
		if o.Succeeded() {
			// ParseResult for the reason TransferMany uses it: the merged wallet's
			// token is delivered encrypted to its new owner.
			result, err := paramsByID[o.ID].ParseResult(o.Result)
			if err != nil {
				co.ItemOutcome = parseFailure(co.ItemOutcome, err)
			} else {
				co.Result = result
			}
		}
		out = append(out, co)
	}
	return out, sendErr
}

// checkConsolidateItems refuses, before anything is written, an item over the
// announced source cap or one that fits no envelope on its own. An unusable
// announcement is left to sendBatch, which reports it.
func (s *BatchSession) checkConsolidateItems(items []BatchConsolidate, builders []itemBuilder) error {
	limits := s.Limits()
	if limits.Validate() != nil {
		return nil
	}
	notAfter := time.Now().Add(s.deadlineWindow()).Unix()
	for i, it := range items {
		id := itemID(it.ID, i)
		if n := len(it.Params.Sources); n > limits.MaxConsolidateSources {
			return fmt.Errorf("%w: %w: item %q has %d sources, the hub's max_consolidate_sources is %d",
				ErrItemTooLarge, ErrTooManySources, id, n, limits.MaxConsolidateSources)
		}
		if err := fitsAlone(builders[i], s.HubIdentity(), limits, notAfter); err != nil {
			return err
		}
	}
	return nil
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

// parseFailure turns a result that did not parse into its outcome: a tombstone
// (the bill is gone; nothing moved) is OutcomeError carrying Gone, never a
// success; anything else is an undecodable answer.
func parseFailure(o ItemOutcome, err error) ItemOutcome {
	var gone *nipcash.BillGone
	if errors.As(err, &gone) {
		o.State = OutcomeError
		o.Error = &transport.ResultError{Message: gone.Error()}
		t := gone.Tombstone
		o.Gone = &t
		return o
	}
	o.State = OutcomeError
	o.Error = decodeError(o.ID, err)
	o.Undecodable = true
	return o
}

// pendingAt completes a call for the send path: the Hub identity and H read
// before sending, and the deadline of the envelope it was packed into.
func (s *BatchSession) pendingAt(pc nipcash.PendingCall) func(int64) nipcash.PendingCall {
	return func(deadline int64) nipcash.PendingCall {
		pc.Deadline, pc.HubIdentity, pc.MaxRequestAge = deadline, s.HubIdentity(), s.MaxRequestAge()
		return pc
	}
}
