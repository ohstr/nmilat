package client

import (
	"encoding/json"
	"fmt"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// OutcomeState is how one batched item ended up. There are three, not two, and the
// third is the one that matters.
type OutcomeState int

const (
	// OutcomeNotServed means the hub returned nothing for this item.
	//
	// This is the zero value on purpose, matching BillIndeterminate's reasoning: a
	// caller who forgets to check the state reads "I don't know", never a false
	// success or a false failure.
	//
	// It is deliberately information-free. A hub omits an item whose target it does
	// not hold, whose proof did not verify, or whose method it does not serve — and
	// those are indistinguishable by design, because distinguishing them would turn
	// batching into an oracle for which bills a hub holds (NIP-CASH §Responses). So
	// "not served" is the whole of what a caller learns, and inferring more from it
	// is a protocol violation rather than a clever optimisation.
	OutcomeNotServed OutcomeState = iota
	// OutcomeResult means the hub served this item and it succeeded. Result holds
	// the method's own result.
	OutcomeResult
	// OutcomeError means the hub served this item and refused it, with a reason.
	// This is distinct from OutcomeNotServed: the hub is telling the caller
	// something, and a circle join refused for non-membership or rate limiting MUST
	// arrive this way rather than as silence (NIP-CW §Private Join).
	OutcomeError
)

func (s OutcomeState) String() string {
	switch s {
	case OutcomeResult:
		return "result"
	case OutcomeError:
		return "error"
	case OutcomeNotServed:
		return "not served"
	default:
		return fmt.Sprintf("OutcomeState(%d)", int(s))
	}
}

// ItemOutcome is one batched item's answer, joined back to the item that asked.
//
// DecodeResponse gives a caller raw results and ResponseEnvelope.Omitted gives ids,
// leaving them to join the two and to remember which ids they sent. That join is
// where a caller can quietly go wrong — reading an omission as a failure, or losing
// track of which bill an id referred to — so it is done here instead.
type ItemOutcome struct {
	// ID is the item id this answers, as supplied by the caller.
	ID    string
	State OutcomeState
	// Result is the method's own result, set only when State is OutcomeResult.
	// Raw JSON because the concrete type differs per method; the per-method batch
	// helpers unmarshal it for their callers.
	Result json.RawMessage
	// Error is the hub's own reason, set only when State is OutcomeError.
	Error *transport.ResultError
	// Envelope identifies which request envelope carried this item, counting from
	// 0, for a batch the SDK split across several.
	//
	// Exposed because a split is otherwise invisible and its failures are not
	// independent: if one envelope never reached the relay, every item in it is
	// NotServed for a reason that has nothing to do with those bills. Without this a
	// caller cannot tell that from N unrelated omissions.
	Envelope int
}

// Succeeded reports whether this item was served and did not fail. Provided because
// `State == OutcomeResult` is easy to write as `Error == nil`, which is also true of
// an omission.
func (o ItemOutcome) Succeeded() bool { return o.State == OutcomeResult }

// SafeToResend reports whether re-sending this item cannot double-spend.
//
// Only an explicit error qualifies. The SDK never retries a money path on its own —
// cash_redeem has no idempotency key and a double redemption is unrecoverable, while
// a manual retry costs nothing — so this exists to tell a caller what they may
// safely do, not to do it for them.
//
// An omission is NOT safe to resend, and that is the important case. It means the
// hub said nothing, which is indistinguishable from an item that executed and whose
// response was lost. A caller who needs to know MUST ask: cash_status on the bill
// will say whether it is still live.
func (o ItemOutcome) SafeToResend() bool { return o.State == OutcomeError }

// joinOutcomes pairs a decoded response with the ids that were sent, so every
// requested item gets exactly one outcome.
//
// requestedIDs drives the loop rather than the response's results, which is what
// makes an omission representable at all: iterating the results could only ever
// produce outcomes for items the hub chose to answer.
func joinOutcomes(requestedIDs []string, resp *transport.ResponseEnvelope, envelope int) []ItemOutcome {
	byID := make(map[string]transport.Result, len(requestedIDs))
	if resp != nil {
		for _, r := range resp.Results {
			byID[r.ID] = r
		}
	}

	// An ENVELOPE-level error applies to every item in it, and it was being collected
	// and then never read — joinOutcomes walked Results only.
	//
	// The direction was fail-safe but it discarded the one thing that makes a spend
	// safe to retry. A hub replying envelope-level RATE_LIMITED means "no item ran",
	// which is exactly the fact a caller needs before resending a cash_redeem;
	// dropping it produced err=nil with every item merely "not served", i.e. the
	// indeterminate state a caller is told never to retry from. So a hub could strand
	// a caller permanently having done nothing at all.
	//
	// Surfaced per item rather than only on the envelope, because that is where every
	// caller already looks, and it keeps ResultError's documented envelope-level
	// contract working for honest hubs too.
	//
	// Note what this makes true: State becomes OutcomeError, and SafeToResend() is
	// exactly State == OutcomeError — so a caller WILL resend a spend on the strength
	// of this. That is deliberate, and it rests on two facts rather than on trusting
	// the hub:
	//
	//   - only the HUB can author this reply. It is authenticated by the reply key,
	//     derived from a per-envelope ephemeral ECDH, so a relay cannot forge one and
	//     a co-holder of the bill's connection secret cannot either.
	//   - a resend cannot double-spend even if the hub lied about nothing having run.
	//     Every money method carries its own idempotency guard — a redeem marks the
	//     slice claimed_at, a transfer burns a single-use proof row — so a second
	//     application finds nothing left to take. That is round 1's R1/R2 refutation,
	//     and this fix depends on it: if a bill method were ever added without such a
	//     guard, a lying envelope-level error would become a way to induce a double
	//     application, and this would have to become conservative again.
	var envelopeErr *transport.ResultError
	if resp != nil {
		envelopeErr = resp.Error
	}

	out := make([]ItemOutcome, 0, len(requestedIDs))
	for _, id := range requestedIDs {
		outcome := ItemOutcome{ID: id, Envelope: envelope, State: OutcomeNotServed}
		if envelopeErr != nil {
			// A decided refusal of the whole envelope, not an omission: the hub said
			// why, and it said it about everything inside.
			outcome.State = OutcomeError
			outcome.Error = envelopeErr
		}
		if r, ok := byID[id]; ok {
			switch {
			case r.Error != nil:
				outcome.State = OutcomeError
				outcome.Error = r.Error
			default:
				// A served item with neither error nor result is still a served
				// item: some methods answer with an empty body. Treating it as
				// omitted would report "the hub said nothing" when it did answer.
				outcome.State = OutcomeResult
				outcome.Result = r.Result
			}
		}
		out = append(out, outcome)
	}
	return out
}

// notServedOutcomes marks a whole envelope's items unserved, for when the envelope
// itself never got an answer — it could not be published, or no response arrived.
//
// Deliberately the same state a per-item omission produces, because from the bills'
// point of view it is the same fact: nothing is known about them. The Envelope field
// is what lets a caller notice the correlation.
func notServedOutcomes(requestedIDs []string, envelope int) []ItemOutcome {
	out := make([]ItemOutcome, 0, len(requestedIDs))
	for _, id := range requestedIDs {
		out = append(out, ItemOutcome{ID: id, Envelope: envelope, State: OutcomeNotServed})
	}
	return out
}
