package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nipcash"
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
	// OutcomeUnanswered means the reply was incomplete and no chunk that did arrive
	// mentions this item: some chunks never came, or nothing came at all.
	//
	// Not an omission. An omission is the hub's final word; this is the client not
	// having heard it (NIP-CASH §Chunked Replies: "ask again"). The item may have
	// run, so it is not safe to resend.
	OutcomeUnanswered
	// OutcomeConflict means the hub answered this item more than once (within one
	// chunk or across chunks, identical or not), answered it with a result while
	// another chunk said no item ran, or sent a result whose result_type is not the
	// item's method. The item has no decided outcome and is indeterminate: the
	// spec forbids picking one answer by arrival order or seq. The other items keep
	// theirs. Not safe to resend.
	OutcomeConflict
	// OutcomeNotSent means nothing of this item was published: the batch
	// stopped before its envelope went out (a send that could not start, a
	// deadline too close, an item that could not be built). The Hub never saw
	// it. Set only by CreateCircleWalletMany, so that every join has an
	// outcome; a join is single use, so a retry needs a new Prepare.
	OutcomeNotSent
)

func (s OutcomeState) String() string {
	switch s {
	case OutcomeResult:
		return "result"
	case OutcomeError:
		return "error"
	case OutcomeNotServed:
		return "not served"
	case OutcomeUnanswered:
		return "unanswered"
	case OutcomeConflict:
		return "conflict"
	case OutcomeNotSent:
		return "not sent"
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
	// Undecodable is set when the hub answered this item with a success this client
	// could not decode. State is then OutcomeError with an INTERNAL Error, but the
	// item DID run, so it is not safe to resend.
	Undecodable bool
	// Gone is the tombstone a value method was answered with: the bill is
	// destroyed and nothing moved. State is then OutcomeError.
	Gone *nipcash.Tombstone
	// Envelope identifies which request envelope carried this item, counting from
	// 0, for a batch the SDK split across several.
	//
	// Exposed because a split is otherwise invisible and its failures are not
	// independent: if one envelope never reached the relay, every item in it is
	// NotServed for a reason that has nothing to do with those bills. Without this a
	// caller cannot tell that from N unrelated omissions.
	Envelope int
	// RequestID is the request_id the item carried, "" for a call without one.
	RequestID string
	// Accepted names the relays that accepted the item's envelope: a Hub's
	// notices for the call arrive there (NIP-CO §Order Notice).
	Accepted []string
	// pending is the call written ahead for this item, with its exact deadline.
	pending *nipcash.PendingCall
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
//
// Nor is a success this client could not decode (Undecodable): the hub ran it.
func (o ItemOutcome) SafeToResend() bool { return o.State == OutcomeError && !o.Undecodable }

// ErrReplyConflict means the chunks of one reply contradict each other: they
// disagree about total, two different events carry one seq, a seq lies outside 1 to
// total, or an item was answered more than once. It wraps ErrIncompleteReply,
// because a contradictory reply is incomplete, not void (NIP-CASH §Chunked Replies):
// every outcome a chunk decided is still returned beside it.
var ErrReplyConflict = fmt.Errorf("%w: chunks contradict each other", ErrIncompleteReply)

// replyState gathers the chunks of one envelope's reply and decides, per item, what
// the reply as a whole says.
//
// It keeps every answer to every id rather than the latest, because the decision
// cannot be made per chunk: an item answered twice is indeterminate whichever answer
// came first (NIP-CASH §Chunked Replies forbids resolving it by arrival order or
// seq), and an omission is only final once every chunk is in. Nothing a validly
// decrypted chunk decided is ever dropped for a later chunk's fault.
type replyState struct {
	ids     []string
	methods map[string]string
	answers map[string][]transport.Result
	// envErrs are the envelope-level errors of the chunks that carried one.
	envErrs []*transport.ResultError
	// seqEvent maps each in-range seq to the event that carried it, so two different
	// events with one seq are told from the same event heard twice.
	seqEvent map[int]string
	declared int
	// conflicts are reply-level contradictions; gaps are reasons the reply is
	// incomplete without contradicting itself (a chunk that decided nothing).
	conflicts, gaps []string
	decoded         int
	decodeErrs      []error
}

func newReplyState(p packedEnvelope) *replyState {
	methods := make(map[string]string, len(p.Envelope.Items))
	for _, item := range p.Envelope.Items {
		methods[item.ID] = item.Method
	}
	return &replyState{
		ids:      p.ItemIDs,
		methods:  methods,
		answers:  map[string][]transport.Result{},
		seqEvent: map[int]string{},
	}
}

// add folds one decoded chunk in. eventKey identifies the event that carried it.
func (r *replyState) add(eventKey string, c *transport.DecodedChunk) {
	r.decoded++
	switch {
	case c.Total < 1 || c.Seq < 1 || c.Seq > c.Total:
		r.conflicts = append(r.conflicts, fmt.Sprintf("seq %d of %d is not a position in a reply", c.Seq, c.Total))
	default:
		if prev, ok := r.seqEvent[c.Seq]; ok && prev != eventKey {
			r.conflicts = append(r.conflicts, fmt.Sprintf("two events carry seq %d", c.Seq))
		} else {
			r.seqEvent[c.Seq] = eventKey
		}
	}
	if c.Total >= 1 {
		if r.declared == 0 {
			r.declared = c.Total
		} else if c.Total != r.declared {
			r.conflicts = append(r.conflicts, fmt.Sprintf("one chunk claims %d chunks, another %d", c.Total, r.declared))
		}
	}
	if c.DecidesNothing() {
		r.gaps = append(r.gaps, fmt.Sprintf("chunk %d carries neither results nor an error", c.Seq))
	}
	if c.Error != nil {
		r.envErrs = append(r.envErrs, c.Error)
	}
	for _, res := range c.Results {
		r.answers[res.ID] = append(r.answers[res.ID], res)
	}
}

// total is the hub's declared total bounded by the items requested (NIP-CASH
// §Chunked Replies: a client MUST bound total by the number of items it requested).
func (r *replyState) total() int { return min(r.declared, len(r.ids)) }

// malformed reports a reply that can no longer become complete, however many more
// chunks arrive.
func (r *replyState) malformed() bool { return len(r.conflicts) > 0 || len(r.gaps) > 0 }

// complete reports whether every chunk 1 to total has arrived and nothing about the
// set is malformed. Only then is an unanswered item an omission.
func (r *replyState) complete() bool {
	total := r.total()
	if total < 1 || r.malformed() {
		return false
	}
	for seq := 1; seq <= total; seq++ {
		if _, ok := r.seqEvent[seq]; !ok {
			return false
		}
	}
	return true
}

// outcomes decides one outcome per requested item, in request order, and says what
// was wrong with the reply as a whole. Decided outcomes and the reply's error are
// independent facts, and both are returned (NIP-CASH §Chunked Replies).
func (r *replyState) outcomes(envelope int) ([]ItemOutcome, error) {
	complete := r.complete()
	out := make([]ItemOutcome, 0, len(r.ids))
	var conflicted []string
	for _, id := range r.ids {
		o := ItemOutcome{ID: id, Envelope: envelope}
		rs := r.answers[id]
		switch {
		case len(rs) > 1:
			// Identical or not: the spec forbids accepting an id answered twice.
			o.State = OutcomeConflict
		case len(rs) == 1 && len(r.envErrs) > 0:
			// A result for an item another chunk said never ran.
			o.State = OutcomeConflict
		case len(rs) == 1:
			o = r.decide(o, rs[0])
		case len(r.envErrs) == 1:
			// An envelope-level error means no item ran, and it is surfaced for every
			// item the reply did not answer otherwise (§Chunked Replies). It decides
			// these items even when another chunk is missing.
			o.State = OutcomeError
			o.Error = r.envErrs[0]
		case len(r.envErrs) > 1:
			o.State = OutcomeConflict
		case complete:
			o.State = OutcomeNotServed
		default:
			o.State = OutcomeUnanswered
		}
		if o.State == OutcomeConflict {
			conflicted = append(conflicted, id)
		}
		out = append(out, o)
	}

	reasons := append([]string(nil), r.conflicts...)
	if len(conflicted) > 0 {
		reasons = append(reasons, fmt.Sprintf("items %q have no single answer", conflicted))
	}
	if len(r.envErrs) > 1 {
		reasons = append(reasons, fmt.Sprintf("%d chunks carry an envelope-level error", len(r.envErrs)))
	}
	var err error
	switch {
	case len(reasons) > 0:
		err = fmt.Errorf("%w: %s", ErrReplyConflict, strings.Join(reasons, "; "))
	case !complete:
		why := fmt.Sprintf("got %d of %d chunks", len(r.seqEvent), r.total())
		if len(r.gaps) > 0 {
			why = strings.Join(r.gaps, "; ")
		}
		err = fmt.Errorf("%w: %s", ErrIncompleteReply, why)
	}
	if err != nil && len(r.decodeErrs) > 0 {
		err = errors.Join(append([]error{err}, r.decodeErrs...)...)
	}
	return out, err
}

// decide reads the one answer an item got.
//
// A result is only a result when its result_type is the item's method (NIP-CASH
// §Responses (kind 23191)): a missing or different one is malformed, so the item has
// no decided outcome. An error object needs no result_type.
func (r *replyState) decide(o ItemOutcome, res transport.Result) ItemOutcome {
	switch {
	case res.HasBoth():
		o.State = OutcomeConflict
	case res.Error != nil:
		o.State = OutcomeError
		o.Error = res.Error
	case res.ResultType == "" || res.ResultType != r.methods[o.ID]:
		o.State = OutcomeConflict
	default:
		// A served item with an empty body is still a served item: some methods
		// answer with nothing more.
		o.State = OutcomeResult
		o.Result = res.Result
	}
	return o
}

// unansweredOutcomes marks a whole envelope's items unanswered, for when the
// envelope itself never got an answer — it could not be published, or no chunk
// arrived.
//
// Not "not served": that is a complete reply's omission, a final answer, and here
// the client heard no reply at all. The Envelope field is what lets a caller notice
// the correlation.
func unansweredOutcomes(requestedIDs []string, envelope int) []ItemOutcome {
	out := make([]ItemOutcome, 0, len(requestedIDs))
	for _, id := range requestedIDs {
		out = append(out, ItemOutcome{ID: id, Envelope: envelope, State: OutcomeUnanswered})
	}
	return out
}
