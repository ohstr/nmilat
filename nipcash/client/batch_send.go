package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/wire"
)

// sendOptions carry what a bill-creating call needs on the send path.
type sendOptions struct {
	journal Journal
	device  string
}

// deadlineWindow is how far ahead an envelope's not_after is set: DeadlineWindow
// of the announced H, or 30 s when the Hub announced none.
func (s *BatchSession) deadlineWindow() time.Duration {
	h := s.MaxRequestAge()
	if h < nipcash.MinMaxRequestAge {
		return 30 * time.Second
	}
	return time.Duration(nipcash.DeadlineWindow(h)) * time.Second
}

// sendBatch packs builders into envelopes lazily, one at a time, publishes each,
// and joins every reply back to the items that asked.
//
// Each envelope's not_after is set when it is packed (now + the deadline window),
// its calls carrying a request_id are written ahead with that exact deadline,
// and, immediately before publishing, at least MinPublishMargin seconds must be
// left (else ErrNotSent wrapping ErrDeadlineTooClose). One outcome per requested
// item, always; an envelope that got no reply yields OutcomeUnanswered for
// everything it carried.
//
// An envelope the Hub refuses whole with QUOTA_EXCEEDED or BAD_REQUEST ran
// nothing (NIP-CASH §Chunked Replies). Once per batch, the announcement is then
// re-read and, when the Hub's limits or inbox changed, the envelope's items
// without a request_id are packed again under them and sent in fresh envelopes;
// otherwise, and always for a call carrying a request_id (never resent under
// the same id, NIP-CASH §Errors), the refusal is the item's outcome.
//
// Every spend carries a request_id, so in practice only reads (cash_status,
// quotes, lookups) are packed again. A spend in an envelope refused whole gets
// the refusal as its outcome, and Recover closes it refused: the caller must
// issue it again under a fresh request_id, packed under the current limits.
func (s *BatchSession) sendBatch(ctx context.Context, builders []itemBuilder, opts sendOptions) ([]ItemOutcome, error) {
	if len(builders) == 0 {
		return nil, nil
	}
	// No call of any kind goes to a Hub whose newest announcement was rejected:
	// a read or a bearer redeem would otherwise reach a retired inbox.
	if _, err := s.usable(); err != nil {
		return nil, err
	}
	if err := s.checkBillCalls(builders, opts); err != nil {
		return nil, err
	}
	if err := checkReplacementBuilders(ctx, builders); err != nil {
		return nil, err
	}
	limits := s.Limits()
	if err := limits.Validate(); err != nil {
		return nil, fmt.Errorf("nipcash/client: hub announced an unusable envelope policy: %w", err)
	}

	outcomes := make([]ItemOutcome, 0, len(builders))
	var incomplete []error
	remaining := builders
	repacked := false
	for i := 0; len(remaining) > 0; i++ {
		notAfter := time.Now().Add(s.deadlineWindow()).Unix()
		env, ids, consumed, err := packOne(remaining, s.HubIdentity(), limits, notAfter)
		if err != nil {
			return outcomes, err
		}
		p := packedEnvelope{Envelope: env, ItemIDs: ids}
		packedNow := remaining[:consumed]
		remaining = remaining[consumed:]

		written, err := writeAhead(ctx, packedNow, notAfter, opts)
		if err != nil {
			return withNotSent(outcomes, packedNow, remaining, nil), fmt.Errorf("%w: write ahead: %v", ErrNotSent, err)
		}
		got, accepted, err := s.sendOne(ctx, p, i)
		if !repacked && policyRefused(got) {
			// The Hub refused the whole envelope for a limit it enforces: nothing
			// ran, so its items without a request_id are packed again, once, under
			// the Hub's current announcement, when that differs from the copy they
			// were packed under. A call carrying a request_id is never resent under
			// the same id (NIP-CASH §Errors): it keeps the refusal as its outcome,
			// and the caller re-issues it as a new call.
			repacked = true
			retry, keep := splitRebuildable(packedNow)
			if len(retry) > 0 {
				if fresh, ok := s.refreshedPolicy(ctx, limits, retry, opts); ok {
					limits = fresh
					if len(keep) > 0 {
						recordAccepted(ctx, keep, accepted, opts)
						outcomes = append(outcomes, withAccepted(withRequestIDs(outcomesFor(got, keep), keep, written), accepted)...)
					}
					remaining = append(retry, remaining...)
					continue
				}
			}
		}
		recordAccepted(ctx, packedNow, accepted, opts)
		if err != nil && len(got) == 0 && errors.Is(err, ErrNotSent) {
			// Nothing of this envelope was published. On the first envelope its
			// items get no outcome, and the caller closes their written-ahead
			// calls as not sent; partway through a batch, this envelope's and every
			// later item get OutcomeNotSent, so one outcome per item holds and the
			// calls an earlier envelope published are told apart.
			return withNotSent(outcomes, packedNow, remaining, written), err
		}
		got = withAccepted(withRequestIDs(got, packedNow, written), accepted)
		if len(got) > 0 {
			outcomes = append(outcomes, got...)
			if err != nil {
				incomplete = append(incomplete, err)
			}
			continue
		}
		if err != nil {
			outcomes = append(outcomes, withAccepted(withRequestIDs(unansweredOutcomes(p.ItemIDs, i), packedNow, written), accepted)...)
			incomplete = append(incomplete, err)
		}
	}
	if len(incomplete) > 0 {
		return outcomes, errors.Join(incomplete...)
	}
	return outcomes, nil
}

// checkReplacementBuilders is checkReplacement over every call of a batch.
func checkReplacementBuilders(ctx context.Context, builders []itemBuilder) error {
	if _, ok := ctx.Value(replacementKey{}).(nipcash.PendingCall); !ok {
		return nil
	}
	var calls []nipcash.PendingCall
	for _, b := range builders {
		if b.Pending != nil {
			calls = append(calls, b.Pending(0))
		}
	}
	return checkReplacement(ctx, calls)
}

// withNotSent gives every item of the envelope that was not published (packed,
// with its written-ahead calls) and of every later one (rest) OutcomeNotSent,
// when earlier envelopes already have outcomes. With none, it adds nothing.
func withNotSent(outcomes []ItemOutcome, packed, rest []itemBuilder, written map[string]*nipcash.PendingCall) []ItemOutcome {
	if len(outcomes) == 0 {
		return outcomes
	}
	add := func(bs []itemBuilder, written map[string]*nipcash.PendingCall) {
		out := make([]ItemOutcome, 0, len(bs))
		for _, b := range bs {
			out = append(out, ItemOutcome{ID: b.ID, State: OutcomeNotSent})
		}
		outcomes = append(outcomes, withRequestIDs(out, bs, written)...)
	}
	add(packed, written)
	add(rest, nil)
	return outcomes
}

// checkBillCalls is the check before anything is written: a call carrying a
// request_id needs a journal, a Hub announcing a usable max_request_age, and an
// id no other item of the batch carries.
func (s *BatchSession) checkBillCalls(builders []itemBuilder, opts sendOptions) error {
	seen := map[string]bool{}
	for _, b := range builders {
		if b.RequestID == "" {
			continue
		}
		if opts.journal == nil {
			return ErrNoJournal
		}
		if seen[b.RequestID] {
			return ErrDuplicateRequestID
		}
		seen[b.RequestID] = true
	}
	if len(seen) == 0 {
		return nil
	}
	ann, err := s.usable()
	if err != nil {
		return err
	}
	return ann.ValidateForBillCalls()
}

// writeAhead writes the envelope's calls carrying a request_id, with its exact
// deadline, before anything is published.
func writeAhead(ctx context.Context, packed []itemBuilder, deadline int64, opts sendOptions) (map[string]*nipcash.PendingCall, error) {
	var calls []nipcash.PendingCall
	byID := map[string]*nipcash.PendingCall{}
	for _, b := range packed {
		if b.Pending == nil {
			continue
		}
		pc := asReplacement(ctx, b.Pending(deadline))
		pc.Deadline, pc.Device = deadline, opts.device
		calls = append(calls, pc)
		byID[b.ID] = &calls[len(calls)-1]
	}
	if len(calls) == 0 {
		return nil, nil
	}
	if err := opts.journal.WriteAhead(ctx, calls); err != nil {
		return nil, err
	}
	if err := derivedWritten(ctx, calls); err != nil {
		return nil, err
	}
	return byID, nil
}

// withRequestIDs stamps each outcome with the request_id its item carried.
func withRequestIDs(out []ItemOutcome, packed []itemBuilder, written map[string]*nipcash.PendingCall) []ItemOutcome {
	ids := map[string]string{}
	for _, b := range packed {
		ids[b.ID] = b.RequestID
	}
	for i := range out {
		out[i].RequestID = ids[out[i].ID]
		if pc, ok := written[out[i].ID]; ok {
			cp := *pc
			out[i].pending = &cp
		}
	}
	return out
}

// recordAccepted tells a Journal implementing AcceptedRecorder which relays
// accepted the envelope, once per call carrying a request_id. A failure never
// fails the call.
func recordAccepted(ctx context.Context, packed []itemBuilder, accepted []string, opts sendOptions) {
	rec, ok := opts.journal.(AcceptedRecorder)
	if !ok || len(accepted) == 0 {
		return
	}
	for _, b := range packed {
		if b.RequestID != "" {
			_ = rec.RecordAccepted(ctx, b.RequestID, append([]string(nil), accepted...))
		}
	}
}

// withAccepted stamps each outcome with the relays that accepted its envelope.
func withAccepted(out []ItemOutcome, accepted []string) []ItemOutcome {
	if len(accepted) == 0 {
		return out
	}
	for i := range out {
		out[i].Accepted = append([]string(nil), accepted...)
	}
	return out
}

// sendOne publishes one envelope and waits for its reply. accepted names the
// relays that took the request.
func (s *BatchSession) sendOne(ctx context.Context, p packedEnvelope, index int) ([]ItemOutcome, []string, error) {
	// One snapshot, re-checked per envelope: a Refresh mid-batch that rejects
	// the newest announcement stops every envelope not yet published.
	ann, err := s.usable()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrNotSent, err)
	}
	limits, inbox := ann.EffectiveLimits(), ann.Inbox
	plaintext, err := p.Envelope.Encode(limits)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: encode envelope %d: %v", ErrNotSent, index, err)
	}
	req, conversationKey, err := s.wrap(ctx, plaintext, inbox, p.Envelope.NotAfter)
	if err != nil {
		return nil, nil, err
	}
	if time.Until(time.Unix(p.Envelope.NotAfter, 0)) < nipcash.MinPublishMargin*time.Second {
		return nil, nil, fmt.Errorf("%w: %w", ErrNotSent, ErrDeadlineTooClose)
	}
	replyKey, err := transport.DeriveReplyKey(conversationKey, p.Envelope.ReplyTo)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: reply key for envelope %d: %v", ErrNotSent, index, err)
	}
	fan, err := s.subscribeAndPublish(ctx, p.Envelope.ReplyTo, req)
	if err != nil {
		return nil, nil, fmt.Errorf("send envelope %d: %w", index, err)
	}
	defer fan.stop()
	out, err := s.collectFrom(ctx, fan, replyKey, p, index)
	return out, fan.acceptedRelays(), err
}

// ErrIncompleteReply means some chunks of a multi-event reply never arrived.
//
// Distinct from an omission on purpose, and the distinction matters most exactly where
// it is least convenient: having received 2 of 3 chunks, reporting the missing items as
// omitted would claim the hub said nothing about work it may well have done — for
// cash_redeem, about money that moved. "Ask again" and "that is final" support different
// actions, so they are different answers.
var ErrIncompleteReply = errors.New("nipcash/client: reply arrived in fewer chunks than the hub sent")

// collectReply gathers however many events the hub split its answer into, and joins them
// into one outcome per requested item.
//
// The hub states its own total (NIP-CASH §Chunked Replies), which is what makes this
// terminate: a client cannot instead collect until every id is answered, because an
// omitted item is never answered and that is indistinguishable from a chunk still in
// flight.
//
// Nothing a validly decrypted chunk decided is ever thrown away. A reply whose chunks
// contradict each other is incomplete, not void: collection continues until not_after
// (a later chunk may still hold a new bill's only token), and every decided outcome is
// returned beside ErrReplyConflict. An item answered twice is OutcomeConflict on its
// own; its siblings keep their answers.
func (s *BatchSession) collectReply(
	ctx context.Context,
	replies <-chan *nip01.Event,
	replyKey [32]byte,
	p packedEnvelope,
	index int,
) ([]ItemOutcome, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return s.collectFrom(ctx, staticReplies(ctx, replies), replyKey, p, index)
}

// collectFrom is collectReply over a fan-out: while no chunk has arrived, a relay
// silent past its share of the wait, or every open stream ending, moves the
// request on to the next untried relay.
func (s *BatchSession) collectFrom(
	ctx context.Context,
	fan *replyFanout,
	replyKey [32]byte,
	p packedEnvelope,
	index int,
) ([]ItemOutcome, error) {
	state := newReplyState(p)
	seenEvents := map[string]struct{}{}
	maxBytes := s.Limits().MaxEnvelopeBytes

	// Bound the wait by the envelope's OWN not_after, which was already computed and
	// signed before it was sent (NIP-CASH §Chunked Replies). A hub cannot be trusted
	// to bound a client's wait: one declaring total 2 and sending one chunk would
	// otherwise hold the caller for its whole deadline. Past not_after the hub is done
	// with this envelope, so nothing further is coming. This only ever tightens a
	// caller's own deadline.
	if p.Envelope.NotAfter > 0 {
		deadline := time.Unix(p.Envelope.NotAfter, 0)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	finish := func(cause error) ([]ItemOutcome, error) {
		if state.decoded == 0 {
			// Nothing usable arrived: the caller marks every item unanswered.
			if len(state.decodeErrs) > 0 {
				return nil, fmt.Errorf("envelope %d: %w", index, errors.Join(append([]error{cause}, state.decodeErrs...)...))
			}
			return nil, fmt.Errorf("envelope %d: %w", index, cause)
		}
		out, err := state.outcomes(index)
		if err != nil {
			err = fmt.Errorf("envelope %d: %w", index, err)
		}
		return out, err
	}

	var silence *time.Timer
	var silent <-chan time.Time
	// take reads one event; done is set once the reply is complete.
	take := func(ev *nip01.Event) (out []ItemOutcome, done bool, err error) {
		// The same event from two relays is one chunk, not a repeat (NIP-CASH
		// §Chunked Replies). An event without an id is keyed by its content, so a
		// copy is still recognised as one.
		key := ev.ID
		if key == "" {
			key = "content:" + ev.Content
		}
		if _, dup := seenEvents[key]; dup {
			return nil, false, nil
		}
		seenEvents[key] = struct{}{}
		plaintext, err := nip44.Decrypt(ev.Content, replyKey[:])
		if err != nil {
			// Addressed to us but not written by the hub. The p-tag addresses a
			// response; it does not authenticate one. Only the derived key proves
			// authorship (the author is never checked, §The Reply Key), so this is
			// discarded and the real reply may still arrive.
			return nil, false, nil
		}
		chunk, err := transport.DecodeResponseChunk([]byte(plaintext), p.Envelope.Nonce, p.ItemIDs, maxBytes)
		if err != nil {
			// Unusable as a whole (bad JSON, another request's nonce, oversized):
			// it decides nothing. The chunk it should have been stays missing, so
			// the reply cannot complete without it, and the reason is reported.
			state.decodeErrs = append(state.decodeErrs, fmt.Errorf("decode reply chunk: %w", err))
			return nil, false, nil
		}
		state.add(key, chunk)
		if state.complete() {
			out, err := state.outcomes(index)
			return out, true, err
		}
		// A relay answered: it serves the request, and no other is contacted.
		if silent != nil {
			silence.Stop()
			silent = nil
		}
		return nil, false, nil
	}

	arm := func() {
		if silence != nil {
			silence.Stop()
		}
		silent = nil
		if n := fan.untried(); n > 0 && state.decoded == 0 && p.Envelope.NotAfter > 0 {
			silence = time.NewTimer(relayAnswerWait(s.cfg.relayAnswerWait, p.Envelope.NotAfter, n))
			silent = silence.C
		}
	}
	arm()
	defer func() {
		if silence != nil {
			silence.Stop()
		}
	}()

	for {
		select {
		case <-silent:
			// Up but not answering, as a relay the Hub no longer reads: the same
			// request goes to the next hint too.
			silent = nil
			if state.decoded == 0 && fan.sendNext(ctx) {
				arm()
			}
		case ev := <-fan.out:
			if ev != nil {
				if out, done, err := take(ev); done {
					return out, err
				}
				continue
			}
			if fan.openStreams() > 0 {
				continue
			}
			// Every stream has ended and all they sent is queued: read it first.
			for drained := false; !drained; {
				select {
				case ev := <-fan.out:
					if ev == nil {
						continue
					}
					if out, done, err := take(ev); done {
						return out, err
					}
				default:
					drained = true
				}
			}
			if state.decoded == 0 && fan.sendNext(ctx) {
				arm()
				continue
			}
			// The relays closed on us: the same fact as a timeout. Some chunks may
			// have arrived and the rest never will.
			return finish(errors.New("reply channel closed"))

		case <-ctx.Done():
			return finish(ctx.Err())
		}
	}
}

// subscriptionAckWait bounds how long a send waits for the relay to acknowledge
// the reply subscription before publishing anyway.
const subscriptionAckWait = 2 * time.Second

// subscribeAndPublish sends one request and returns the fan-out its reply will arrive on.
//
// The reply is published on the relay the request arrived on (NIP-CASH §Addressing the
// Response), so the request goes to the relay this client is listening on, never to
// another. Relays are tried in order (§Multiple Relay Hints): subscribe there, then
// publish there, and the first relay that accepts the request is the one it went to.
// The rest stay untried until that relay fails to answer (replyFanout.sendNext).
//
// Subscribe BEFORE publishing. A hub may answer immediately, and a subscription opened
// afterwards can miss an ephemeral event entirely — relays are not required to store
// kind 23191, and this transport specifically does not want them to.
//
// A relay whose publish failed keeps its subscription. A publish that timed out may
// still have reached the hub, whose reply then lands there; a client that sent to
// several relays listens on all of them, merged into one stream.
func (s *BatchSession) subscribeAndPublish(ctx context.Context, replyTo string, req *outgoing) (*replyFanout, error) {
	relays := s.Relays()
	if len(relays) == 0 {
		return nil, fmt.Errorf("%w: session has no relays", ErrNotSent)
	}
	f := newReplyFanout(ctx, s, replyTo, req, relays)
	if f.sendNext(ctx) {
		return f, nil
	}
	f.stop()
	// Every relay's failure is kept, not just the last: with failover the useful
	// question is why all of them failed (NIP-CASH §Multiple Relay Hints).
	if !f.attempted {
		return nil, fmt.Errorf("%w: no relay could be reached: %w", ErrNotSent, errors.Join(f.failures...))
	}
	return nil, fmt.Errorf("nipcash/client: no relay took the request: %w", errors.Join(f.failures...))
}

// replyFanout is one request on the relays it has gone to so far, in hint order,
// and the replies from every one of them merged into one stream. A relay that
// accepted the request but stays silent, or closes, is followed by the next
// untried one (NIP-CASH §Multiple Relay Hints: continue on failure, never give up
// while a listed relay is untried). The same event goes to each, so the Hub's
// nonce check runs it once.
type replyFanout struct {
	ctx     context.Context
	s       *BatchSession
	replyTo string
	req     *outgoing
	relays  []string
	// out carries every stream's events, and a nil each time a stream ends.
	out chan *nip01.Event

	mu        sync.Mutex
	next      int
	open      int
	stops     []func()
	accepted  []string
	failures  []error
	attempted bool
}

func newReplyFanout(ctx context.Context, s *BatchSession, replyTo string, req *outgoing, relays []string) *replyFanout {
	return &replyFanout{ctx: ctx, s: s, replyTo: replyTo, req: req, relays: relays,
		out: make(chan *nip01.Event, 8)}
}

// staticReplies is a fan-out over one stream already open, with no relay to move to.
func staticReplies(ctx context.Context, in <-chan *nip01.Event) *replyFanout {
	f := newReplyFanout(ctx, nil, "", nil, nil)
	f.add(in, func() {})
	return f
}

// add forwards stream into the merged one until it closes or the send ends.
func (f *replyFanout) add(in <-chan *nip01.Event, stop func()) {
	f.mu.Lock()
	f.open++
	f.stops = append(f.stops, stop)
	f.mu.Unlock()
	go func() {
		for ev := range in {
			if ev == nil {
				continue
			}
			select {
			case f.out <- ev:
			case <-f.ctx.Done():
				return
			}
		}
		// Counted down after the stream's last event went out, then a nil marks
		// the end: once none is open, every event sent is already queued.
		f.mu.Lock()
		f.open--
		f.mu.Unlock()
		select {
		case f.out <- nil:
		case <-f.ctx.Done():
		}
	}()
}

// sendNext subscribes and publishes on the next untried relays until one accepts
// the request, and reports whether one did.
func (f *replyFanout) sendNext(ctx context.Context) bool {
	for {
		f.mu.Lock()
		if f.next >= len(f.relays) {
			f.mu.Unlock()
			return false
		}
		raw := f.relays[f.next]
		f.next++
		f.mu.Unlock()
		if f.sendTo(ctx, raw) {
			return true
		}
	}
}

func (f *replyFanout) sendTo(ctx context.Context, raw string) bool {
	fail := func(err error) bool {
		f.mu.Lock()
		f.failures = append(f.failures, fmt.Errorf("relay %q: %w", raw, err))
		f.mu.Unlock()
		return false
	}
	relayURL, err := url.Parse(raw)
	if err != nil {
		return fail(err)
	}
	events, ready, stop, err := subscribeReplies(f.ctx, relayURL, f.replyTo)
	if err != nil {
		return fail(err)
	}
	f.add(events, stop)
	// The REQ and the request travel on separate connections, so nothing
	// orders them at the relay: a request that overtook its subscription had
	// its reply delivered to nobody, and the client waited out not_after for
	// an answer the hub had sent. EOSE is the relay saying it has the
	// subscription. Bounded, so a relay that never sends one still gets the
	// request.
	select {
	case <-ready:
	case <-time.After(subscriptionAckWait):
	case <-ctx.Done():
	}
	f.mu.Lock()
	f.attempted = true
	f.mu.Unlock()
	if err := f.s.publishTo(ctx, relayURL, f.req); err != nil {
		return fail(err)
	}
	f.mu.Lock()
	f.accepted = append(f.accepted, raw)
	f.mu.Unlock()
	if hook := afterPublishFrom(ctx); hook != nil {
		hook()
	}
	return true
}

func (f *replyFanout) untried() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.relays) - f.next
}

func (f *replyFanout) openStreams() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open
}

// acceptedRelays are the relays that took the request, in the order they did.
func (f *replyFanout) acceptedRelays() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.accepted...)
}

func (f *replyFanout) stop() {
	f.mu.Lock()
	stops := f.stops
	f.stops = nil
	f.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

// minRelayAnswerWait is the shortest a relay is given to answer before the
// request also goes to the next hint.
const minRelayAnswerWait = time.Second

// relayAnswerWait is fixed when set (WithRelayAnswerWait), else what is left
// until notAfter shared between the relay just sent to and every untried one, so
// each is tried before the envelope expires.
func relayAnswerWait(fixed time.Duration, notAfter int64, untried int) time.Duration {
	if fixed > 0 {
		return fixed
	}
	w := time.Until(time.Unix(notAfter, 0)) / time.Duration(untried+1)
	return max(w, minRelayAnswerWait)
}

// subscribeReplies opens a subscription for one envelope's response on one relay.
//
// Filtered on the p-tag carrying reply_to (NIP-CASH §Addressing the Response). That value
// appears nowhere else — not as an author, not in the request's tags — so nothing on the
// relay links this subscription to the request it answers.
//
// Uses SubscribeWithID + Read rather than Connection.Subscribe, and that is the whole
// correctness of this function. Subscribe closes its channel at EOSE by design (see its own
// doc comment), and EOSE means "end of STORED events" — everything live arrives after it. A
// reply is always live: the hub has not even seen the request when the subscription opens,
// and kind 23191 is ephemeral so no relay stores it. Subscribe therefore closed this
// subscription before the reply could ever arrive, and every item came back as an omission —
// indistinguishable, by design, from a hub that declined to serve them.
//
// It survived every in-process test because those never cross a real relay, so nothing ever
// sent an EOSE. The first live run failed on all items, immediately and silently.
func subscribeReplies(ctx context.Context, relayURL *url.URL, replyTo string) (<-chan *nip01.Event, <-chan struct{}, func(), error) {
	filter := nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{transport.KindPrivateResponse},
		Tags:  map[string][]string{"p": {replyTo}},
	})

	conn, err := relayclient.Connect(ctx, relayURL)
	if err != nil {
		return nil, nil, nil, err
	}
	subID := uuid.NewString()
	if !conn.SubscribeWithID(subID, filter) {
		conn.Close()
		return nil, nil, nil, errors.New("connection closed before the subscription could be sent")
	}

	// ready closes once the relay has acknowledged the subscription (EOSE, or a
	// CLOSED), or the reader stops: see subscribeAndPublish for why it waits.
	ready := make(chan struct{})
	var readyOnce sync.Once
	markReady := func() { readyOnce.Do(func() { close(ready) }) }

	// Buffered and forwarding EVERY event, not just the first: a hub may answer one
	// request with several chunks (NIP-CASH §Chunked Replies), so stopping at the
	// first would strand the rest and the caller would read them as omissions.
	out := make(chan *nip01.Event, 8)
	go func() {
		defer close(out)
		defer markReady()
		for {
			select {
			case msg, ok := <-conn.Read():
				if !ok {
					return
				}
				switch m := msg.(type) {
				case *wire.EventSubscriptionResponse:
					// Other subscriptions do not exist on this connection today,
					// but filtering by id keeps that an implementation detail
					// rather than an assumption.
					if m.SubscriptionID != subID || m.Event == nil {
						continue
					}
					select {
					case out <- m.Event:
					case <-ctx.Done():
						return
					}
				case *wire.EOSESubscriptionResponse:
					// The end of STORED events, so never the end of this
					// subscription — every reply comes after it. It does say the
					// relay now has the subscription.
					if m.SubscriptionID == subID {
						markReady()
					}
				case *wire.ClosedSubscriptionResponse:
					// The relay ended it; nothing more will arrive.
					if m.SubscriptionID == subID {
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, ready, func() { conn.Close() }, nil
}

// policyRefused reports a reply that is one envelope-level refusal a stale copy
// of the Hub's policy explains: QUOTA_EXCEEDED (an envelope over max_bytes,
// max_items or max_verify_budget, NIP-CASH §Serving an Envelope E5, E6) or
// BAD_REQUEST (a not_after further ahead than max_request_age, E4). Either
// way no item ran.
func policyRefused(got []ItemOutcome) bool {
	if len(got) == 0 {
		return false
	}
	for _, o := range got {
		if o.State != OutcomeError || !o.envelopeLevel || o.Error == nil {
			return false
		}
		if o.Error.Code != nipcash.ErrCodeQuotaExceeded && o.Error.Code != nipcash.ErrCodeBadRequest {
			return false
		}
	}
	return true
}

// splitRebuildable splits an envelope's items into those that can be built
// again for a new envelope and those that cannot: a single-use item (a circle
// join, Measure set), and a call carrying a request_id, which is never resent
// under the same id.
func splitRebuildable(packed []itemBuilder) (retry, keep []itemBuilder) {
	for _, b := range packed {
		if b.Measure != nil || b.RequestID != "" || b.Pending != nil {
			keep = append(keep, b)
		} else {
			retry = append(retry, b)
		}
	}
	return retry, keep
}

// outcomesFor keeps the outcomes of the items in packed.
func outcomesFor(got []ItemOutcome, packed []itemBuilder) []ItemOutcome {
	ids := map[string]bool{}
	for _, b := range packed {
		ids[b.ID] = true
	}
	var out []ItemOutcome
	for _, o := range got {
		if ids[o.ID] {
			out = append(out, o)
		}
	}
	return out
}

// refreshedPolicy re-reads the announcement after a policy refusal and returns
// the limits to pack under, ok only when they, or the inbox, changed, are
// usable, and still admit the envelope's calls carrying a request_id. An
// unchanged policy would be refused again.
func (s *BatchSession) refreshedPolicy(ctx context.Context, packedUnder transport.Limits, packed []itemBuilder, opts sendOptions) (transport.Limits, bool) {
	inbox := s.Inbox()
	if s.Refresh(ctx) != nil {
		return packedUnder, false
	}
	fresh := s.Limits()
	if fresh == packedUnder && s.Inbox() == inbox {
		return packedUnder, false
	}
	if fresh.Validate() != nil || s.checkBillCalls(packed, opts) != nil {
		return packedUnder, false
	}
	return fresh, true
}
