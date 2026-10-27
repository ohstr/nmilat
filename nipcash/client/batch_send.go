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
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/wire"
)

// defaultNotAfterWindow is how long a batch stays valid.
//
// Comfortably inside any horizon H a Hub may announce, which bounds how far ahead a hub will
// accept — a hub need only remember a nonce until the envelope carrying it can no longer
// be accepted, so asking for the maximum would make a hub remember more for no gain.
const defaultNotAfterWindow = 60 * time.Second

// sendBatch packs builders into envelopes, publishes each, and joins every reply back to
// the items that asked.
//
// One outcome per requested item, always, whatever happened. An envelope that could not
// be published, or got no reply, yields OutcomeUnanswered for everything it carried:
// nothing is known about those bills, and unlike an omission it is not the hub's final
// word. The Envelope field on each outcome is what lets a caller
// notice the correlation rather than read N independent omissions.
//
// Nothing here retries. cash_redeem has no idempotency key and a double redemption is
// unrecoverable, so a caller decides — ItemOutcome.SafeToResend tells them which items
// they may.
func (s *BatchSession) sendBatch(ctx context.Context, builders []itemBuilder) ([]ItemOutcome, error) {
	if len(builders) == 0 {
		return nil, nil
	}

	packed, err := packItems(builders, s.HubIdentity(), s.Limits(), defaultNotAfterWindow)
	if err != nil {
		// A packing failure is the caller's own — an item that cannot be built, or one
		// too large for any envelope. It must surface rather than become an unserved
		// outcome, which the caller would misread as the hub's choice.
		return nil, err
	}

	outcomes := make([]ItemOutcome, 0, len(builders))
	// Collected rather than returned immediately: one envelope arriving incompletely
	// must not hide the other envelopes' results, and the caller needs both the
	// outcomes and the knowledge that part of the picture is missing.
	var incomplete []error
	for i, p := range packed {
		got, err := s.sendOne(ctx, p, i)
		if err != nil && isStalePolicy(err) {
			// A refetch is worth exactly one retry, and only of the SEND: if the hub
			// changed its limits or inbox, the cached policy is stale and the envelope
			// was never served. Re-packing is not attempted here because the whole
			// batch's envelopes were sized against the old limits; the caller reruns
			// with a refreshed session instead, which is why the error surfaces.
			if s.Refresh(ctx) == nil {
				got, err = s.sendOne(ctx, p, i)
			}
		}

		// An incomplete reply still carries real answers for the chunks that did
		// arrive, so those are kept rather than thrown away and replaced with
		// wholesale ignorance. Only when nothing usable came back is the whole
		// envelope marked unserved.
		if len(got) > 0 {
			outcomes = append(outcomes, got...)
			if err != nil {
				incomplete = append(incomplete, err)
			}
			continue
		}
		if err != nil {
			// Nothing came back at all: everything this envelope carried is unknown,
			// which is not the same as failed.
			outcomes = append(outcomes, unansweredOutcomes(p.ItemIDs, i)...)
			incomplete = append(incomplete, err)
			continue
		}
	}
	if len(incomplete) > 0 {
		// Joined rather than first-wins: with several envelopes in flight, which one
		// failed is part of the answer, and a caller reading only the first would
		// under-report.
		return outcomes, errors.Join(incomplete...)
	}
	return outcomes, nil
}

// sendOne publishes one envelope and waits for its reply.
func (s *BatchSession) sendOne(ctx context.Context, p packedEnvelope, index int) ([]ItemOutcome, error) {
	limits := s.Limits()
	inbox := s.Inbox()
	if inbox == "" {
		return nil, fmt.Errorf("nipcash/client: session has no announced inbox")
	}

	plaintext, err := p.Envelope.Encode(limits)
	if err != nil {
		return nil, fmt.Errorf("encode envelope %d: %w", index, err)
	}
	request, conversationKey, err := transport.WrapRequest(plaintext, inbox)
	if err != nil {
		return nil, fmt.Errorf("wrap envelope %d: %w", index, err)
	}

	// The conversation key comes back from WrapRequest because it cannot be recovered
	// any other way: it is ECDH(ephemeral_priv, inbox_pub), and the ephemeral private
	// key is discarded inside WrapRequest so it can never be reused. The hub derives
	// the same key from its own inbox key and this event's author.
	replyKey, err := transport.DeriveReplyKey(conversationKey, p.Envelope.ReplyTo)
	if err != nil {
		return nil, fmt.Errorf("reply key for envelope %d: %w", index, err)
	}

	replies, stop, err := s.subscribeAndPublish(ctx, p.Envelope.ReplyTo, request)
	if err != nil {
		return nil, fmt.Errorf("send envelope %d: %w", index, err)
	}
	defer stop()

	return s.collectReply(ctx, replies, replyKey, p, index)
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

	for {
		select {
		case ev, ok := <-replies:
			if !ok {
				// The relay closed on us: the same fact as a timeout. Some chunks may
				// have arrived and the rest never will.
				return finish(errors.New("reply channel closed"))
			}
			// The same event from two relays is one chunk, not a repeat (NIP-CASH
			// §Chunked Replies). An event without an id is keyed by its content, so a
			// copy is still recognised as one.
			key := ev.ID
			if key == "" {
				key = "content:" + ev.Content
			}
			if _, dup := seenEvents[key]; dup {
				continue
			}
			seenEvents[key] = struct{}{}
			plaintext, err := nip44.Decrypt(ev.Content, replyKey[:])
			if err != nil {
				// Addressed to us but not written by the hub. The p-tag addresses a
				// response; it does not authenticate one. Only the derived key proves
				// authorship (the author is never checked, §The Reply Key), so this is
				// discarded and the real reply may still arrive.
				continue
			}
			chunk, err := transport.DecodeResponseChunk([]byte(plaintext), p.Envelope.Nonce, p.ItemIDs, maxBytes)
			if err != nil {
				// Unusable as a whole (bad JSON, another request's nonce, oversized):
				// it decides nothing. The chunk it should have been stays missing, so
				// the reply cannot complete without it, and the reason is reported.
				state.decodeErrs = append(state.decodeErrs, fmt.Errorf("decode reply chunk: %w", err))
				continue
			}
			state.add(key, chunk)
			if state.complete() {
				return state.outcomes(index)
			}

		case <-ctx.Done():
			return finish(ctx.Err())
		}
	}
}

// subscriptionAckWait bounds how long a send waits for the relay to acknowledge
// the reply subscription before publishing anyway.
const subscriptionAckWait = 2 * time.Second

// subscribeAndPublish sends one request and returns the stream its reply will arrive on.
//
// The reply is published on the relay the request arrived on (NIP-CASH §Addressing the
// Response), so the request goes to the relay this client is listening on, never to
// another. Relays are tried in order (§Multiple Relay Hints): subscribe there, then
// publish there, and the first relay that accepts the request is the one it went to.
//
// Subscribe BEFORE publishing. A hub may answer immediately, and a subscription opened
// afterwards can miss an ephemeral event entirely — relays are not required to store
// kind 23191, and this transport specifically does not want them to.
//
// A relay whose publish failed keeps its subscription. A publish that timed out may
// still have reached the hub, whose reply then lands there; a client that sent to
// several relays listens on all of them. The returned stream merges every one and
// closes once all of them have.
func (s *BatchSession) subscribeAndPublish(ctx context.Context, replyTo string, request *nip01.Event) (<-chan *nip01.Event, func(), error) {
	relays := s.Relays()
	if len(relays) == 0 {
		return nil, nil, errors.New("nipcash/client: session has no relays")
	}

	var (
		streams  []<-chan *nip01.Event
		stops    []func()
		failures []error
	)
	stopAll := func() {
		for _, stop := range stops {
			stop()
		}
	}
	for _, raw := range relays {
		relayURL, err := url.Parse(raw)
		if err != nil {
			failures = append(failures, fmt.Errorf("relay %q: %w", raw, err))
			continue
		}
		events, ready, stop, err := subscribeReplies(ctx, relayURL, replyTo)
		if err != nil {
			failures = append(failures, fmt.Errorf("relay %q: %w", raw, err))
			continue
		}
		streams, stops = append(streams, events), append(stops, stop)
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
		ok, err := relayclient.PublishEventToRelay(ctx, relayURL, request)
		if err == nil && !ok.Accepted {
			// A refusal comes back as an OK, not an error: the request is not on this
			// relay, and waiting here for a reply would only run out not_after.
			err = fmt.Errorf("refused: %s", ok.Message)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("relay %q: %w", raw, err))
			continue
		}
		return mergeEvents(ctx, streams), stopAll, nil
	}
	stopAll()
	// Every relay's failure is kept, not just the last: with failover the useful
	// question is why all of them failed (NIP-CASH §Multiple Relay Hints).
	return nil, nil, fmt.Errorf("nipcash/client: no relay took the request: %w", errors.Join(failures...))
}

// mergeEvents forwards every stream into one, closed once all of them are.
func mergeEvents(ctx context.Context, streams []<-chan *nip01.Event) <-chan *nip01.Event {
	if len(streams) == 1 {
		return streams[0]
	}
	out := make(chan *nip01.Event, 8)
	var wg sync.WaitGroup
	for _, in := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ev := range in {
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
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

// isStalePolicy reports whether a failure suggests the cached announcement is out of
// date, rather than something a refetch cannot help with.
//
// Deliberately narrow. Refetching on any failure would turn every transient relay
// problem into an extra round trip, and would mask a caller's own mistakes as hub churn.
func isStalePolicy(err error) bool {
	return errors.Is(err, transport.ErrEnvelopeTooLarge) ||
		errors.Is(err, transport.ErrTooManyItems) ||
		errors.Is(err, transport.ErrVerifyBudgetExceeded)
}
