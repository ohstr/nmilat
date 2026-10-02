package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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
// Comfortably inside transport.MaxNotAfterWindow, which bounds how far ahead a hub will
// accept — a hub need only remember a nonce until the envelope carrying it can no longer
// be accepted, so asking for the maximum would make a hub remember more for no gain.
const defaultNotAfterWindow = 60 * time.Second

// sendBatch packs builders into envelopes, publishes each, and joins every reply back to
// the items that asked.
//
// One outcome per requested item, always, whatever happened. An envelope that could not
// be published, or got no reply, yields NotServed for everything it carried — the same
// state a per-item omission produces, because from those bills' point of view it is the
// same fact: nothing is known. The Envelope field on each outcome is what lets a caller
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
			outcomes = append(outcomes, notServedOutcomes(p.ItemIDs, i)...)
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

	// Subscribe BEFORE publishing. A hub may answer immediately, and a subscription
	// opened afterwards can miss an ephemeral event entirely — relays are not required
	// to store kind 23191, and this transport specifically does not want them to.
	replies, stop, err := s.subscribeReplies(ctx, p.Envelope.ReplyTo)
	if err != nil {
		return nil, fmt.Errorf("subscribe for envelope %d: %w", index, err)
	}
	defer stop()

	if err := s.publish(ctx, request); err != nil {
		return nil, fmt.Errorf("publish envelope %d: %w", index, err)
	}

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
func (s *BatchSession) collectReply(
	ctx context.Context,
	replies <-chan *nip01.Event,
	replyKey [32]byte,
	p packedEnvelope,
	index int,
) ([]ItemOutcome, error) {
	merged := &transport.ResponseEnvelope{Version: transport.EnvelopeVersion, ReqNonce: p.Envelope.Nonce}
	seen := map[int]struct{}{}
	answered := map[string]struct{}{}
	total := 0

	// Bound the wait by the envelope's OWN not_after, which was already computed and
	// signed before it was sent.
	//
	// Without this the only exits were completion, the relay closing, a fatal decode,
	// and the caller's context — so a hub declaring total: 2 and sending one chunk left
	// a client waiting for the caller's full deadline on a reply that will never come,
	// even when the envelope it is a reply TO expired minutes ago. A hub cannot be
	// trusted to bound a client's wait, and the client already knows the answer: past
	// not_after the hub is contractually done with this envelope, so nothing further is
	// coming.
	//
	// Derived from the envelope rather than a constant, because it is the same value
	// both sides already agreed on, and a caller who set a shorter deadline still wins —
	// this only ever tightens.
	if p.Envelope.NotAfter > 0 {
		deadline := time.Unix(p.Envelope.NotAfter, 0)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	for {
		select {
		case ev, ok := <-replies:
			if !ok {
				// The relay closed on us. Treated exactly like a timeout rather than as
				// a distinct failure, because it is the same fact: some chunks arrived
				// and the rest never will.
				//
				// This path used to discard the partial results and report no error at
				// all, which made a dropped connection indistinguishable from a hub
				// omitting every item — the worst possible confusion, since an omission
				// is final and this is not.
				if total > 0 && len(seen) > 0 {
					return joinOutcomes(p.ItemIDs, merged, index),
						fmt.Errorf("%w: envelope %d: got %d of %d chunks before the relay closed",
							ErrIncompleteReply, index, len(seen), total)
				}
				return nil, fmt.Errorf("reply channel closed for envelope %d", index)
			}
			plaintext, err := nip44.Decrypt(ev.Content, replyKey[:])
			if err != nil {
				// Addressed to us but not written by the hub. The p-tag addresses a
				// response; it does not authenticate one, since anyone can publish an
				// event carrying a tag they observed. Only the derived key proves
				// authorship — so this is discarded rather than fatal, and the real
				// reply may still arrive.
				continue
			}
			chunk, err := transport.DecodeResponse([]byte(plaintext), p.Envelope.Nonce, p.ItemIDs, s.Limits())
			if err != nil {
				return nil, fmt.Errorf("decode reply for envelope %d: %w", index, err)
			}

			if total == 0 {
				total = chunk.Total
			} else if chunk.Total != total {
				// Chunks disagreeing about the total cannot be one reply, and picking
				// either would mean guessing when to stop.
				return nil, fmt.Errorf("%w: envelope %d: chunk claims %d chunks, an earlier one claimed %d",
					transport.ErrResponseMalformed, index, chunk.Total, total)
			}
			if _, dup := seen[chunk.Seq]; dup {
				return nil, fmt.Errorf("%w: envelope %d: repeated chunk %d",
					transport.ErrResponseMalformed, index, chunk.Seq)
			}
			seen[chunk.Seq] = struct{}{}

			if chunk.Error != nil && merged.Error == nil {
				merged.Error = chunk.Error
			}
			// Refuse a second answer for an id already answered, rather than letting the
			// later one overwrite the earlier.
			//
			// A duplicate id WITHIN one chunk is already rejected, but across chunks the
			// results were appended blind and the outcome map is last-wins — so two
			// contradictory statements about the same bill were resolved by ARRIVAL
			// ORDER. Only the hub can produce them (it holds the reply key), but a relay
			// holding no key at all decides which one the client believes, simply by
			// reordering two events: NOT_FOUND becomes a live million-millis bill, or the
			// reverse.
			//
			// Sorting by seq would make the outcome deterministic and still let the hub
			// choose it by construction. Refusing is the answer that leaves no room for
			// either party to pick: a hub that answers one item twice with different
			// content has contradicted itself, and there is no reading of that reply a
			// client should act on.
			for _, r := range chunk.Results {
				if _, already := answered[r.ID]; already {
					return nil, fmt.Errorf("%w: envelope %d: item %q answered in more than one chunk",
						transport.ErrResponseMalformed, index, r.ID)
				}
				answered[r.ID] = struct{}{}
			}
			merged.Results = append(merged.Results, chunk.Results...)

			if len(seen) == total {
				return joinOutcomes(p.ItemIDs, merged, index), nil
			}

		case <-ctx.Done():
			if total > 0 && len(seen) > 0 {
				// Partial: return what did arrive rather than discarding it, but say
				// plainly that the picture is incomplete. Items in the missing chunks
				// come back NotServed, which is honest — we do not know — while the
				// error tells the caller that is ignorance rather than the hub's answer.
				return joinOutcomes(p.ItemIDs, merged, index),
					fmt.Errorf("%w: envelope %d: got %d of %d chunks", ErrIncompleteReply, index, len(seen), total)
			}
			return nil, ctx.Err()
		}
	}
}

// subscribeReplies opens a subscription for one envelope's response.
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
func (s *BatchSession) subscribeReplies(ctx context.Context, replyTo string) (<-chan *nip01.Event, func(), error) {
	relays := s.Relays()
	if len(relays) == 0 {
		return nil, nil, errors.New("nipcash/client: session has no relays")
	}

	filter := nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{transport.KindPrivateResponse},
		Tags:  map[string][]string{"p": {replyTo}},
	})

	var lastErr error
	for _, raw := range relays {
		relayURL, err := url.Parse(raw)
		if err != nil {
			lastErr = err
			continue
		}
		conn, err := relayclient.Connect(ctx, relayURL)
		if err != nil {
			lastErr = err
			continue
		}

		subID := uuid.NewString()
		if !conn.SubscribeWithID(subID, filter) {
			conn.Close()
			lastErr = errors.New("connection closed before the subscription could be sent")
			continue
		}

		// Buffered and forwarding EVERY event, not just the first: a hub may answer one
		// request with several chunks (NIP-CASH §Chunked Replies), so stopping at the
		// first would strand the rest and the caller would read them as omissions.
		out := make(chan *nip01.Event, 8)
		go func() {
			defer close(out)
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
					case *wire.ClosedSubscriptionResponse:
						// The relay ended it; nothing more will arrive. EOSE is
						// deliberately NOT handled here — it only marks the end of
						// stored events, and every reply comes after it.
						if m.SubscriptionID == subID {
							return
						}
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		return out, func() { conn.Close() }, nil
	}
	return nil, nil, fmt.Errorf("nipcash/client: no relay reachable: %w", lastErr)
}

// publish sends the request to the first relay that accepts it.
//
// First-wins rather than all-of-them: a hub reads one inbox and a duplicate arriving by
// another path is refused as a replayed nonce, so publishing everywhere would spend
// bandwidth to manufacture rejections.
func (s *BatchSession) publish(ctx context.Context, ev *nip01.Event) error {
	relays := s.Relays()
	var lastErr error
	for _, raw := range relays {
		relayURL, err := url.Parse(raw)
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := relayclient.PublishEventToRelay(ctx, relayURL, ev); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no relays")
	}
	return lastErr
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
