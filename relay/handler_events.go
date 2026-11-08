package relay

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/nip98"
	"github.com/ohstr/nmilat/relay/ratelimit"
)

// MaxEventsBodyBytes caps a POST /events request body. A single signed
// event is typically well under this; anything larger is a mistake or an
// attack.
const MaxEventsBodyBytes = 1 << 20

// NewEventsHandler returns an http.Handler serving POST /events: a NIP-98-
// authenticated HTTP bridge for submitting one already-signed event, the
// write-side counterpart to NewQueryHandler's POST /query. An HTTP-bridge
// client (an agent bridge and its CLI) uses this instead of opening a
// WebSocket connection purely to publish -- e.g. reactions, NIP-AM turn
// metrics, and chat replies.
//
// The request body is a single signed NIP-01 event object (not an array --
// clients submit one event per call). The response is {"event_id":"...",
// "accepted":true} on success.
//
// Mirrors processEvent's admission pipeline (session.go) as faithfully as a
// connectionless HTTP request allows, with deliberate narrowing in two
// places:
//
//   - The NIP-98 signer must equal the submitted event's own pubkey. Over
//     WS, a connection could in principle relay a different pubkey's
//     pre-signed, non-protected, non-membership-gated event; this handler
//     never allows that, since it would otherwise be straightforward abuse
//     with no connection-level participation to anchor it. Every real
//     caller already signs the NIP-98
//     wrapper and the event with the same key, so this costs nothing in
//     practice.
//   - NIP-AA virtual membership is not evaluated: only a direct NIP-43
//     member (or the relay's own key, for relay-authored kinds) may publish
//     here. The NIP-98 signer has proven their own identity, not a
//     delegated credential, and there is no connection to have offered one
//     at AUTH time the way NIP-AA requires. Matches NewQueryHandler's own
//     documented membership-check scope.
//   - NIP-43 join/leave requests (kind 28934/28936) are rejected outright:
//     MembershipService.HandleEvent is wired to a live *Session for its
//     reply/broadcast side effects, which an HTTP POST has none of. Use the
//     relay's membership management API (ncli relay members) instead.
//   - NIP-29 moderation events and group requests (kinds 9000-9022) are
//     rejected outright for the same reason: over the WebSocket they are
//     commands GroupsService applies, never stored as sent. Send them over
//     a WebSocket. Group content goes through the same members-only write
//     gate as over the WebSocket when the handler has the relay's groups
//     (WithEventsGroups).
func NewEventsHandler(store *EventStore, limitation *nip11.Limitation, membership *MembershipService, selfPubkey string, opts ...EventsHandlerOption) http.Handler {
	h := &eventsHandler{store: store, limitation: limitation, membership: membership, selfPubkey: selfPubkey}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// EventsHandlerOption configures NewEventsHandler.
type EventsHandlerOption func(*eventsHandler)

// WithEventsPolicy applies policy to every event POSTed to /events, the same
// as SessionConfig.EventPolicy does over the WebSocket. A refusal is a 403
// carrying the policy's message.
func WithEventsPolicy(policy EventPolicy) EventsHandlerOption {
	return func(h *eventsHandler) { h.policy = policy }
}

// WithEventsRelayAuthoredKinds refuses these kinds unless the relay's own
// key signed them, as SessionConfig.RelayAuthoredKinds does over the
// WebSocket.
func WithEventsRelayAuthoredKinds(kinds ...int) EventsHandlerOption {
	return func(h *eventsHandler) { h.relayAuthored = append([]int(nil), kinds...) }
}

// WithEventsRateLimiter counts every POST /events against l's HTTP limits
// (client IP, then NIP-98 signer) and the event against its Event limits:
// the client IP's, and, for an event the relay does not already have, the
// author's, so an author's writes share one budget with the WebSocket. A
// refusal is a 429 with Retry-After.
func WithEventsRateLimiter(l *ratelimit.Limiter) EventsHandlerOption {
	return func(h *eventsHandler) { h.limiter = l }
}

// WithEventsGroups gives the handler the relay's hosted NIP-29 groups
// (SessionHandler.Groups), so an event tagged into a private, closed or
// restricted group is refused unless its author is a member, as over the
// WebSocket. A relay hosting groups should always pass it.
func WithEventsGroups(g *GroupsService) EventsHandlerOption {
	return func(h *eventsHandler) { h.groups = g }
}

type eventsHandler struct {
	groups        *GroupsService
	limiter       *ratelimit.Limiter
	store         *EventStore
	limitation    *nip11.Limitation
	membership    *MembershipService
	selfPubkey    string
	policy        EventPolicy
	relayAuthored []int
}

func (h *eventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := h.limiter.ClientIP(r)
	if wait, ok := h.limiter.Allow(ratelimit.HTTP, ip, ""); !ok {
		ratelimit.Refuse(w, ratelimit.HTTP, wait)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxEventsBodyBytes+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > MaxEventsBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	signerPubkey, err := nip98.VerifyAnyPubkey(r, nip98.Options{Body: body, NormalizeRootPath: true})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if wait, ok := h.limiter.Allow(ratelimit.HTTP, "", signerPubkey); !ok {
		ratelimit.Refuse(w, ratelimit.HTTP, wait)
		return
	}

	var ev nip01.Event
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "body must be a single signed NIP-01 event object", http.StatusBadRequest)
		return
	}

	// See doc comment: the NIP-98 signer must be the event's own author.
	// This also subsumes NIP-70's protected-event check (processEvent's
	// IdentityMembership(ev.PubKey) requirement) -- it is strictly stronger.
	if signerPubkey != ev.PubKey {
		http.Error(w, "restricted: the NIP-98 signer must match the event's own pubkey", http.StatusForbidden)
		return
	}

	if ev.Kind == nip43.KindJoinRequest || ev.Kind == nip43.KindLeaveRequest {
		http.Error(w, "restricted: join/leave requests are not accepted via /events -- use the relay's membership management API", http.StatusBadRequest)
		return
	}
	if nip29.IsModerationKind(ev.Kind) || nip29.IsUserRequestKind(ev.Kind) {
		http.Error(w, "restricted: use a WebSocket to send group moderation events and requests", http.StatusBadRequest)
		return
	}

	if ok, msg := CheckSelfAuthored(&ev, h.selfPubkey, h.relayAuthored...); !ok {
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	if err := ev.Validate(); err != nil {
		http.Error(w, "invalid: "+err.Error(), http.StatusBadRequest)
		return
	}

	var verifyOpts []nip01.VerifyOption
	if h.limitation == nil || !h.limitation.StrictPow {
		verifyOpts = append(verifyOpts, nip01.WithoutPowCheck())
	} else if h.limitation.MinPowDifficulty > 0 {
		verifyOpts = append(verifyOpts, nip01.WithMinPowDifficulty(h.limitation.MinPowDifficulty))
	}
	if err := ev.Verify(verifyOpts...); err != nil {
		var powErr *nip01.InsufficientPowError
		if errors.As(err, &powErr) {
			http.Error(w, powErr.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid: "+err.Error(), http.StatusBadRequest)
		return
	}

	// The IP's Event budget, as an EVENT over the WebSocket takes first;
	// the author's comes later, for a new event only.
	if wait, ok := h.limiter.Allow(ratelimit.Event, ip, ""); !ok {
		ratelimit.Refuse(w, ratelimit.Event, wait)
		return
	}

	if err := runEventValidators(r.Context(), &ev); err != nil {
		http.Error(w, rejectMessage(err), http.StatusBadRequest)
		return
	}

	if h.policy != nil {
		if msg := h.policy(&ev); msg != "" {
			http.Error(w, msg, http.StatusForbidden)
			return
		}
	}

	// NIP-29 content: only members post into a private, closed or
	// restricted group, as processEvent checks.
	if msg := h.groups.deniedGroupWrite(&ev); msg != "" {
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	if h.limitation != nil && h.limitation.MembershipRequired && !nip43.IsRelayAuthoredKind(ev.Kind) {
		if h.membership == nil || !h.membership.IsMember(ev.PubKey) {
			http.Error(w, "restricted: valid NIP-43 membership required", http.StatusForbidden)
			return
		}
	}

	// The author's Event budget, shared with the WebSocket. The NIP-98
	// signer is the author here, but a replay of an event the relay
	// already has costs the author nothing, as over the WebSocket.
	if h.limiter != nil && !h.store.has(ev.ID) {
		if wait, ok := h.limiter.Allow(ratelimit.Event, "", ev.PubKey); !ok {
			ratelimit.Refuse(w, ratelimit.Event, wait)
			return
		}
	}

	task := NewEventInsertTask([]*nip01.Event{&ev})
	h.store.Execute(r.Context(), task)

	w.Header().Set("Content-Type", "application/json")
	select {
	case <-task.Completed():
		_, _ = w.Write([]byte(`{"event_id":"` + ev.ID + `","accepted":true}`))
	case err := <-task.Errors():
		switch {
		case errors.Is(err, ErrEventDuplicated):
			_, _ = w.Write([]byte(`{"event_id":"` + ev.ID + `","accepted":true,"message":"duplicate: ` + err.Error() + `"}`))
		case errors.Is(err, ErrRateLimited):
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		default:
			http.Error(w, "could not store event", http.StatusInternalServerError)
		}
	case <-r.Context().Done():
		http.Error(w, "request cancelled", http.StatusRequestTimeout)
	}
}
