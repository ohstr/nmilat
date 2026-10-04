package relay

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/nip98"
)

// MaxEventsBodyBytes caps a POST /events request body. A single signed
// event is typically well under this; anything larger is a mistake or an
// attack.
const MaxEventsBodyBytes = 1 << 20

// NewEventsHandler returns an http.Handler serving POST /events: a NIP-98-
// authenticated HTTP bridge for submitting one already-signed event, the
// write-side counterpart to NewQueryHandler's POST /query. A buzz-relay
// client (and the buzz CLI buzz-acp drives) uses this instead of opening a
// WebSocket connection purely to publish -- e.g. reactions, NIP-AM turn
// metrics, and chat replies.
//
// The request body is a single signed NIP-01 event object (not an array --
// buzz-acp submits one event per call). The response is {"event_id":"...",
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
//     caller (the buzz CLI, buzz-acp itself) already signs the NIP-98
//     wrapper and the event with the same key, so this costs nothing in
//     practice.
//   - NIP-AA virtual membership is not evaluated: only a direct NIP-43
//     member (or the relay's own key, for relay-authored kinds) may publish
//     here. The NIP-98 signer has proven their own identity, not a
//     delegated credential, and there is no connection to have offered one
//     at AUTH time the way NIP-AA requires. Matches NewQueryHandler's own
//     documented membership-check scope.
//   - NIP-43 join/leave requests (kind 9021/9022) are rejected outright:
//     MembershipService.HandleEvent is wired to a live *Session for its
//     reply/broadcast side effects, which an HTTP POST has none of. Use the
//     relay's membership management API (ncli relay members) instead.
func NewEventsHandler(store *EventStore, limitation *nip11.Limitation, membership *MembershipService, selfPubkey string) http.Handler {
	return &eventsHandler{store: store, limitation: limitation, membership: membership, selfPubkey: selfPubkey}
}

type eventsHandler struct {
	store      *EventStore
	limitation *nip11.Limitation
	membership *MembershipService
	selfPubkey string
}

func (h *eventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

	if ok, msg := CheckSelfAuthored(&ev, h.selfPubkey); !ok {
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

	if err := runEventValidators(r.Context(), &ev); err != nil {
		http.Error(w, "invalid: "+err.Error(), http.StatusBadRequest)
		return
	}

	if h.limitation != nil && h.limitation.MembershipRequired && !nip43.IsRelayAuthoredKind(ev.Kind) {
		if h.membership == nil || !h.membership.IsMember(ev.PubKey) {
			http.Error(w, "restricted: valid NIP-43 membership required", http.StatusForbidden)
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
