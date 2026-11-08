package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip98"
	"github.com/ohstr/nmilat/relay/ratelimit"
)

// MaxQueryBodyBytes caps a POST /query request body. A client sends a
// small array of filters, so anything larger is a mistake or an attack.
const MaxQueryBodyBytes = 1 << 20

// NewQueryHandler returns an http.Handler serving POST /query: a NIP-98-
// authenticated HTTP bridge that is a one-shot alternative to a WebSocket
// REQ/EOSE round trip. The request body is a JSON array of plain NIP-01
// filters; the response is a flat JSON array of the matching stored
// events (empty if none match) -- the same filter-matching semantics as
// REQ, just over HTTP instead of a socket, with no subscription/live
// behavior.
//
// This serves the baseline, non-windowed case of the NIP-CW HTTP query
// bridge -- a different spec from this module's unrelated nipcw package
// (NIP-CASH's Circle Wallet), which merely happens to share the short name. NIP-CW's
// optional windowing/cursor extension fields are not implemented; only
// the base NIP-01 filter fields are read (kinds, authors, ids,
// since/until, limit, single-letter tag filters).
//
// NIP-98 proves the caller's identity and binds the request the way it
// would for any HTTP endpoint; it is not an authorization gate on its
// own. But NIP-CW's own Access Scoping section is explicit that a query
// surface MUST apply "the relay's ordinary access-scoped result for that
// surface... exactly as any other filter against an inaccessible channel
// produces" -- a plain filter through this endpoint is not exempt from
// whatever access control an equivalent REQ would get. On this relay that
// is the NIP-43 MembershipRequired gate (processRequest's connection-level
// check, mirrored here per authenticated pubkey since there is no
// connection to hold state on): limitation and membership, if given,
// reject a non-member exactly as a REQ would, rather than silently
// serving everyone who can produce a valid signature. AuthRequired has no
// separate equivalent here -- a NIP-98 signature is already mandatory for
// every request to this endpoint, required or not.
func NewQueryHandler(store *EventStore, limitation *nip11.Limitation, membership *MembershipService, groups *GroupsService) http.Handler {
	return &queryHandler{store: store, limitation: limitation, membership: membership, groups: groups}
}

type queryHandler struct {
	store      *EventStore
	limitation *nip11.Limitation
	membership *MembershipService
	// groups applies the same NIP-29 visibility REQ does, for the signer.
	groups *GroupsService
	// recipientOnly, when set, withholds its RecipientOnlyKinds from all
	// but their recipient, the signer standing in for the AUTHed pubkey.
	recipientOnly *SessionConfig
	// count answers POST /count ({"count": n}) instead of the events.
	count bool
	// presence, when set, answers presence snapshot queries.
	presence *presenceSnapshot
	// limiter, when set, counts each request against ratelimit.HTTP.
	limiter *ratelimit.Limiter
}

// NewCountHandler is NewQueryHandler for POST /count (NIP-45): the same
// request and checks, answered with {"count": n}, plus "approximate": true
// when the count is a lower bound.
func NewCountHandler(store *EventStore, limitation *nip11.Limitation, membership *MembershipService, groups *GroupsService) http.Handler {
	return &queryHandler{store: store, limitation: limitation, membership: membership, groups: groups, count: true}
}

func (h *queryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reader, filters, ok := h.admit(w, r)
	if !ok {
		return
	}
	if h.count {
		h.serveCount(w, r, reader, filters)
		return
	}
	if authors, ok := h.presence.asks(filters); ok {
		h.presence.serve(w, authors)
		return
	}

	checkRecipient := h.recipientOnly.mayMatchRecipientOnlyKind(filters...)

	// Filters are OR'd together per NIP-01: an event matching more than one
	// of them is still delivered once.
	seen := make(map[uint64]bool)
	var matched [][]byte

	for _, filter := range filters {
		potEvents, err := h.store.FindEvents(r.Context(), filter)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		for _, pe := range potEvents {
			if seen[pe.Evsid] || h.groups.deniedPrivateGroupPotentialEvent(reader, pe) ||
				(checkRecipient && h.recipientOnly.deniedRecipientOnlyPotentialEvent(reader, pe)) {
				continue
			}
			seen[pe.Evsid] = true
			matched = append(matched, pe.Bytes)
		}
	}

	w.Header().Set("Content-Type", "application/json")

	// Built manually, like wire.EventSubscriptionResponse, to splice in each
	// event's already-marshaled bytes rather than unmarshal-then-remarshal
	// every one of them.
	var b strings.Builder
	b.WriteByte('[')
	for i, raw := range matched {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(raw)
	}
	b.WriteByte(']')
	_, _ = w.Write([]byte(b.String()))
}

// admit runs every check a request passes before its filters are read:
// method, body size, NIP-98, NIP-43 membership and NIP-29 group filters.
// On failure it has already written the response.
func (h *queryHandler) admit(w http.ResponseWriter, r *http.Request) (pubkeyReader, []*nip01.SubscriptionFilter, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return pubkeyReader{}, nil, false
	}
	if wait, ok := h.limiter.Allow(ratelimit.HTTP, h.limiter.ClientIP(r), ""); !ok {
		ratelimit.Refuse(w, ratelimit.HTTP, wait)
		return pubkeyReader{}, nil, false
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxQueryBodyBytes+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return pubkeyReader{}, nil, false
	}
	if len(body) > MaxQueryBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return pubkeyReader{}, nil, false
	}

	pubkey, err := nip98.VerifyAnyPubkey(r, nip98.Options{Body: body, NormalizeRootPath: true})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return pubkeyReader{}, nil, false
	}
	if wait, ok := h.limiter.Allow(ratelimit.HTTP, "", pubkey); !ok {
		ratelimit.Refuse(w, ratelimit.HTTP, wait)
		return pubkeyReader{}, nil, false
	}

	// Same gate as processRequest's REQ/COUNT check: NIP-43's "if at least
	// one authenticated pubkey ... holds active or virtual membership" has
	// no connection to hold multiple identities on here, so the NIP-98
	// signer is the one pubkey being asked about. No membership service
	// configured fails closed, same as nip86's empty-AllowedPubkeys
	// posture: an operator who turned MembershipRequired on without
	// wiring membership through to this handler gets a closed endpoint,
	// not an accidentally open one.
	if h.limitation != nil && h.limitation.MembershipRequired {
		if h.membership == nil || !h.membership.IsMember(pubkey) {
			http.Error(w, "restricted: valid NIP-43 membership required", http.StatusForbidden)
			return pubkeyReader{}, nil, false
		}
	}

	var filters []*nip01.SubscriptionFilter
	if err := json.Unmarshal(body, &filters); err != nil {
		http.Error(w, "body must be a JSON array of NIP-01 filters", http.StatusBadRequest)
		return pubkeyReader{}, nil, false
	}

	// NIP-29: the same visibility REQ applies, for the NIP-98 signer -- a
	// filter naming a group it can't see is refused, and anything else a
	// private group holds is withheld per event.
	reader := pubkeyReader{pubkey}
	if groupID, denied := h.groups.deniedPrivateGroupFilter(reader, nip01.NewSubscriptionFilterGroup(filters...)); denied {
		http.Error(w, "restricted: valid membership in group "+groupID+" is required", http.StatusForbidden)
		return pubkeyReader{}, nil, false
	}
	return reader, filters, true
}

// serveCount answers POST /count (NIP-45) the way processCount answers a
// COUNT: only events the signer could read are counted, and a scan that
// stops at its limit is reported as approximate.
func (h *queryHandler) serveCount(w http.ResponseWriter, r *http.Request, reader pubkeyReader, filters []*nip01.SubscriptionFilter) {
	group := nip01.NewSubscriptionFilterGroup(filters...)
	checkGroups := h.groups.needsPrivacyCheck(group)
	checkRecipient := h.recipientOnly.mayMatchRecipientOnlyKind(filters...)

	var count int64
	var approx bool
	var err error
	if checkGroups || checkRecipient {
		count, approx, err = h.store.CountEventsApprox(r.Context(), group, func(pe *PotentialEvent) bool {
			return (checkGroups && h.groups.deniedPrivateGroupPotentialEvent(reader, pe)) ||
				(checkRecipient && h.recipientOnly.deniedRecipientOnlyPotentialEvent(reader, pe))
		})
	} else if n, ok := h.store.CountFromCounters(group); ok {
		count = n
	} else {
		count, approx, err = h.store.CountEventsApprox(r.Context(), group, nil)
	}
	if err != nil {
		http.Error(w, "count failed", http.StatusInternalServerError)
		return
	}

	resp := struct {
		Count       int64 `json:"count"`
		Approximate bool  `json:"approximate,omitempty"`
	}{count, approx}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
