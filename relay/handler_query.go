package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip98"
)

// MaxQueryBodyBytes caps a POST /query request body. A buzz-relay client
// sends a small array of filters, so anything larger is a mistake or an
// attack.
const MaxQueryBodyBytes = 1 << 20

// NewQueryHandler returns an http.Handler serving POST /query: a NIP-98-
// authenticated HTTP bridge that is a one-shot alternative to a WebSocket
// REQ/EOSE round trip. The request body is a JSON array of plain NIP-01
// filters; the response is a flat JSON array of the matching stored
// events (empty if none match) -- the same filter-matching semantics as
// REQ, just over HTTP instead of a socket, with no subscription/live
// behavior.
//
// This serves the baseline, non-windowed case of buzz's own NIP-CW
// (https://github.com/block/buzz/blob/main/docs/nips/NIP-CW.md) -- a
// different spec from this module's unrelated nipcw package (NIP-CASH's
// Circle Wallet), which merely happens to share the short name. NIP-CW's
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
func NewQueryHandler(store *EventStore, limitation *nip11.Limitation, membership *MembershipService) http.Handler {
	return &queryHandler{store: store, limitation: limitation, membership: membership}
}

type queryHandler struct {
	store      *EventStore
	limitation *nip11.Limitation
	membership *MembershipService
}

func (h *queryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxQueryBodyBytes+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > MaxQueryBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	pubkey, err := nip98.VerifyAnyPubkey(r, nip98.Options{Body: body, NormalizeRootPath: true})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
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
			return
		}
	}

	var filters []*nip01.SubscriptionFilter
	if err := json.Unmarshal(body, &filters); err != nil {
		http.Error(w, "body must be a JSON array of NIP-01 filters", http.StatusBadRequest)
		return
	}

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
			if seen[pe.Evsid] {
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
