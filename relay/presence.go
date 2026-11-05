package relay

import (
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// KindPresence is a client's own ephemeral presence status ("online",
// "away", ...), and the kind of the relay-signed answers to a presence
// snapshot query.
const KindPresence = 20001

// DefaultPresenceQueryKind is the kind existing clients ask presence
// snapshots by. No NIP fixes it.
const DefaultPresenceQueryKind = 40902

// MaxPresenceAuthors caps the pubkeys one presence snapshot query asks about.
const MaxPresenceAuthors = 500

// WithPresenceQueryKind sets SessionConfig.PresenceQueryKind: POST /query
// (SessionHandler.QueryHandler) answers a filter {"kinds":[kind],"authors":
// [...]} with one relay-signed KindPresence event per author -- content
// "online" while it has a connection authenticated here (or the status its
// latest KindPresence on such a connection gave), else "offline" -- built on
// the spot and never stored. 0 turns it off. List kind in
// RelayAuthoredKinds too, so no client publishes one.
func WithPresenceQueryKind(kind int) SessionOption {
	return func(cfg *SessionConfig) { cfg.PresenceQueryKind = kind }
}

// presenceStatuses holds the latest KindPresence status each connected
// pubkey published.
type presenceStatuses struct {
	mu     sync.Mutex
	status map[string]string
}

func (p *presenceStatuses) set(pubkey, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status == nil {
		p.status = make(map[string]string)
	}
	p.status[pubkey] = status
}

func (p *presenceStatuses) get(pubkey string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status[pubkey]
}

func (p *presenceStatuses) clear(pubkey string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.status, pubkey)
}

// recordPresence keeps ev's status when presence snapshots are on and ev is
// a KindPresence its author published on this connection.
func (s *Session) recordPresence(ev *nip01.Event) {
	if s.config.PresenceQueryKind == 0 || ev.Kind != KindPresence || s.presence == nil {
		return
	}
	if _, authed := s.IdentityMembership(ev.PubKey); authed {
		s.presence.set(ev.PubKey, ev.Content)
	}
}

// online reports whether a connection here is authenticated as pubkey.
func (sh *SessionHandler) online(pubkey string) bool {
	found := false
	sh.sessions.Range(func(_, v any) bool {
		if slices.Contains(v.(*Session).readerPubkeys(), pubkey) {
			found = true
			return false
		}
		return true
	})
	return found
}

// PresenceStatus is pubkey's presence: the status its latest KindPresence
// gave while connected ("online" if none, or if it was empty), or
// "offline" when no connection here is authenticated as it.
func (sh *SessionHandler) PresenceStatus(pubkey string) string {
	if !sh.online(pubkey) {
		return "offline"
	}
	if status := sh.presence.get(pubkey); status != "" {
		return status
	}
	return "online"
}

// forgetPresence drops the statuses of s's pubkeys that have no other
// connection left.
func (sh *SessionHandler) forgetPresence(s *Session) {
	for _, pk := range s.readerPubkeys() {
		if !sh.online(pk) {
			sh.presence.clear(pk)
		}
	}
}

// presenceSnapshot answers presence queries for queryHandler.
type presenceSnapshot struct {
	kind    int
	status  func(pubkey string) string
	privKey string
}

// asks reports whether filters are exactly one presence snapshot query,
// returning its authors.
func (p *presenceSnapshot) asks(filters []*nip01.SubscriptionFilter) ([]string, bool) {
	if p == nil || p.kind == 0 || len(filters) != 1 {
		return nil, false
	}
	f := filters[0]
	if len(f.Kinds) != 1 || f.Kinds[0] != p.kind || len(f.Authors) == 0 {
		return nil, false
	}
	return f.Authors, true
}

// serve writes one relay-signed KindPresence per distinct author.
func (p *presenceSnapshot) serve(w http.ResponseWriter, authors []string) {
	if p.privKey == "" {
		http.Error(w, "error: presence needs the relay's private key", http.StatusInternalServerError)
		return
	}
	seen := make(map[string]bool, len(authors))
	var out []*nip01.Event
	now := uint64(time.Now().Unix())
	for _, a := range authors {
		if seen[a] {
			continue
		}
		seen[a] = true
		if len(seen) > MaxPresenceAuthors {
			http.Error(w, "invalid: too many authors in one presence query", http.StatusBadRequest)
			return
		}
		if _, ok := decodePubkey(a); !ok {
			http.Error(w, "invalid: authors must be 64-character hex pubkeys", http.StatusBadRequest)
			return
		}
		ev := &nip01.Event{
			CreatedAt: now,
			Kind:      KindPresence,
			Tags:      [][]string{{"p", a}},
			Content:   p.status(a),
		}
		if err := ev.Sign(p.privKey); err != nil {
			http.Error(w, "error: could not sign presence", http.StatusInternalServerError)
			return
		}
		out = append(out, ev)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
