package niplsp

import (
	"sync"

	"github.com/ohstr/nmilat/nip01"
)

// Mark is the newest announcement seen for a node: its created_at and id.
type Mark struct {
	CreatedAt int64
	ID        string
}

// newer reports whether (createdAt, id) replaces m under NIP-01's rule for
// replaceable events: a later created_at, or the same one and a lower id.
func (m Mark) newer(createdAt int64, id string) bool {
	return createdAt > m.CreatedAt || (createdAt == m.CreatedAt && id < m.ID)
}

type seenEntry struct {
	mark Mark
	ann  *Announcement // nil when the newest failed a check
	err  error
}

// Seen remembers the newest announcement of each node, by node key, and
// whether it passed the checks. It keeps only the newest: an older version
// offered later is refused, and when the newest fails a check the node has no
// usable announcement until a newer one passes; there is no fallback (NIP-LSP
// §Client Behavior). An event whose kind or signature fails (step 1) is not
// the node's and changes nothing.
//
// Keep the marks across runs (Marks, Remember) so that a relay serving an old
// version later cannot bring it back. Seen is safe for concurrent use.
type Seen struct {
	// Options are the checks each newest announcement must pass.
	Options CheckOptions

	mu    sync.Mutex
	nodes map[string]*seenEntry
}

// NewSeen returns an empty Seen checking with o.
func NewSeen(o CheckOptions) *Seen {
	return &Seen{Options: o, nodes: map[string]*seenEntry{}}
}

// Offer takes one event. It returns the announcement when ev is now the
// node's newest and passed every check; ErrNotNewer when it is no newer than
// the newest seen (the same event again returns the stored outcome, and the
// event of a mark restored by Remember is checked and held); and the
// check's *AnnouncementError otherwise, in which case a newer-but-failing ev
// still becomes the newest and leaves the node with no usable announcement.
func (s *Seen) Offer(ev *nip01.Event) (*Announcement, error) {
	if err := checkSignature(ev); err != nil {
		return nil, err
	}
	created := int64(ev.CreatedAt) //nolint:gosec // event timestamps are seconds
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodes == nil {
		s.nodes = map[string]*seenEntry{}
	}
	e, ok := s.nodes[ev.PubKey]
	if ok && e.mark.ID == ev.ID && e.mark.CreatedAt == created && (e.ann != nil || e.err != nil) {
		return e.ann, e.err
	}
	// The remembered mark's own event (restored by Remember, never held) is
	// checked and held like a newer one.
	remembered := ok && e.mark.ID == ev.ID && e.mark.CreatedAt == created
	if ok && !remembered && !e.mark.newer(created, ev.ID) {
		return nil, ErrNotNewer
	}
	ann, err := ParseAnnouncement(ev, s.Options)
	s.nodes[ev.PubKey] = &seenEntry{mark: Mark{CreatedAt: created, ID: ev.ID}, ann: ann, err: err}
	return ann, err
}

// Current is the node's newest announcement while it passed every check and
// has not expired at Options.Now; else ErrNoUsable, wrapping why.
func (s *Seen) Current(nodeKey string) (*Announcement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current(nodeKey)
}

func (s *Seen) current(nodeKey string) (*Announcement, error) {
	e, ok := s.nodes[nodeKey]
	switch {
	case !ok, e.ann == nil && e.err == nil:
		return nil, ErrNoUsable
	case e.err != nil:
		return nil, &noUsable{e.err}
	case e.ann.Expired(s.Options.now()):
		return nil, &noUsable{stepErr(4, "expired at %d", e.ann.Expiration)}
	}
	return e.ann, nil
}

// noUsable is ErrNoUsable with its cause.
type noUsable struct{ cause error }

func (e *noUsable) Error() string   { return ErrNoUsable.Error() + ": " + e.cause.Error() }
func (e *noUsable) Is(t error) bool { return t == ErrNoUsable }
func (e *noUsable) Unwrap() error   { return e.cause }

// Marks are the newest created_at and id seen per node key, to keep across
// runs.
func (s *Seen) Marks() map[string]Mark {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Mark, len(s.nodes))
	for k, e := range s.nodes {
		out[k] = e.mark
	}
	return out
}

// Remember restores a mark kept from an earlier run: versions older than it
// are refused from now on, and the mark's own event is taken when offered. It never lowers a newer mark already held.
func (s *Seen) Remember(nodeKey string, m Mark) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodes == nil {
		s.nodes = map[string]*seenEntry{}
	}
	if e, ok := s.nodes[nodeKey]; ok && !e.mark.newer(m.CreatedAt, m.ID) {
		return
	}
	s.nodes[nodeKey] = &seenEntry{mark: m}
}

// Newest offers evs to seen in turn and returns the usable newest
// announcement of every node seen holds, by node key: nodes whose newest
// failed a check or has expired are absent, whatever older versions evs carry.
func Newest(seen *Seen, evs []*nip01.Event) map[string]*Announcement {
	for _, ev := range evs {
		_, _ = seen.Offer(ev)
	}
	seen.mu.Lock()
	defer seen.mu.Unlock()
	out := map[string]*Announcement{}
	for k := range seen.nodes {
		if a, err := seen.current(k); err == nil {
			out[k] = a
		}
	}
	return out
}
