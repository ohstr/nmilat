package listing

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/ohstr/nmilat/nip01"
)

// VersionBook keeps, per listing address, the newest version seen (remembered
// after it expires, so an older version is never taken again), the NIP-09
// deletion floor, and the tap outcomes (§Wallet Rules "Versions and expiry").
// It is safe for concurrent use; Snapshot and Restore keep it across runs.
type VersionBook struct {
	mu     sync.Mutex
	newest map[string]*Listing
	floors map[string]int64
	taps   *TapCache
}

// NewVersionBook returns an empty book.
func NewVersionBook() *VersionBook {
	return &VersionBook{newest: map[string]*Listing{}, floors: map[string]int64{}, taps: NewTapCache()}
}

// Taps is the book's tap cache: record CheckTap outcomes there so Current
// honours them.
func (b *VersionBook) Taps() *TapCache { return b.taps }

// Offer takes l as its address's newest version and reports whether it did. It
// refuses a version dated more than MaxSkewSecs after now, one at or below the
// address's deletion floor, one older than the newest seen and, on an equal
// created_at, the higher id. An expired version newer than the one held is
// remembered (so nothing older is taken again) but reported false.
func (b *VersionBook) Offer(l *Listing, now int64) bool {
	if l == nil || l.Event == nil {
		return false
	}
	ca := l.CreatedAt()
	if ca > now+MaxSkewSecs {
		return false
	}
	addr := l.Address()
	b.mu.Lock()
	defer b.mu.Unlock()
	if f, ok := b.floors[addr]; ok && ca <= f {
		return false
	}
	if cur, ok := b.newest[addr]; ok && !nip01.Supersedes(l.Event, cur.Event) {
		return false
	}
	b.newest[addr] = l
	return now <= l.ExpiresAt()
}

// ApplyDeletion applies a NIP-09 deletion: a kind 5 signed by the node identity
// of the address it names in an a tag, carrying ["k", "31190"], hides every
// version of that address up to its created_at. Anyone else's deletion, or one
// without the k tag, is ignored. It reports whether a floor rose.
func (b *VersionBook) ApplyDeletion(ev *nip01.Event) bool {
	if ev == nil || ev.Kind != kindDeletion || !hasTag(ev, "k", strconv.Itoa(KindListing)) || ev.Verify() != nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	raised := false
	for _, t := range ev.Tags {
		if len(t) < 2 || t[0] != "a" {
			continue
		}
		k, pubkey, _, ok := ParseAddress(t[1])
		if !ok || k != KindListing || pubkey != ev.PubKey {
			continue
		}
		if f, ok := b.floors[t[1]]; !ok || int64(ev.CreatedAt) > f {
			b.floors[t[1]] = int64(ev.CreatedAt)
			raised = true
		}
	}
	return raised
}

// Current is "before showing" step 5: the address's newest version while its
// status is open or paused, now is not past ExpiresAt, it is above the deletion
// floor and no tap outcome hides it.
func (b *VersionBook) Current(addr string, now int64) (*Listing, bool) {
	b.mu.Lock()
	l, ok := b.newest[addr]
	f, hasFloor := b.floors[addr]
	b.mu.Unlock()
	if !ok || (hasFloor && l.CreatedAt() <= f) {
		return nil, false
	}
	if l.Status != StatusOpen && l.Status != StatusPaused {
		return nil, false
	}
	if now > l.ExpiresAt() || b.taps.Hidden(l) {
		return nil, false
	}
	return l, true
}

// CurrentByD is Current across every pubkey listing d (§Wallet Rules
// "Signals"): the one current listing when a single pubkey lists d; when
// several do, only the listing whose signer passed the check at tap
// (TapCache.Passed), or none. Anyone can re-sign a listed connection's public
// secret under their own key, so before a tap no copy is preferred.
func (b *VersionBook) CurrentByD(d string, now int64) (*Listing, bool) {
	b.mu.Lock()
	var addrs []string
	for a, l := range b.newest {
		if l.D == d {
			addrs = append(addrs, a)
		}
	}
	b.mu.Unlock()
	var shown []*Listing
	for _, a := range addrs {
		if l, ok := b.Current(a, now); ok {
			shown = append(shown, l)
		}
	}
	switch len(shown) {
	case 0:
		return nil, false
	case 1:
		return shown[0], true
	}
	var passed *Listing
	for _, l := range shown {
		if b.taps.Passed(l) {
			if passed != nil {
				return nil, false
			}
			passed = l
		}
	}
	return passed, passed != nil
}

// Addresses lists the addresses the book holds a version of.
func (b *VersionBook) Addresses() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.newest))
	for a := range b.newest {
		out = append(out, a)
	}
	return out
}

type snapshot struct {
	Newest []*nip01.Event        `json:"newest"`
	Floors map[string]int64      `json:"floors"`
	Taps   map[string]TapOutcome `json:"taps"`
	Passed []string              `json:"passed,omitempty"`
}

// Snapshot serialises the book: every newest version, the deletion floors, the
// tap outcomes and the addresses that passed at tap.
func (b *VersionBook) Snapshot() ([]byte, error) {
	b.mu.Lock()
	s := snapshot{Floors: map[string]int64{}, Taps: map[string]TapOutcome{}}
	for _, l := range b.newest {
		s.Newest = append(s.Newest, l.Event)
	}
	for a, f := range b.floors {
		s.Floors[a] = f
	}
	b.mu.Unlock()
	b.taps.mu.Lock()
	for k, o := range b.taps.hide {
		s.Taps[k] = o
	}
	for a := range b.taps.passed {
		s.Passed = append(s.Passed, a)
	}
	b.taps.mu.Unlock()
	return json.Marshal(s)
}

// Restore replaces the book's content with a Snapshot. Every version is checked
// again (steps 1 to 3); one that fails makes Restore fail and leaves the book
// unchanged.
func (b *VersionBook) Restore(p []byte) error {
	var s snapshot
	if err := json.Unmarshal(p, &s); err != nil {
		return fmt.Errorf("listing: snapshot: %w", err)
	}
	newest := map[string]*Listing{}
	for _, ev := range s.Newest {
		l, err := parseListing(ev, nil)
		if err != nil {
			return fmt.Errorf("listing: snapshot: %w", err)
		}
		newest[l.Address()] = l
	}
	floors := map[string]int64{}
	for a, f := range s.Floors {
		if k, _, _, ok := ParseAddress(a); !ok || k != KindListing {
			return fmt.Errorf("listing: snapshot: address %q", a)
		}
		floors[a] = f
	}
	taps := map[string]TapOutcome{}
	for k, o := range s.Taps {
		if strings.Count(k, ":") < 2 || (o != TapHideForGood && o != TapHideUntilNewer) {
			return fmt.Errorf("listing: snapshot: tap outcome %q", k)
		}
		taps[k] = o
	}
	passed := map[string]bool{}
	for _, a := range s.Passed {
		if k, _, _, ok := ParseAddress(a); !ok || k != KindListing {
			return fmt.Errorf("listing: snapshot: passed address %q", a)
		}
		passed[a] = true
	}
	b.mu.Lock()
	b.newest, b.floors = newest, floors
	b.mu.Unlock()
	b.taps.mu.Lock()
	b.taps.hide, b.taps.passed = taps, passed
	b.taps.mu.Unlock()
	return nil
}
