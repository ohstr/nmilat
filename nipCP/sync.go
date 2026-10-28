package nipCP

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip59"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// Relays is how the pocket reaches relays: publish one event to one relay, and
// query one relay for the events a filter matches (stored ones, up to EOSE).
// Kind 1059 is served only to its p, so a Relays answers NIP-42 AUTH as the user.
type Relays interface {
	Publish(ctx context.Context, relay string, ev *nip01.Event) error
	Query(ctx context.Context, relay string, f nip01.SubscriptionFilter) ([]*nip01.Event, error)
}

// DialRelays is a Relays over websocket connections, one per call, answering
// AUTH with authKeyHex (the user's key). It is DialRelaysWith with the default
// AuthWait.
func DialRelays(authKeyHex string) Relays { return DialRelaysWith(DialConfig{AuthKeyHex: authKeyHex}) }

// DefaultAuthWait is DialConfig.AuthWait's default.
const DefaultAuthWait = 2 * time.Second

// DialConfig configures DialRelaysWith.
type DialConfig struct {
	// AuthKeyHex is the key that answers NIP-42 AUTH (the user's key).
	AuthKeyHex string
	// AuthWait bounds how long a query that found nothing waits for the
	// relay's AUTH to settle before it asks once more: the wait ends as soon as
	// the handshake settles, and lasts the whole AuthWait only on a relay that
	// never challenges (or never answers). 0 is DefaultAuthWait; negative never
	// waits.
	AuthWait time.Duration
}

// DialRelaysWith is a Relays over websocket connections, one per call,
// configured by c.
func DialRelaysWith(c DialConfig) Relays {
	if c.AuthWait == 0 {
		c.AuthWait = DefaultAuthWait
	}
	return dialRelays{key: c.AuthKeyHex, authWait: c.AuthWait}
}

type dialRelays struct {
	key      string
	authWait time.Duration
}

func (d dialRelays) conn(ctx context.Context, relay string) (*relayclient.Connection, error) {
	u, err := url.Parse(relay)
	if err != nil {
		return nil, err
	}
	cfg := relayclient.DefaultConnectionConfig()
	cfg.SigningKeyHex = d.key
	return relayclient.NewConnection(ctx, u, cfg)
}

func (d dialRelays) Publish(ctx context.Context, relay string, ev *nip01.Event) error {
	c, err := d.conn(ctx, relay)
	if err != nil {
		return err
	}
	defer c.Close()
	ok, err := c.Publish(ctx, ev)
	if err != nil {
		return err
	}
	if !ok.Accepted {
		return fmt.Errorf("nipCP: %s refused the event: %s", relay, ok.Message)
	}
	return nil
}

func (d dialRelays) Query(ctx context.Context, relay string, f nip01.SubscriptionFilter) ([]*nip01.Event, error) {
	c, err := d.conn(ctx, relay)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	run := func() []*nip01.Event {
		// The events channel closes at EOSE, CLOSED or when the connection
		// ends, together with the done channel: read it to the end, so an
		// event buffered just before EOSE is never lost to that race.
		_, events, _ := c.Subscribe(nip01.NewSubscriptionFilterGroup(&f))
		var out []*nip01.Event
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					return out
				}
				out = append(out, ev.Event)
			case <-ctx.Done():
				return out
			}
		}
	}
	out := run()
	if len(out) == 0 && d.authWait > 0 {
		// A relay serving 1059 only to its p may have closed the first REQ
		// before AUTH settled: ask once more as soon as it does.
		t := time.NewTimer(d.authWait)
		defer t.Stop()
		select {
		case <-c.AuthSettled():
			if c.AuthState() == relayclient.AuthStateSucceeded {
				out = run()
			}
		case <-t.C:
		case <-ctx.Done():
		}
	}
	return out, ctx.Err()
}

// WrapRelays are the relays an entry's wraps go to (NIP-CP §Wrapping): the
// user's kind 10050 relay tags, else the write relays of their NIP-65 list (r
// tags with no marker or "write"). Duplicates are dropped, order kept.
func WrapRelays(kind10050, nip65 *nip01.Event) []string {
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if kind10050 != nil && kind10050.Kind == 10050 {
		for _, t := range kind10050.Tags {
			if len(t) >= 2 && t[0] == "relay" {
				add(t[1])
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	if nip65 != nil && nip65.Kind == 10002 {
		for _, t := range nip65.Tags {
			if len(t) >= 2 && t[0] == "r" && (len(t) == 2 || t[2] == "write" || t[2] == "") {
				add(t[1])
			}
		}
	}
	return out
}

// MinStored is how many relays a wrap is written to and read back from before
// it counts as stored (fewer when fewer relays are given).
const MinStored = 2

// Store writes wrap to every relay and reads it back by id (NIP-CP §Wrapping).
// stored lists the relays that returned it; err is ErrNotStored when fewer
// than MinStored (or than len(relays), if smaller) did.
func Store(ctx context.Context, rs Relays, relays []string, wrap *nip01.Event) (stored []string, err error) {
	if wrap == nil || wrap.Kind != nip59.KindGiftWrap {
		return nil, errors.New("nipCP: Store takes a gift wrap")
	}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		errs []error
	)
	for _, r := range relays {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			err := rs.Publish(ctx, r, wrap)
			if err == nil {
				var got []*nip01.Event
				got, err = rs.Query(ctx, r, nip01.SubscriptionFilter{IDs: []string{wrap.ID}})
				if err == nil && !hasID(got, wrap.ID) {
					err = errors.New("did not return the wrap")
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", r, err))
				return
			}
			stored = append(stored, r)
		}(r)
	}
	wg.Wait()
	stored = ordered(relays, stored)
	need := MinStored
	if len(relays) < need {
		need = len(relays)
	}
	if need == 0 || len(stored) < need {
		return stored, fmt.Errorf("%w (%d of %d): %w", ErrNotStored, len(stored), len(relays), errors.Join(errs...))
	}
	return stored, nil
}

func hasID(evs []*nip01.Event, id string) bool {
	for _, e := range evs {
		if e != nil && e.ID == id {
			return true
		}
	}
	return false
}

func ordered(all, some []string) []string {
	in := map[string]bool{}
	for _, s := range some {
		in[s] = true
	}
	var out []string
	for _, a := range all {
		if in[a] {
			out = append(out, a)
		}
	}
	return out
}

// FullSyncFilter is the full sync's filter: every gift wrap addressed to user.
func FullSyncFilter(user string) nip01.SubscriptionFilter {
	return nip01.SubscriptionFilter{Kinds: []int{nip59.KindGiftWrap}, Tags: map[string][]string{"p": {user}}}
}

// SyncOverlap is how far before the last sync an incremental sync starts: gift
// wraps carry created_at randomized up to two days into the past.
const SyncOverlap = 2 * 24 * 60 * 60

// IncrementalFilter is FullSyncFilter with since = lastSync - SyncOverlap.
func IncrementalFilter(user string, lastSync int64) nip01.SubscriptionFilter {
	f := FullSyncFilter(user)
	since := lastSync - SyncOverlap
	if since < 0 {
		since = 0
	}
	f.Since = uint64(since)
	return f
}

// SeenSet is the wrap ids a sync has already opened.
type SeenSet map[string]bool

// Add records id and reports whether it was new.
func (s SeenSet) Add(id string) bool {
	if s[id] {
		return false
	}
	s[id] = true
	return true
}

// Synced is one sync's harvest: every entry opened (unresolved, for
// DerivedEntryExists and NextVersion), each wrap by id, the relays that
// returned each wrap, and the relays that answered the query at all.
type Synced struct {
	Entries  []Entry
	Wraps    map[string]*nip01.Event
	On       map[string][]string
	Answered []string
}

// Sync queries every relay with f, opens each wrap not in seen, and returns
// what it found. Every event is checked (id and signature) before it is keyed,
// credited to a relay or marked seen, so a relay cannot hide a wrap by
// returning garbage under its id; a wrap is added to seen only once it was
// opened. A relay that fails is skipped; err is set only when every relay
// failed.
func Sync(ctx context.Context, rs Relays, relays []string, userPriv string, f nip01.SubscriptionFilter, seen SeenSet) (Synced, error) {
	out := Synced{Wraps: map[string]*nip01.Event{}, On: map[string][]string{}}
	var errs []error
	var opened []*nip01.Event
	for _, r := range relays {
		evs, err := rs.Query(ctx, r, f)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r, err))
			continue
		}
		out.Answered = append(out.Answered, r)
		for _, ev := range evs {
			if ev == nil || ev.Kind != nip59.KindGiftWrap {
				continue
			}
			if ev.Verify(nip01.WithoutPowCheck()) != nil {
				continue
			}
			out.On[ev.ID] = append(out.On[ev.ID], r)
			if _, ok := out.Wraps[ev.ID]; ok {
				continue
			}
			out.Wraps[ev.ID] = ev
			if seen == nil || !seen[ev.ID] {
				opened = append(opened, ev)
			}
		}
	}
	if len(relays) > 0 && len(errs) == len(relays) {
		return out, errors.Join(errs...)
	}
	entries, err := OpenAll(opened, userPriv)
	if err != nil {
		return out, err
	}
	for _, ev := range opened {
		if seen != nil {
			seen.Add(ev.ID)
		}
	}
	out.Entries = entries
	return out, nil
}

// Republish writes each current entry's wrap again, unchanged, to every relay
// of relays that did not return it in this sync (NIP-CP §Wrapping: republish
// entries a relay no longer returns). Only winners are republished, never a
// superseded wrap. It returns the relays written to, per wrap id.
func Republish(ctx context.Context, rs Relays, relays []string, winners map[string]Entry, seen Synced) (map[string][]string, error) {
	out := map[string][]string{}
	var errs []error
	for _, e := range winners {
		wrap, ok := seen.Wraps[e.WrapID]
		if !ok {
			continue
		}
		have := map[string]bool{}
		for _, r := range seen.On[e.WrapID] {
			have[r] = true
		}
		for _, r := range relays {
			if have[r] {
				continue
			}
			if err := rs.Publish(ctx, r, wrap); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", r, err))
				continue
			}
			out[e.WrapID] = append(out[e.WrapID], r)
		}
	}
	return out, errors.Join(errs...)
}
