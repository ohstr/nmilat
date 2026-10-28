package nipCP

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/utils"
)

func key(t testing.TB) (priv, pub string) {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv = hex.EncodeToString(k.Serialize())
	pub, err = utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func hx(c byte, n int) string { return strings.Repeat(string(c), n) }

func secret(t testing.TB) string {
	t.Helper()
	ct, err := nipcash.NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	return ct.Secret()
}

func commitment(t testing.TB, s string) string {
	t.Helper()
	c, err := nipcash.CashCommitment(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func i64(n int64) *int64 { return &n }

func bill(w string, rev uint64, st State) Entry {
	return Entry{W: w, Rev: rev, Cash: "satscash1" + w[:8], Amount: 21000, Chain: "bitcoin",
		Identity: EntryIdentity{Type: IdentityPubkey, Value: hx('a', 64)}, State: st, CheckedAt: 1760000000}
}

func pendingEntry(rid string) Entry {
	return Entry{W: rid, Rev: 1, State: StatePending, CheckedAt: 1760000000, RequestID: rid, Deadline: 1760000300,
		Target: hx('b', 64), Device: hx('d', 32), Chain: "bitcoin", Amount: 5000}
}

func fixClock(t *testing.T, at int64) {
	t.Helper()
	old := now
	now = func() int64 { return at }
	t.Cleanup(func() { now = old })
}

// memRelays is an in-memory Relays: each relay keeps the events published to
// it; hooks make one refuse, drop (accept and never return), or fail queries.
type memRelays struct {
	mu        sync.Mutex
	store     map[string][]*nip01.Event
	refuse    map[string]bool
	drop      map[string]bool
	down      map[string]bool
	published map[string]int
}

func newMem() *memRelays {
	return &memRelays{store: map[string][]*nip01.Event{}, refuse: map[string]bool{}, drop: map[string]bool{},
		down: map[string]bool{}, published: map[string]int{}}
}

func (m *memRelays) Publish(_ context.Context, r string, ev *nip01.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published[r]++
	if m.refuse[r] || m.down[r] {
		return errors.New("refused")
	}
	if m.drop[r] {
		return nil
	}
	if ev.Kind == 5 {
		var keep []*nip01.Event
		for _, s := range m.store[r] {
			gone := false
			for _, t := range ev.Tags {
				gone = gone || (len(t) > 1 && t[0] == "e" && t[1] == s.ID && s.PubKey == ev.PubKey)
			}
			if !gone {
				keep = append(keep, s)
			}
		}
		m.store[r] = keep
		return nil
	}
	for _, s := range m.store[r] {
		if s.ID == ev.ID {
			return nil
		}
	}
	m.store[r] = append(m.store[r], ev)
	return nil
}

func (m *memRelays) Query(_ context.Context, r string, f nip01.SubscriptionFilter) ([]*nip01.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down[r] {
		return nil, errors.New("down")
	}
	var out []*nip01.Event
	for _, ev := range m.store[r] {
		if f.Match(ev) {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (m *memRelays) remove(r, id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keep []*nip01.Event
	for _, s := range m.store[r] {
		if s.ID != id {
			keep = append(keep, s)
		}
	}
	m.store[r] = keep
}

// memDevice is a DeviceStore in memory.
type memDevice struct {
	mu      sync.Mutex
	id      string
	derived map[string]int64
}

func newDevice(t testing.TB) *memDevice {
	id, err := NewDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	return &memDevice{id: id, derived: map[string]int64{}}
}

func (d *memDevice) DeviceID(context.Context) (string, error) { return d.id, nil }
func (d *memDevice) RecordDerived(_ context.Context, id string, until int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.derived[id] = until
	return nil
}
func (d *memDevice) DerivedPlaced(_ context.Context, id string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.derived[id]
	return ok, nil
}
