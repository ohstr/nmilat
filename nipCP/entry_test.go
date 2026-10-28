package nipCP

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
)

func roundTrip(t *testing.T, e Entry) Entry {
	t.Helper()
	_, user := key(t)
	if e.WrapKey == "" {
		e.WrapKey = hx('c', 64)
	}
	r, err := e.Rumor(user, 1760000001)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRumor(r)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func tagNames(t *testing.T, e Entry) []string {
	t.Helper()
	_, user := key(t)
	e.WrapKey = hx('c', 64)
	r, err := e.Rumor(user, 1760000001)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, tg := range r.Tags {
		out = append(out, tg[0])
	}
	return out
}

// T15-03: bill, pending and tombstone entry shapes (S-CP-05, 20, 55).
func TestEntryShapes(t *testing.T) {
	b := bill(hx('1', 64), 1, StateLive)
	b.Mint, b.Source, b.ExpiresAt = "02"+hx('e', 64), hx('f', 64), i64(1790000000)
	if got := tagNames(t, b); !reflect.DeepEqual(got, []string{"w", "rev", "cash", "amount", "chain", "identity", "state", "mint", "expires_at", "source", "wrap_key"}) {
		t.Fatalf("bill tags %v", got)
	}
	got := roundTrip(t, b)
	if got.Cash != b.Cash || *got.ExpiresAt != 1790000000 || got.Mint != b.Mint || got.Source != b.Source || got.Identity != b.Identity {
		t.Fatalf("bill round trip %+v", got)
	}

	s1 := secret(t)
	p := pendingEntry(hx('2', 32))
	p.Secrets = []nipcash.PendingSecret{{Secret: s1}}
	if got := tagNames(t, p); !reflect.DeepEqual(got, []string{"w", "rev", "amount", "chain", "state", "request_id", "deadline", "target", "device", "secret", "wrap_key"}) {
		t.Fatalf("pending tags %v", got)
	}
	if got := roundTrip(t, p); got.RequestID != p.RequestID || got.Secrets[0].Secret != s1 || got.Device != p.Device {
		t.Fatalf("pending round trip %+v", got)
	}

	// A tombstone entry: no cash, no expires_at, final state.
	tomb := bill(hx('3', 64), 2, StateReclaimed)
	tomb.Cash = ""
	if got := roundTrip(t, tomb); got.Cash != "" || got.State != StateReclaimed {
		t.Fatalf("tombstone entry %+v", got)
	}
	tomb.State = StateLive
	if err := tomb.Validate(); !errors.Is(err, ErrEntry) {
		t.Fatal("a live entry without cash validated")
	}

	// A pending entry carries no cash, identity or expires_at.
	for _, mut := range []func(*Entry){
		func(e *Entry) { e.Cash = "satscash1x" },
		func(e *Entry) { e.Identity = EntryIdentity{Type: IdentityCash} },
		func(e *Entry) { e.ExpiresAt = i64(5) },
		func(e *Entry) { e.W = hx('9', 32) },
		func(e *Entry) { e.State = StateLive },
	} {
		q := pendingEntry(hx('2', 32))
		mut(&q)
		if err := q.Validate(); !errors.Is(err, ErrEntry) {
			t.Fatalf("pending %+v validated", q)
		}
	}
}

func rumorWith(t *testing.T, e Entry, edit func(tags [][]string) [][]string) *nip01.Event {
	t.Helper()
	_, user := key(t)
	e.WrapKey = hx('c', 64)
	r, err := e.Rumor(user, 1760000001)
	if err != nil {
		t.Fatal(err)
	}
	r.Tags = edit(r.Tags)
	r.ID = ""
	return r
}

func setTag(name string, v ...string) func([][]string) [][]string {
	return func(tags [][]string) [][]string {
		for i, tg := range tags {
			if tg[0] == name {
				tags[i] = append([]string{name}, v...)
			}
		}
		return tags
	}
}

// T15-03 encodings (S-CP-54, K-POCKET-1..2).
func TestParseRumorEncodings(t *testing.T) {
	b := bill(hx('1', 64), 7, StateLive)
	b.Mint = "02" + hx('e', 64)
	for name, edit := range map[string]func([][]string) [][]string{
		"rev 07":         setTag("rev", "07"),
		"amount +21000":  setTag("amount", "+21000"),
		"amount 21000.0": setTag("amount", "21000.0"),
		"uppercase w":    setTag("w", hx('A', 64)),
		"64-hex mint":    setTag("mint", hx('e', 64)),
		"state time 01":  setTag("state", "live", "01"),
		"no state time":  setTag("state", "live"),
		"v not rev": func(tags [][]string) [][]string {
			return setTag("rev")(tags)[:0:0]
		},
		"two amounts":  func(tags [][]string) [][]string { return append(tags, []string{"amount", "1"}) },
		"expires_at 0": func(tags [][]string) [][]string { return append(tags, []string{"expires_at", "0"}) },
	} {
		r := rumorWith(t, b, edit)
		if name == "v not rev" {
			r.Tags = [][]string{{"w", b.W}, {"v", "1"}, {"cash", "x"}, {"amount", "1"}, {"chain", "bitcoin"}, {"identity", "cash"}, {"state", "live", "1"}, {"wrap_key", hx('c', 64)}}
		}
		if _, err := ParseRumor(r); !errors.Is(err, ErrEntry) {
			t.Errorf("%s: err = %v, want ErrEntry", name, err)
		}
	}
	// A signed 9525 is refused.
	priv, _ := key(t)
	r := rumorWith(t, b, func(tags [][]string) [][]string { return tags })
	r.PubKey = ""
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRumor(r); !errors.Is(err, ErrEntry) {
		t.Fatal("a signed 9525 parsed")
	}
	// An unrecognised state is kept raw, for the derived-id check only.
	u := rumorWith(t, b, setTag("state", "frozen", "1760000000"))
	got, err := ParseRumor(u)
	if err != nil || got.RawState != "frozen" || got.Recognised() {
		t.Fatalf("unrecognised state: %+v %v", got, err)
	}
}

// T15-04: expires_at 0 is never stored (S-CP-06).
func TestExpiresAtZeroNotStored(t *testing.T) {
	b := bill(hx('1', 64), 1, StateLive)
	if WithExpiry(b, 0, 1760000100).ExpiresAt != nil {
		t.Fatal("expires_at 0 stored")
	}
	if n := WithExpiry(b, 1790000000, 1760000100); *n.ExpiresAt != 1790000000 || n.Rev != 2 {
		t.Fatalf("WithExpiry %+v", n)
	}
	b.ExpiresAt = i64(0)
	if err := b.Validate(); !errors.Is(err, ErrEntry) {
		t.Fatal("expires_at 0 validated")
	}
}

// T15-19 / CASH-S-14: a zap bill's source stays with it until it moves.
func TestZapSourceKept(t *testing.T) {
	b := bill(hx('1', 64), 1, StateLive)
	b.Source = hx('f', 64)
	if got := roundTrip(t, WithExpiry(b, 1790000000, 1760000100)); got.Source != b.Source {
		t.Fatal("source lost on a rewrite")
	}
	if got := roundTrip(t, WithState(b, StateSpent, 1760000100)); got.Source != b.Source || got.Cash == "" {
		t.Fatal("a spent source lost its token or source")
	}
}

// F-CP-1: parse, write, parse is stable.
func FuzzParseRumor(f *testing.F) {
	f.Add("live", "21000", "bitcoin", "1")
	f.Add("frozen", "07", "", "0")
	f.Fuzz(func(t *testing.T, state, amount, chain, rev string) {
		ev := &nip01.Event{Kind: KindPocketEntry, PubKey: hx('a', 64), CreatedAt: 1, Tags: [][]string{
			{"w", hx('1', 64)}, {"rev", rev}, {"cash", "x"}, {"amount", amount}, {"chain", chain},
			{"identity", "cash"}, {"state", state, "5"}, {"wrap_key", hx('c', 64)}}}
		e, err := ParseRumor(ev)
		if err != nil || !e.Recognised() {
			return
		}
		r, err := e.Rumor(ev.PubKey, 1)
		if err != nil {
			t.Fatalf("parsed entry does not write: %v", err)
		}
		e2, err := ParseRumor(r)
		if err != nil {
			t.Fatal(err)
		}
		e.RumorID, e2.RumorID = "", ""
		if !reflect.DeepEqual(e, e2) {
			t.Fatalf("unstable: %+v vs %+v", e, e2)
		}
	})
}
