package niplsp

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// version signs the example at createdAt with the given title.
func version(t *testing.T, createdAt int64, title string) *nip01.Event {
	t.Helper()
	f := exampleFields()
	f.Expiration = createdAt + MaxExpirySecs
	f.Display.Title = title
	return signed(t, f, createdAt)
}

// T23-09: newest only, older refused, no fallback.
func TestNewest(t *testing.T) {
	v1 := version(t, exampleCreatedAt, "v1")
	v2 := version(t, exampleCreatedAt+100, "v2")
	seen := NewSeen(mainnet)

	got := Newest(seen, []*nip01.Event{v1})
	if a := got[key1Pub]; a == nil || a.Display.Title != "v1" {
		t.Fatalf("v1: %+v", got)
	}
	// A newer version replaces.
	got = Newest(seen, []*nip01.Event{v2})
	if a := got[key1Pub]; a == nil || a.Display.Title != "v2" {
		t.Fatalf("v2: %+v", got)
	}
	// An older one offered later is refused.
	if _, err := seen.Offer(v1); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("older: %v", err)
	}
	if a, _ := seen.Current(key1Pub); a == nil || a.Display.Title != "v2" {
		t.Fatal("older replaced newer")
	}
	// The same event again gives the same outcome.
	if a, err := seen.Offer(v2); err != nil || a.Display.Title != "v2" {
		t.Fatalf("same again: %v", err)
	}

	// A newer invalid one (protocol 2 without a fee row) leaves the node with
	// no usable announcement: no fallback to v2.
	v3 := signRaw(t, Kind, exampleCreatedAt+200, "", without(TagLSPS2Fee)(cloneTags(exampleTags)))
	if _, err := seen.Offer(v3); err == nil {
		t.Fatal("invalid v3 accepted")
	}
	if _, err := seen.Current(key1Pub); !errors.Is(err, ErrNoUsable) {
		t.Fatalf("fallback: %v", err)
	} else {
		var ae *AnnouncementError
		if !errors.As(err, &ae) || ae.Step != 2 {
			t.Fatalf("cause: %v", err)
		}
	}
	if got := Newest(seen, []*nip01.Event{v1, v2}); len(got) != 0 {
		t.Fatalf("fell back: %+v", got)
	}
	// A still newer valid one makes the node usable again.
	v4 := version(t, exampleCreatedAt+300, "v4")
	if got := Newest(seen, []*nip01.Event{v4}); got[key1Pub] == nil {
		t.Fatal("v4")
	}

	// A forgery (step 1 failure) is not the node's and changes nothing.
	forged := version(t, exampleCreatedAt+400, "forged")
	forged.Sig = strings.Repeat("1", 128)
	if _, err := seen.Offer(forged); err == nil {
		t.Fatal("forgery accepted")
	}
	if a, err := seen.Current(key1Pub); err != nil || a.Display.Title != "v4" {
		t.Fatalf("forgery displaced v4: %v", err)
	}

	// Order of arrival does not matter within one batch.
	seen2 := NewSeen(mainnet)
	if a := Newest(seen2, []*nip01.Event{v4, v1, v2})[key1Pub]; a == nil || a.Display.Title != "v4" {
		t.Fatal("batch order")
	}
}

func TestNewestTieAndExpiry(t *testing.T) {
	a := version(t, exampleCreatedAt, "a")
	b := version(t, exampleCreatedAt, "b")
	low, high := a, b
	if b.ID < a.ID {
		low, high = b, a
	}
	seen := NewSeen(mainnet)
	if _, err := seen.Offer(high); err != nil {
		t.Fatal(err)
	}
	// Same created_at: the lower id wins (NIP-01), the higher is refused.
	if _, err := seen.Offer(low); err != nil {
		t.Fatal(err)
	}
	if _, err := seen.Offer(high); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("higher id: %v", err)
	}

	// An expired newest is not usable, and an older unexpired one is not
	// brought back.
	seen.Options.Now = exampleExpiration + 1
	if _, err := seen.Current(key1Pub); !errors.Is(err, ErrNoUsable) {
		t.Fatalf("expired: %v", err)
	}
	if got := Newest(seen, nil); len(got) != 0 {
		t.Fatal("expired returned")
	}
	if _, err := seen.Current(key2Pub); !errors.Is(err, ErrNoUsable) {
		t.Fatal("unknown node")
	}
}

func TestSeenMarks(t *testing.T) {
	v1 := version(t, exampleCreatedAt, "v1")
	v2 := version(t, exampleCreatedAt+100, "v2")
	seen := NewSeen(mainnet)
	if _, err := seen.Offer(v2); err != nil {
		t.Fatal(err)
	}
	marks := seen.Marks()
	if m := marks[key1Pub]; m.CreatedAt != exampleCreatedAt+100 || m.ID != v2.ID {
		t.Fatalf("%+v", marks)
	}

	// A later run restores the marks: the old version a relay still serves
	// is refused, and v2 itself is remembered, held once offered again.
	next := &Seen{Options: mainnet}
	for k, m := range marks {
		next.Remember(k, m)
	}
	if _, err := next.Offer(v1); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("restored: %v", err)
	}
	if _, err := next.Current(key1Pub); !errors.Is(err, ErrNoUsable) {
		t.Fatal("remembered mark is not an announcement")
	}
	// The remembered event itself is usable once offered again.
	if a, err := next.Offer(v2); err != nil || a == nil {
		t.Fatalf("remembered event re-offered: %v", err)
	}
	if _, err := next.Current(key1Pub); err != nil {
		t.Fatalf("remembered event not held: %v", err)
	}
	// Remember never lowers a newer mark.
	next.Remember(key1Pub, Mark{CreatedAt: exampleCreatedAt, ID: v1.ID})
	if next.Marks()[key1Pub].ID != v2.ID {
		t.Fatal("lowered")
	}
	v3 := version(t, exampleCreatedAt+200, "v3")
	if a, err := next.Offer(v3); err != nil || a.Display.Title != "v3" {
		t.Fatalf("v3: %v", err)
	}
}

func TestSeenConcurrent(t *testing.T) {
	evs := []*nip01.Event{
		version(t, exampleCreatedAt, "1"),
		version(t, exampleCreatedAt+1, "2"),
		version(t, exampleCreatedAt+2, "3"),
	}
	seen := NewSeen(mainnet)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range evs {
				_, _ = seen.Offer(evs[(i+j)%len(evs)])
				_, _ = seen.Current(key1Pub)
				_ = seen.Marks()
			}
		}(i)
	}
	wg.Wait()
	if a, err := seen.Current(key1Pub); err != nil || a.Display.Title != "3" {
		t.Fatalf("%v", err)
	}
}

// NIP-LSP §Client Behavior: an announcement dated more than 15 minutes ahead
// fails step 4 and does not count as seen, so the node's later announcements,
// a closed one included, still replace the last one seen; one dated exactly
// 15 minutes ahead counts.
func TestSeenFutureDated(t *testing.T) {
	now := int64(exampleCreatedAt + 1000)
	o := mainnet
	o.Now = now
	seen := NewSeen(o)
	v1 := version(t, now-100, "v1")
	if _, err := seen.Offer(v1); err != nil {
		t.Fatal(err)
	}
	future := version(t, now+MaxFutureSecs+1, "future")
	_, err := seen.Offer(future)
	wantStep(t, err, 4)
	if m := seen.Marks()[key1Pub]; m.ID != v1.ID {
		t.Fatalf("future-dated event moved the mark: %+v", m)
	}
	if a, err := seen.Current(key1Pub); err != nil || a.Display.Title != "v1" {
		t.Fatalf("current after a future-dated event: %v", err)
	}
	f := exampleFields()
	f.Status = StatusClosed
	f.Expiration = now + MaxExpirySecs
	closed := signed(t, f, now)
	if a, err := seen.Offer(closed); err != nil || a.Status != StatusClosed {
		t.Fatalf("closed after a future-dated event: %v", err)
	}

	atBound := version(t, now+MaxFutureSecs, "at bound")
	if a, err := seen.Offer(atBound); err != nil || a.Display.Title != "at bound" {
		t.Fatalf("15 minutes ahead: %v", err)
	}
	if _, err := seen.Offer(version(t, now+10, "older")); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("older than the 15-minute one: %v", err)
	}

	// A future-dated mark kept by an earlier run is not restored either.
	next := NewSeen(o)
	next.Remember(key1Pub, Mark{CreatedAt: now + MaxFutureSecs + 1, ID: future.ID})
	if _, ok := next.Marks()[key1Pub]; ok {
		t.Fatal("future-dated mark restored")
	}
	next.Remember(key1Pub, Mark{CreatedAt: now + MaxFutureSecs, ID: atBound.ID})
	if m := next.Marks()[key1Pub]; m.ID != atBound.ID {
		t.Fatalf("mark at the bound not restored: %+v", m)
	}
}
