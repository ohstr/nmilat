package relay

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// A tag index key is name(1) + uint16 length + value + created_at + evsid.
// Without the length, the entry for ["h","1"] is a byte prefix of the entry
// for ["h","10"], so a cursor for the shorter value could not tell where its
// own range ended and stopped before reaching any of its keys.

func tagFilter(name string, values ...string) *nip01.SubscriptionFilter {
	return &nip01.SubscriptionFilter{
		Tags:  map[string][]string{name: values},
		Limit: 100,
	}
}

// TestTagValueIsNotShadowedByALongerOne is the core case: a short value must
// still match when a longer value sharing its prefix exists.
func TestTagValueIsNotShadowedByALongerOne(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	values := []string{"1", "10", "100", "1000"}
	byValue := map[string]*nip01.Event{}
	var all []*nip01.Event
	for i, v := range values {
		ev := signEventAt(t, probeKeyA, 1, base-uint64(i), "tag "+v, []string{"h", v})
		byValue[v] = ev
		all = append(all, ev)
	}
	insertInOrder(t, store, all, newestFirst)

	for _, v := range values {
		t.Run("value_"+v, func(t *testing.T) {
			q := newQuery(t, store, filterGroup(tagFilter("h", v)))
			assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{byValue[v]})
		})
	}
}

func TestTagValuePrefixesDoNotCollide(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	values := []string{"a", "ab", "abc", "abcd"}
	byValue := map[string]*nip01.Event{}
	var all []*nip01.Event
	for i, v := range values {
		ev := signEventAt(t, probeKeyA, 1, base-uint64(i), "tag "+v, []string{"t", v})
		byValue[v] = ev
		all = append(all, ev)
	}
	insertInOrder(t, store, all, newestFirst)

	for _, v := range values {
		t.Run("value_"+v, func(t *testing.T) {
			q := newQuery(t, store, filterGroup(tagFilter("t", v)))
			assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{byValue[v]})
		})
	}
}

// Tag values are arbitrary strings, so any byte can appear in one. A
// separator byte would have been unsound; a length prefix is not.
func TestTagValuesWithAwkwardBytes(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	// NUL is the obvious separator byte a naive encoding would pick, and it
	// appears here inside values. Raw invalid UTF-8 is not testable at this
	// level: an event is signed over its JSON, and encoding/json rewrites
	// invalid bytes to U+FFFD, so the stored value would not be the one
	// written here.
	values := []string{
		"\x00",
		"\x00\x00",
		"a\x00b",
		"ÿ",
		"ÿÿ",
		"héllo-世界",
		strings.Repeat("x", 300),
	}

	byValue := map[string]*nip01.Event{}
	var all []*nip01.Event
	for i, v := range values {
		ev := signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("awkward %d", i), []string{"t", v})
		byValue[v] = ev
		all = append(all, ev)
	}
	insertInOrder(t, store, all, newestFirst)

	for i, v := range values {
		t.Run(fmt.Sprintf("value_%d", i), func(t *testing.T) {
			q := newQuery(t, store, filterGroup(tagFilter("t", v)))
			assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{byValue[v]})
		})
	}
}

// The same value under two tag names must not match across them.
func TestSameTagValueUnderDifferentNames(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	e := signEventAt(t, probeKeyA, 1, base, "e tag", []string{"e", "shared"})
	p := signEventAt(t, probeKeyA, 1, base-1, "p tag", []string{"p", "shared"})
	insertInOrder(t, store, []*nip01.Event{e, p}, newestFirst)

	q := newQuery(t, store, filterGroup(tagFilter("e", "shared")))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{e})

	q = newQuery(t, store, filterGroup(tagFilter("p", "shared")))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{p})
}

// A value too long to encode its length is simply not indexed, rather than
// producing a key that later reads back as something else.
func TestOverlongTagValueIsNotIndexed(t *testing.T) {
	store := newStore(t)

	long := strings.Repeat("y", 0x10000)
	ev := signEventAt(t, probeKeyA, 1, uint64(time.Now().Unix()), "overlong", []string{"t", long})
	InsertTestEvents(t, store, []*nip01.Event{ev})

	if got := countBucket(t, store, indexTag); got != 0 {
		t.Errorf("tag index: got %d keys for an unindexable value, want 0", got)
	}
	// The event itself is still stored and findable by other means.
	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 10}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{ev})
}

// Several values of one tag name behave as a union, newest-first.
func TestTagFilterWithSeveralValues(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var all []*nip01.Event
	for i := 0; i < 6; i++ {
		all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i),
			fmt.Sprintf("multi %d", i), []string{"t", fmt.Sprintf("v%d", i)}))
	}
	insertInOrder(t, store, all, newestFirst)

	q := newQuery(t, store, filterGroup(tagFilter("t", "v0", "v1", "v2")))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{all[0], all[1], all[2]})
}
