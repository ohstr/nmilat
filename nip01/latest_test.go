package nip01

import (
	"strings"
	"testing"
	"time"
)

const (
	latestKeyA = "0000000000000000000000000000000000000000000000000000000000000003"
	latestKeyB = "0000000000000000000000000000000000000000000000000000000000000005"
)

func version(t *testing.T, key string, kind int, at uint64, content string, tags ...[]string) *Event {
	t.Helper()
	if tags == nil {
		tags = [][]string{}
	}
	ev := &Event{Kind: kind, CreatedAt: at, Content: content, Tags: tags}
	if err := ev.Sign(key); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestSupersedes(t *testing.T) {
	old := version(t, latestKeyA, 30001, 100, "old", []string{"d", "x"})
	newer := version(t, latestKeyA, 30001, 101, "new", []string{"d", "x"})
	if !Supersedes(newer, old) || Supersedes(old, newer) {
		t.Error("higher created_at must win")
	}

	a := version(t, latestKeyA, 30001, 100, "a", []string{"d", "x"})
	b := version(t, latestKeyA, 30001, 100, "b", []string{"d", "x"})
	low, high := a, b
	if high.ID < low.ID {
		low, high = high, low
	}
	if !Supersedes(low, high) || Supersedes(high, low) {
		t.Error("on a tie the lower id must win")
	}
	upper := *high
	upper.ID = strings.ToUpper(high.ID)
	if !Supersedes(low, &upper) {
		t.Error("id comparison must ignore hex case")
	}
	if Supersedes(low, low) {
		t.Error("an event must not supersede itself")
	}
}

func TestLatestVersion(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	at := func(d time.Duration) uint64 { return uint64(now.Add(d).Unix()) }

	past := version(t, latestKeyA, 30001, at(-time.Hour), "past", []string{"d", "x"})
	recent := version(t, latestKeyA, 30001, at(-time.Minute), "recent", []string{"d", "x"})
	skewed := version(t, latestKeyA, 30001, at(30*time.Second), "slightly ahead", []string{"d", "x"})
	future := version(t, latestKeyA, 30001, at(24*time.Hour), "future", []string{"d", "x"})

	if got := LatestVersion([]*Event{past, future, recent, nil}, now, time.Minute); got != recent {
		t.Errorf("got %q, want recent (future-dated ignored)", got.Content)
	}
	if got := LatestVersion([]*Event{past, skewed, recent}, now, time.Minute); got != skewed {
		t.Errorf("got %q, want the version within the allowed skew", got.Content)
	}
	if got := LatestVersion([]*Event{skewed}, now, 0); got != nil {
		t.Errorf("got %q, want nil: no skew allows nothing past now", got.Content)
	}
	if got := LatestVersion([]*Event{future}, now, time.Minute); got != nil {
		t.Errorf("got %q, want nil when every version is future-dated", got.Content)
	}
	if got := LatestVersion(nil, now, time.Minute); got != nil {
		t.Error("empty input must give nil")
	}

	// The winner doesn't depend on input order.
	tieA := version(t, latestKeyA, 30001, at(-time.Minute), "tie a", []string{"d", "x"})
	tieB := version(t, latestKeyA, 30001, at(-time.Minute), "tie b", []string{"d", "x"})
	want := tieA
	if tieB.ID < tieA.ID {
		want = tieB
	}
	all := []*Event{past, tieA, tieB}
	for i := range all {
		rotated := append(append([]*Event{}, all[i:]...), all[:i]...)
		if got := LatestVersion(rotated, now, time.Minute); got != want {
			t.Errorf("rotation %d: got %q, want %q", i, got.Content, want.Content)
		}
	}
}

func TestLatestVersions(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	ts := uint64(now.Unix())
	events := []*Event{
		version(t, latestKeyA, 30001, ts-10, "x old", []string{"d", "x"}),
		version(t, latestKeyA, 30001, ts-5, "x new", []string{"d", "x"}),
		version(t, latestKeyA, 30001, ts-5, "y", []string{"d", "y"}),
		version(t, latestKeyA, 30001, ts-5, "no d"),
		version(t, latestKeyA, 30001, ts-1, "empty d", []string{"d"}),
		version(t, latestKeyB, 30001, ts-1, "x by B", []string{"d", "x"}),
		version(t, latestKeyA, 0, ts-9, "profile old"),
		version(t, latestKeyA, 0, ts-2, "profile new"),
		version(t, latestKeyA, 1, ts, "note: not replaceable"),
		version(t, latestKeyA, 30001, ts+3600, "future z", []string{"d", "z"}),
		nil,
	}
	got := LatestVersions(events, now, time.Minute)

	pubA := events[0].PubKey
	pubB := events[5].PubKey
	want := map[string]string{
		"30001:" + pubA + ":x": "x new",
		"30001:" + pubA + ":y": "y",
		"30001:" + pubA + ":":  "empty d", // no d and an empty d share a slot
		"30001:" + pubB + ":x": "x by B",
		"0:" + pubA + ":":      "profile new",
	}
	if len(got) != len(want) {
		t.Errorf("got %d slots, want %d: %v", len(got), len(want), keys(got))
	}
	for addr, content := range want {
		if ev := got[addr]; ev == nil || ev.Content != content {
			t.Errorf("%s = %v, want %q", addr, ev, content)
		}
	}
}

func keys(m map[string]*Event) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestReplaceableAddress(t *testing.T) {
	ev := version(t, latestKeyA, 30001, 1, "", []string{"t", "x"}, []string{"d", "first"}, []string{"d", "second"})
	if addr, ok := ReplaceableAddress(ev); !ok || !strings.HasSuffix(addr, ":first") {
		t.Errorf("addr %q ok %v, want the first d tag", addr, ok)
	}
	note := version(t, latestKeyA, 1, 1, "")
	if _, ok := ReplaceableAddress(note); ok {
		t.Error("kind 1 has no replaceable address")
	}
	upper := *ev
	upper.PubKey = strings.ToUpper(ev.PubKey)
	a, _ := ReplaceableAddress(ev)
	b, _ := ReplaceableAddress(&upper)
	if a != b {
		t.Error("address must ignore pubkey hex case")
	}
}
