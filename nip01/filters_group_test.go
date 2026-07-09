package nip01

import "testing"

func TestSubscriptionFilter_Match(t *testing.T) {
	event := &Event{
		ID:        "1234567890123456789012345678901234567890123456789012345678901a",
		PubKey:    "abcdef0123456789012345678901234567890123456789012345678901234a",
		Kind:      1,
		CreatedAt: 1000,
		Content:   "hello world",
		Tags:      [][]string{{"t", "nostr"}},
	}

	tests := []struct {
		name   string
		filter *SubscriptionFilter
		want   bool
	}{
		{"empty filter matches", &SubscriptionFilter{}, true},
		{"matching kind", &SubscriptionFilter{Kinds: []int{1}}, true},
		{"non-matching kind", &SubscriptionFilter{Kinds: []int{2}}, false},
		{"matching id prefix", &SubscriptionFilter{IDs: []string{"12345678"}}, true},
		{"non-matching id", &SubscriptionFilter{IDs: []string{"ffffffff"}}, false},
		{"matching author prefix", &SubscriptionFilter{Authors: []string{"abcdef01"}}, true},
		{"non-matching author", &SubscriptionFilter{Authors: []string{"ffffffff"}}, false},
		{"since satisfied", &SubscriptionFilter{Since: 500}, true},
		{"since not satisfied", &SubscriptionFilter{Since: 2000}, false},
		{"until satisfied", &SubscriptionFilter{Until: 2000}, true},
		{"until not satisfied", &SubscriptionFilter{Until: 500}, false},
		{"matching tag", &SubscriptionFilter{Tags: map[string][]string{"t": {"nostr"}}}, true},
		{"non-matching tag value", &SubscriptionFilter{Tags: map[string][]string{"t": {"other"}}}, false},
		{"missing tag", &SubscriptionFilter{Tags: map[string][]string{"missing": {"x"}}}, false},
		{"matching search", &SubscriptionFilter{Search: "WORLD"}, true},
		{"non-matching search", &SubscriptionFilter{Search: "nope"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.Match(event); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubscriptionFilter_IsEmpty(t *testing.T) {
	if !(&SubscriptionFilter{}).IsEmpty() {
		t.Error("expected zero-value filter to be empty")
	}
	if (&SubscriptionFilter{Kinds: []int{1}}).IsEmpty() {
		t.Error("expected filter with kinds to not be empty")
	}
}

func TestSubscriptionFilter_MarshalJSON_IncludesTags(t *testing.T) {
	filter := &SubscriptionFilter{
		Kinds: []int{1},
		Tags:  map[string][]string{"e": {"eventid1"}},
	}

	data, err := filter.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var roundTripped SubscriptionFilter
	if err := roundTripped.UnmarshalJSON(data); err != nil {
		t.Fatalf("unexpected error unmarshaling: %v", err)
	}
	if len(roundTripped.Kinds) != 1 || roundTripped.Kinds[0] != 1 {
		t.Errorf("expected kinds [1], got %v", roundTripped.Kinds)
	}
	if len(roundTripped.Tags["e"]) != 1 || roundTripped.Tags["e"][0] != "eventid1" {
		t.Errorf("expected tag e=[eventid1], got %v", roundTripped.Tags)
	}
}

func TestSubscriptionFilterGroup(t *testing.T) {
	group := NewSubscriptionFilterGroup()
	if group.Size() != 0 {
		t.Fatalf("expected new group to be empty, got size %d", group.Size())
	}

	f1 := &SubscriptionFilter{Kinds: []int{1}}
	f2 := &SubscriptionFilter{Kinds: []int{2}}
	group.Add(f1)
	group.Add(f2)

	if group.Size() != 2 {
		t.Errorf("expected size 2, got %d", group.Size())
	}
	if len(group.GetAll()) != 2 {
		t.Errorf("expected 2 filters from GetAll, got %d", len(group.GetAll()))
	}

	matchingEvent := &Event{Kind: 2}
	if !group.Match(matchingEvent) {
		t.Error("expected group to match an event matching one of its filters")
	}

	nonMatchingEvent := &Event{Kind: 99}
	if group.Match(nonMatchingEvent) {
		t.Error("expected group not to match an event matching none of its filters")
	}
}

func TestSubscriptionFilterGroup_Equals(t *testing.T) {
	g1 := NewSubscriptionFilterGroup()
	g1.Add(&SubscriptionFilter{Kinds: []int{1}})

	g2 := NewSubscriptionFilterGroup()
	g2.Add(&SubscriptionFilter{Kinds: []int{1}})

	g3 := NewSubscriptionFilterGroup()
	g3.Add(&SubscriptionFilter{Kinds: []int{2}})

	if !g1.Equals(g2) {
		t.Error("expected equivalent groups to be equal")
	}
	if g1.Equals(g3) {
		t.Error("expected different groups to not be equal")
	}
}

func TestSubscriptionFilterGroup_ResetSince(t *testing.T) {
	group := NewSubscriptionFilterGroup()
	group.Add(&SubscriptionFilter{Since: 10})
	group.Add(&SubscriptionFilter{Since: 20})

	group.ResetSince(100)
	for _, f := range group.GetAll() {
		if f.Since != 100 {
			t.Errorf("expected Since=100, got %d", f.Since)
		}
	}

	// lastUpdate == 0 must be a no-op.
	group.ResetSince(0)
	for _, f := range group.GetAll() {
		if f.Since != 100 {
			t.Errorf("expected Since to remain 100 after a zero-value ResetSince, got %d", f.Since)
		}
	}
}

func TestSubscriptionFilterGroup_Copy(t *testing.T) {
	if (*SubscriptionFilterGroup)(nil).Copy() != nil {
		t.Error("expected Copy() on a nil group to return nil")
	}

	original := NewSubscriptionFilterGroup()
	original.Add(&SubscriptionFilter{
		IDs:     []string{"id1"},
		Authors: []string{"author1"},
		Kinds:   []int{1},
		Tags:    map[string][]string{"e": {"eventid1"}},
	})

	cp := original.Copy()
	if cp.Size() != original.Size() {
		t.Fatalf("expected copy to have same size, got %d vs %d", cp.Size(), original.Size())
	}

	// Mutating the copy's slices/maps must not affect the original.
	cp.GetAll()[0].IDs[0] = "mutated"
	cp.GetAll()[0].Authors[0] = "mutated"
	cp.GetAll()[0].Kinds[0] = 999
	cp.GetAll()[0].Tags["e"][0] = "mutated"

	orig := original.GetAll()[0]
	if orig.IDs[0] == "mutated" || orig.Authors[0] == "mutated" || orig.Kinds[0] == 999 || orig.Tags["e"][0] == "mutated" {
		t.Errorf("expected Copy() to deep-copy filter fields, original was mutated: %+v", orig)
	}
}

func TestSubscriptionFilterGroup_HasSearch(t *testing.T) {
	group := NewSubscriptionFilterGroup()
	group.Add(&SubscriptionFilter{Kinds: []int{1}})
	if group.HasSearch() {
		t.Error("expected HasSearch to be false with no search filter")
	}

	group.Add(&SubscriptionFilter{Search: "term"})
	if !group.HasSearch() {
		t.Error("expected HasSearch to be true once a filter has a Search term")
	}
}
