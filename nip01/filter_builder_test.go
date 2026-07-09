package nip01

import (
	"reflect"
	"testing"
)

func TestFilterBuilder_MatchesStructLiteral(t *testing.T) {
	built := NewFilter().
		WithKinds(1, 2).
		WithAuthors("author1", "author2").
		WithIDs("id1").
		WithLimit(10).
		WithSince(100).
		WithUntil(200).
		WithTag("e", "e1", "e2").
		WithTag("p", "p1")

	want := &SubscriptionFilter{
		Kinds:   []int{1, 2},
		Authors: []string{"author1", "author2"},
		IDs:     []string{"id1"},
		Limit:   10,
		Since:   100,
		Until:   200,
		Tags: map[string][]string{
			"e": {"e1", "e2"},
			"p": {"p1"},
		},
	}

	if !reflect.DeepEqual(built, want) {
		t.Errorf("builder output = %+v, want %+v", built, want)
	}
}

func TestFilterBuilder_WithTagMergesRepeatedCalls(t *testing.T) {
	built := NewFilter().WithTag("e", "e1").WithTag("e", "e2")

	if got := built.Tags["e"]; !reflect.DeepEqual(got, []string{"e1", "e2"}) {
		t.Errorf("expected merged tag values [e1 e2], got %v", got)
	}
}

func TestNewSubscriptionFilterGroup_Variadic(t *testing.T) {
	f1 := NewFilter().WithKinds(1)
	f2 := NewFilter().WithKinds(2)

	group := NewSubscriptionFilterGroup(f1, f2)
	if group.Size() != 2 {
		t.Fatalf("expected 2 filters, got %d", group.Size())
	}

	group2 := NewSubscriptionFilterGroup()
	group2.Add(f1, f2)
	if group2.Size() != 2 {
		t.Fatalf("expected Add to accept multiple filters, got %d", group2.Size())
	}
}
