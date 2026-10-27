package nip51

import (
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestAddKeepsEverythingElse(t *testing.T) {
	old := &nip01.Event{Kind: KindMuteList, Content: "encrypted-private-items", Tags: [][]string{
		{"p", "aa"}, {"t", "spam"}, {"word", "x"},
	}}
	out, added := Add(old, KindMuteList, []string{"p", "AA"}, []string{"p", "bb"})
	if !reflect.DeepEqual(added, []string{"bb"}) {
		t.Fatalf("added %v", added)
	}
	want := [][]string{{"p", "aa"}, {"t", "spam"}, {"word", "x"}, {"p", "bb"}}
	if out.Content != "encrypted-private-items" || !reflect.DeepEqual(out.Tags, want) {
		t.Fatalf("%+v", out)
	}
	if len(old.Tags) != 3 {
		t.Fatal("input list changed")
	}
	if out.ID != "" || out.Sig != "" {
		t.Fatal("output must be unsigned")
	}
}

func TestRemove(t *testing.T) {
	old := &nip01.Event{Kind: 3, Content: `{"wss://r":{}}`, Tags: [][]string{{"p", "aa", "wss://x", "al"}, {"p", "bb"}, {"t", "aa"}}}
	out, removed := Remove(old, 3, "p", "AA", "cc")
	if !reflect.DeepEqual(removed, []string{"aa"}) {
		t.Fatalf("removed %v", removed)
	}
	if out.Content != old.Content || !reflect.DeepEqual(out.Tags, [][]string{{"p", "bb"}, {"t", "aa"}}) {
		t.Fatalf("%+v", out)
	}
	if len(old.Tags) != 3 {
		t.Fatal("input list changed")
	}
}

func TestNilList(t *testing.T) {
	out, added := Add(nil, KindSimpleGroups, []string{"group", "id", "wss://r"})
	if out.Kind != KindSimpleGroups || len(added) != 1 || !Has(out, "group", "id") {
		t.Fatalf("%+v", out)
	}
	if v := Values(nil, "p"); v == nil || len(v) != 0 {
		t.Fatal("Values(nil) must be empty, not nil")
	}
}
