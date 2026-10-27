package nip09

import (
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewDeletionRequest(t *testing.T) {
	a := &nip01.Event{ID: "1", PubKey: "aa", Kind: 1}
	b := &nip01.Event{ID: "2", PubKey: "AA", Kind: 1}
	c := &nip01.Event{ID: "3", PubKey: "aa", Kind: 30023, Tags: [][]string{{"d", "post"}}}
	ev, err := NewDeletionRequest("aa", []*nip01.Event{a, b, c}, "oops")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"e", "1"}, {"k", "1"}, {"e", "2"}, {"e", "3"}, {"a", "30023:aa:post"}, {"k", "30023"}}
	if ev.Kind != KindDeletion || ev.Content != "oops" || !reflect.DeepEqual(ev.Tags, want) {
		t.Fatalf("%+v", ev)
	}
	if _, err := NewDeletionRequest("bb", []*nip01.Event{a}, ""); err == nil {
		t.Fatal("deleted someone else's event")
	}
	if _, err := NewDeletionRequest("aa", nil, ""); err == nil {
		t.Fatal("empty request")
	}
}
