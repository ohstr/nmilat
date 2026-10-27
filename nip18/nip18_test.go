package nip18

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewRepost(t *testing.T) {
	note := &nip01.Event{ID: "n", PubKey: "aa", Kind: 1, Content: "hi", Tags: [][]string{}}
	ev, err := NewRepost(note, "wss://r")
	if err != nil {
		t.Fatal(err)
	}
	var back nip01.Event
	if ev.Kind != KindRepost || json.Unmarshal([]byte(ev.Content), &back) != nil || back.ID != "n" {
		t.Fatalf("%+v", ev)
	}
	if !reflect.DeepEqual(ev.Tags, [][]string{{"e", "n", "wss://r"}, {"p", "aa"}}) {
		t.Fatalf("%v", ev.Tags)
	}

	article := &nip01.Event{ID: "a1", PubKey: "BB", Kind: 30023, Tags: [][]string{{"d", "x"}, {"-"}}}
	ev, _ = NewRepost(article, "")
	if ev.Kind != KindGenericRepost || ev.Content != "" {
		t.Fatalf("protected or generic: %+v", ev)
	}
	want := [][]string{{"e", "a1", ""}, {"p", "BB"}, {"k", "30023"}, {"a", "30023:bb:x", ""}}
	if !reflect.DeepEqual(ev.Tags, want) {
		t.Fatalf("%v", ev.Tags)
	}
}
