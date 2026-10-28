package nip25

import (
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewReaction(t *testing.T) {
	note := &nip01.Event{ID: "e1", PubKey: "AA", Kind: 1, Tags: [][]string{}}
	ev := NewReaction(note, "", "wss://r")
	want := [][]string{{"e", "e1", "wss://r", "AA"}, {"p", "AA", "wss://r"}, {"k", "1"}}
	if ev.Kind != KindReaction || ev.Content != "+" || !reflect.DeepEqual(ev.Tags, want) {
		t.Fatalf("%+v", ev)
	}

	group := &nip01.Event{ID: "e2", PubKey: "bb", Kind: 9, Tags: [][]string{{"h", "room"}, {"previous", "x"}}}
	ev = NewReaction(group, "👀", "")
	want = [][]string{{"e", "e2", "", "bb"}, {"p", "bb", ""}, {"k", "9"}, {"h", "room"}}
	if ev.Content != "👀" || !reflect.DeepEqual(ev.Tags, want) {
		t.Fatalf("%+v", ev.Tags)
	}

	article := &nip01.Event{ID: "e3", PubKey: "CC", Kind: 30023, Tags: [][]string{{"d", "slug"}}}
	ev = NewReaction(article, "-", "")
	if got := ev.Tags[3]; !reflect.DeepEqual(got, []string{"a", "30023:cc:slug", ""}) {
		t.Fatalf("%v", got)
	}
}
