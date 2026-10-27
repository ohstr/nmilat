package nip10

import (
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestReplyToRoot(t *testing.T) {
	root := &nip01.Event{ID: "r", PubKey: "AA", Kind: 1, Tags: [][]string{{"p", "bb"}}}
	got := ReplyTags(root, "wss://x")
	want := [][]string{{"e", "r", "wss://x", "root", "AA"}, {"p", "aa"}, {"p", "bb"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestReplyToReply(t *testing.T) {
	mid := &nip01.Event{ID: "m", PubKey: "cc", Kind: 1, Tags: [][]string{
		{"e", "r", "wss://root", "root", "aa"}, {"e", "r", "", "reply"}, {"p", "aa"}, {"p", "cc"},
	}}
	got := ReplyTags(mid, "")
	want := [][]string{{"e", "r", "wss://root", "root", "aa"}, {"e", "m", "", "reply", "cc"}, {"p", "cc"}, {"p", "aa"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestReplyToPositional(t *testing.T) {
	old := &nip01.Event{ID: "m", PubKey: "cc", Kind: 1, Tags: [][]string{{"e", "r"}, {"e", "x"}}}
	id, _, _ := Root(old)
	if id != "r" {
		t.Fatalf("root %q", id)
	}
}
