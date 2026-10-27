package nip17

import (
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestChatMessageTags(t *testing.T) {
	ev := NewChatMessage("hi",
		WithRecipients("AA", "bb"),
		WithSubject("plans"),
		WithReply("CC", "wss://r.example"),
	)
	want := [][]string{{"p", "aa"}, {"p", "bb"}, {"subject", "plans"}, {"e", "cc", "wss://r.example"}}
	if !reflect.DeepEqual(ev.Tags, want) {
		t.Fatalf("tags %v", ev.Tags)
	}
	m, err := ParseChatMessage(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.Recipients, []string{"aa", "bb"}) || m.Subject != "plans" || m.ReplyTo != "cc" || m.Root != "" || m.Content != "hi" {
		t.Fatalf("%+v", m)
	}
}

func TestParseChatMessageMarkers(t *testing.T) {
	// The older marked form still parses; the marked reply wins over an unmarked e.
	ev := NewChatMessage("x", WithRoot("r"), WithReplyTo("p1"))
	ev.Tags = append(ev.Tags, []string{"e", "other"})
	m, err := ParseChatMessage(ev)
	if err != nil {
		t.Fatal(err)
	}
	if m.Root != "r" || m.ReplyTo != "p1" {
		t.Fatalf("%+v", m)
	}
	if _, err := ParseChatMessage(nip01.NewEvent(1, "x")); err == nil {
		t.Fatal("kind 1 accepted")
	}
	// No tags: empty lists, never nil.
	m, _ = ParseChatMessage(NewChatMessage("y"))
	if m.Recipients == nil {
		t.Fatal("nil recipients")
	}
}

func TestDMRelayList(t *testing.T) {
	ev := NewDMRelayList([]string{"wss://a", "wss://b"})
	if ev.Kind != KindDMRelays {
		t.Fatal(ev.Kind)
	}
	ev.Tags = append(ev.Tags, []string{"relay"}, []string{"r", "wss://c"})
	got, err := ParseDMRelayList(ev)
	if err != nil || !reflect.DeepEqual(got, []string{"wss://a", "wss://b"}) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseDMRelayList(nip01.NewEvent(10002, "")); err == nil {
		t.Fatal("10002 accepted")
	}
}
