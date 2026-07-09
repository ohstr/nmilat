package nip17

import "testing"

func TestCreateChatMessage_NoRefs(t *testing.T) {
	ev := NewChatMessage("hello")

	if ev.Kind != KindChatMessage {
		t.Errorf("expected kind %d, got %d", KindChatMessage, ev.Kind)
	}
	if ev.Content != "hello" {
		t.Errorf("expected content %q, got %q", "hello", ev.Content)
	}
	if len(ev.Tags) != 0 {
		t.Errorf("expected no tags, got %v", ev.Tags)
	}
}

func TestCreateChatMessage_WithRootAndReply(t *testing.T) {
	root := "root-id"
	reply := "reply-id"

	ev := NewChatMessage("hi", WithRoot(root), WithReplyTo(reply))

	if len(ev.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d: %v", len(ev.Tags), ev.Tags)
	}

	rootTag := ev.Tags[0]
	if rootTag[0] != "e" || rootTag[1] != root || rootTag[3] != "root" {
		t.Errorf("unexpected root tag: %v", rootTag)
	}

	replyTag := ev.Tags[1]
	if replyTag[0] != "e" || replyTag[1] != reply || replyTag[3] != "reply" {
		t.Errorf("unexpected reply tag: %v", replyTag)
	}
}

func TestCreateChatMessage_RootOnly(t *testing.T) {
	root := "root-id"
	ev := NewChatMessage("hi", WithRoot(root))

	if len(ev.Tags) != 1 {
		t.Fatalf("expected 1 tag, got %d: %v", len(ev.Tags), ev.Tags)
	}
	if ev.Tags[0][3] != "root" {
		t.Errorf("expected root marker, got %v", ev.Tags[0])
	}
}
