package nip01

import (
	"context"
	"encoding/hex"
	"testing"
)

func TestNewEvent(t *testing.T) {
	ev := NewEvent(1, "hello", []string{"p", "abc"})

	if ev.Kind != 1 {
		t.Errorf("expected kind 1, got %d", ev.Kind)
	}
	if ev.PubKey != "" {
		t.Errorf("expected empty pubkey (set by Sign), got %q", ev.PubKey)
	}
	if ev.Content != "hello" {
		t.Errorf("expected content %q, got %q", "hello", ev.Content)
	}
	if ev.CreatedAt == 0 {
		t.Error("expected a non-zero CreatedAt")
	}
	if len(ev.Tags) != 1 || ev.Tags[0][0] != "p" {
		t.Errorf("unexpected tags: %v", ev.Tags)
	}
}

func TestNewUnsignedEvent(t *testing.T) {
	ev := NewUnsignedEvent(1, "pubkey1", "hello", []string{"p", "abc"})

	if ev.PubKey != "pubkey1" {
		t.Errorf("expected pubkey %q, got %q", "pubkey1", ev.PubKey)
	}
	if ev.Content != "hello" {
		t.Errorf("expected content %q, got %q", "hello", ev.Content)
	}
	if ev.CreatedAt == 0 {
		t.Error("expected a non-zero CreatedAt")
	}
}

func TestNewSignedEvent(t *testing.T) {
	privKey := "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

	ev, err := NewSignedEvent(1, "hello", privKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.PubKey == "" {
		t.Error("expected Sign to populate PubKey")
	}
	if ev.ID == "" || ev.Sig == "" {
		t.Error("expected Sign to populate ID and Sig")
	}
	if err := ev.Verify(); err != nil {
		t.Errorf("expected signed event to verify, got: %v", err)
	}

	if _, err := NewSignedEvent(1, "hello", "not-hex"); err == nil {
		t.Error("expected an error for an invalid private key")
	}
}

func TestEvent_Copy(t *testing.T) {
	original := &Event{
		ID:   "id1",
		Kind: 1,
		Tags: [][]string{{"p", "abc"}},
	}

	cp := original.Copy()

	if cp == original {
		t.Fatal("expected Copy to return a different pointer")
	}
	if cp.ID != original.ID || cp.Kind != original.Kind {
		t.Errorf("expected copy to have the same field values: %+v vs %+v", cp, original)
	}

	// Mutating the copy's tags must not affect the original (deep copy).
	cp.Tags[0][1] = "mutated"
	if original.Tags[0][1] == "mutated" {
		t.Error("expected Copy to deep-copy Tags")
	}
}

func TestEvent_AddTag(t *testing.T) {
	ev := &Event{}
	ev.AddTag([]string{"e", "eventid1"})

	if len(ev.Tags) != 1 || ev.Tags[0][0] != "e" || ev.Tags[0][1] != "eventid1" {
		t.Errorf("unexpected tags after AddTag: %v", ev.Tags)
	}
}

func TestEvent_Mine(t *testing.T) {
	ev := NewEvent(1, "hello")
	ev.PubKey = "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"

	const difficulty = 8
	if err := ev.Mine(context.Background(), difficulty); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ev.Tags) != 1 || ev.Tags[0][0] != "nonce" {
		t.Fatalf("expected a nonce tag to be appended, got %v", ev.Tags)
	}

	wantID, err := ev.HashID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.ID != hex.EncodeToString(wantID) {
		t.Error("Mine did not set ID to the hash of the mined event")
	}
}

func TestEvent_Rehash(t *testing.T) {
	privKey := "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

	ev, err := NewSignedEvent(1, "hello", privKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	originalID := ev.ID

	// Mutating a field after signing desyncs ID from the event's actual
	// content — Rehash should bring it back in sync without re-signing.
	ev.Content = "changed"
	if err := ev.Rehash(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.ID == originalID {
		t.Error("expected Rehash to produce a different ID after content changed")
	}

	wantID, err := ev.HashID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.ID != hex.EncodeToString(wantID) {
		t.Errorf("Rehash did not set ID to the recomputed hash")
	}
}

func TestEvent_GetTag(t *testing.T) {
	ev := &Event{
		Tags: [][]string{
			{"e", "id1"},
			{"e", "id2"},
			{"p", "pubkey1"},
			{"x"}, // too short, should be ignored
		},
	}

	eTags := ev.GetTag("e")
	if len(eTags) != 2 || eTags[0] != "id1" || eTags[1] != "id2" {
		t.Errorf("unexpected e tags: %v", eTags)
	}

	pTags := ev.GetTag("p")
	if len(pTags) != 1 || pTags[0] != "pubkey1" {
		t.Errorf("unexpected p tags: %v", pTags)
	}

	if ev.GetTag("missing") != nil {
		t.Error("expected nil for a tag name with no matches")
	}
}
