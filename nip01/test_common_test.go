package nip01

import (
	"testing"
	"time"
)

func CreateEvent(t testing.TB, kind int, tags ...[]string) *Event {
	ev := &Event{
		PubKey:    "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e", // Sample pubkey
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      kind,
		Tags:      tags,
		Content:   "test content",
	}
	// Sign with corresponding private key
	privKey := "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	return ev
}

func createSampleEvent(t testing.TB, kind int, tags ...[]string) *Event {
	return CreateEvent(t, kind, tags...)
}

func createAlteredEvent(t testing.TB, kind int, alter func(*Event)) *Event {
	ev := CreateEvent(t, kind)
	alter(ev)
	// Resign if needed? The test might expect invalid signature if altered content without resign.
	// But validation "EventCheckFormat" checks ID format etc.
	// TestEventVerify checks signature. If we alter content, sig is invalid.
	// We don't resign here to allow creating invalid events.
	return ev
}
