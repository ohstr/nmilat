package nip65

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

const testPrivKey = "48939ec93986b59b58d7206887b42ff74d99dd3258782e2fdfd720eb74d547a5"

func signed(t *testing.T, ev *nip01.Event) *nip01.Event {
	t.Helper()
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return ev
}

func TestParseRelayList_WrongKind(t *testing.T) {
	event := &nip01.Event{Kind: 1}
	if _, err := ParseRelayList(event); err == nil {
		t.Fatal("expected error for wrong kind")
	}
}

func TestParseRelayList_ValidRelays(t *testing.T) {
	event := &nip01.Event{
		Kind: KindRelayListMetadata,
		Tags: [][]string{
			{"r", "wss://relay.example.com"},
			{"r", "ws://relay2.example.com", "read"},
			{"r", "ws://relay3.example.com", "write"},
			{"p", "ignored-non-r-tag"},
		},
	}
	rl, err := ParseRelayList(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rl.Relays) != 3 {
		t.Fatalf("expected 3 relays, got %d: %v", len(rl.Relays), rl.Relays)
	}
	if !rl.Relays[0].Read || !rl.Relays[0].Write {
		t.Errorf("expected no-marker relay to be both read+write, got %+v", rl.Relays[0])
	}
	if !rl.Relays[1].Read || rl.Relays[1].Write {
		t.Errorf("expected read-marker relay to be read-only, got %+v", rl.Relays[1])
	}
	if rl.Relays[2].Read || !rl.Relays[2].Write {
		t.Errorf("expected write-marker relay to be write-only, got %+v", rl.Relays[2])
	}
}

func TestParseRelayList_InvalidURL(t *testing.T) {
	event := &nip01.Event{
		Kind: KindRelayListMetadata,
		Tags: [][]string{
			{"r", "://not-a-valid-url"},
		},
	}
	if _, err := ParseRelayList(event); err == nil {
		t.Fatal("expected error for malformed relay URL")
	}
}

func TestParseRelayList_WrongScheme(t *testing.T) {
	event := &nip01.Event{
		Kind: KindRelayListMetadata,
		Tags: [][]string{
			{"r", "https://relay.example.com"},
		},
	}
	if _, err := ParseRelayList(event); err == nil {
		t.Fatal("expected error for non-ws(s) scheme")
	}
}

func TestParseRelayList_ShortTagIgnored(t *testing.T) {
	event := &nip01.Event{
		Kind: KindRelayListMetadata,
		Tags: [][]string{
			{"r"},
		},
	}
	rl, err := ParseRelayList(event)
	if err != nil {
		t.Fatalf("unexpected error for short tag: %v", err)
	}
	if len(rl.Relays) != 0 {
		t.Errorf("expected short tag to be ignored, got %v", rl.Relays)
	}
}

func TestNewRelayListAndValidate(t *testing.T) {
	ev := signed(t, NewRelayList("", []RelayEntry{
		{URL: "wss://relay.example.com", Read: true, Write: true},
		{URL: "ws://read-only.example.com", Read: true},
		{URL: "ws://write-only.example.com", Write: true},
	}))

	if err := ValidateRelayList(ev); err != nil {
		t.Fatalf("ValidateRelayList() error = %v", err)
	}

	rl, err := ParseRelayList(ev)
	if err != nil {
		t.Fatalf("ParseRelayList() error = %v", err)
	}
	if len(rl.Relays) != 3 {
		t.Fatalf("expected 3 relays, got %d", len(rl.Relays))
	}
	if !rl.Relays[1].Read || rl.Relays[1].Write {
		t.Errorf("expected relay 1 to be read-only, got %+v", rl.Relays[1])
	}
	if rl.Relays[2].Read || !rl.Relays[2].Write {
		t.Errorf("expected relay 2 to be write-only, got %+v", rl.Relays[2])
	}
}

func TestValidateRelayList_InvalidSignature(t *testing.T) {
	ev := NewRelayList("", []RelayEntry{{URL: "wss://relay.example.com", Read: true, Write: true}})
	// Not signed: ID/PubKey/Sig are all empty.
	if err := ValidateRelayList(ev); err == nil {
		t.Fatal("expected error for unsigned event")
	}
}
