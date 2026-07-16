package nip01

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func readSampleEvents(t testing.TB) []*Event {
	data, err := os.ReadFile("../testdata/events.json")
	if err != nil {
		t.Fatal(err)
	}

	var events []*Event
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatal(err)
	}

	for _, event := range events {
		if err := event.Validate(); err != nil {
			t.Fatal(err)
		}
	}

	return events[0:55]
}

func readSampleStrEvents(t testing.TB, sampleEvents []*Event) []string {
	sampleStrEvents := []string{}

	for _, ev := range sampleEvents {
		if evBytes, err := json.Marshal(ev); err != nil {
			t.Fatal(err)
		} else {
			sampleStrEvents = append(sampleStrEvents, string(evBytes))
		}
	}

	return sampleStrEvents
}

func TestEventSign(t *testing.T) {
	privKey := "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	pubKey := "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"

	tests := []struct {
		name      string
		event     *Event
		wantError bool
	}{
		{
			"valid event",
			&Event{
				PubKey:    pubKey,
				CreatedAt: 1700000000, // Fixed timestamp for deterministic ID
				Kind:      1,
				Tags:      [][]string{},
				Content:   "test content",
			},
			false,
		},
		{
			"invalid event",
			&Event{
				PubKey:    pubKey,
				CreatedAt: 1700000000,
				Kind:      1,
				Tags:      [][]string{{"e", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}},
				Content:   "test content",
			},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.event.Sign(privKey); err != nil {
				t.Fatalf("failed to sign event: %v", err)
			}

			// Verify the event can be validated
			if err := test.event.Verify(); err != nil {
				t.Fatalf("signed event failed verification: %v", err)
			}

			// Verify ID is a valid 64-char hex string
			if len(test.event.ID) != 64 {
				t.Fatalf("invalid event ID length: %d", len(test.event.ID))
			}

			// Verify Sig is a valid 128-char hex string (64 bytes)
			if len(test.event.Sig) != 128 {
				t.Fatalf("invalid event Sig length: %d", len(test.event.Sig))
			}
		})
	}

}

func TestEventCheckFormat(t *testing.T) {

	tests := []struct {
		name      string
		event     *Event
		wantError bool
	}{
		{"valid", createAlteredEvent(t, 1, func(e *Event) {}), false},
		{"upper", createAlteredEvent(t, 1, func(e *Event) { e.ID = strings.ToUpper(e.ID) }), false},
		{"kind", createAlteredEvent(t, 1, func(e *Event) { e.Kind = 99999 }), true},
		{"tags", createAlteredEvent(t, 1, func(e *Event) { e.Tags = append(e.Tags, []string{"a9", ""}) }), false},
		{"tags", createAlteredEvent(t, 1, func(e *Event) { e.Tags = append(e.Tags, []string{}) }), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			if err := test.event.Validate(); (err != nil) != test.wantError {
				if err == nil {
					t.Fatalf("expected error got nil")
				} else {
					t.Fatalf("failed to check event format, error=%v", err)
				}
			}

		})
	}

}

func TestEventVerify(t *testing.T) {

	tests := []struct {
		name      string
		event     *Event
		wantError bool
	}{
		{"valid event", CreateEvent(t, 1), false},
		{"altered event", createAlteredEvent(t, 1, func(e *Event) { e.Content = "altered content" }), true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			if err := test.event.Verify(); (err != nil) != test.wantError {
				t.Fatalf("failed to verify. error=%v", err)
			}

		})
	}

}

func TestEventVerifyWithoutPowCheck(t *testing.T) {

	// Declares difficulty 20 -- essentially certain not to be met by an
	// event that wasn't actually mined for it.
	ev := CreateEvent(t, 1, []string{"nonce", "1", "20"})

	if err := ev.Verify(); err == nil {
		t.Fatal("expected pow check to fail for an unmined nonce tag")
	} else if !strings.Contains(err.Error(), "pow check failed") {
		t.Fatalf("expected a pow check failure, got: %v", err)
	}

	if err := ev.Verify(WithoutPowCheck()); err != nil {
		t.Fatalf("WithoutPowCheck should have skipped the invalid nonce tag, got: %v", err)
	}
}

func TestEventID(t *testing.T) {

	sampleEvents := readSampleEvents(t)

	for _, event := range sampleEvents {
		t.Run(fmt.Sprintf("event-%s", event.ID[:8]), func(t *testing.T) {

			if eventID, err := event.HashID(); err != nil {
				t.Fatal(err)
			} else if event.ID != hex.EncodeToString(eventID) {
				t.Fatalf("mismatch event ID : %v <> %v", event.ID, hex.EncodeToString(eventID))
			}

			// marshal
			eventBytes, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}

			var eventCopy *Event
			if err := json.Unmarshal(eventBytes, &eventCopy); err != nil {
				t.Fatal(err)
			}

			if err := eventCopy.Validate(); err != nil {
				t.Fatal(err)
			}

			if eventID, err := eventCopy.HashID(); err != nil {
				t.Fatal(err)
			} else if eventCopy.ID != hex.EncodeToString(eventID) {
				t.Fatalf("mismatch eventCopy ID : %v <> %v", eventCopy.ID, hex.EncodeToString(eventID))
			}

		})

	}

}

func BenchmarkEventUnMarshal(b *testing.B) {

	sampleEvents := readSampleEvents(b)
	sampleStrEvents := readSampleStrEvents(b, sampleEvents)

	for b.Loop() {
		for _, strEvent := range sampleStrEvents {
			var event *Event
			if err := json.Unmarshal([]byte(strEvent), &event); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkEventMarshal(b *testing.B) {

	sampleEvents := readSampleEvents(b)

	for b.Loop() {
		for _, event := range sampleEvents {
			_, err := json.Marshal(event)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkEventVerify measures schnorr signature verification, the
// CPU-bound gate every incoming EVENT passes through before it ever
// reaches the store.
func BenchmarkEventVerify(b *testing.B) {

	sampleEvents := readSampleEvents(b)

	for b.Loop() {
		for _, event := range sampleEvents {
			if err := event.Verify(); err != nil {
				b.Fatal(err)
			}
		}
	}
}
