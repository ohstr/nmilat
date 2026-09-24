package nip57

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// Shared fixtures for the zap request/receipt tests. DecodeBolt11 is a
// package-level var stubInvoice swaps, so no test using these may call
// t.Parallel().

// validRecipient is a well-formed 32-byte hex pubkey for the "p" tag.
const validRecipient = "0000000000000000000000000000000000000000000000000000000000000001"

// requestTags returns a minimal valid zap-request tag set with extra tags
// appended.
func requestTags(extra ...[]string) [][]string {
	tags := [][]string{
		{"p", validRecipient},
		{"relays", "wss://relay.example.com"},
		{"amount", "1000"},
	}
	return append(tags, extra...)
}

// signRequest builds and signs a kind-9734 zap request carrying tags.
func signRequest(t *testing.T, tags [][]string) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindZapRequest,
		Tags:      tags,
	}
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("sign zap request: %v", err)
	}
	return ev
}

// signReceipt builds and signs a kind-9735 receipt embedding req as its
// description tag.
func signReceipt(t *testing.T, req *nip01.Event) *nip01.Event {
	t.Helper()
	desc, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal embedded request: %v", err)
	}
	ev := &nip01.Event{
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindZapReceipt,
		Tags: [][]string{
			{"p", validRecipient},
			{"bolt11", "lnbc10n1pjqxyz"},
			{"description", string(desc)},
		},
	}
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("sign zap receipt: %v", err)
	}
	return ev
}

// descriptionHashOf returns the hex sha256 of a receipt's description tag —
// the value a conforming invoice carries in its "h" field.
func descriptionHashOf(t *testing.T, receipt *nip01.Event) string {
	t.Helper()
	for _, tag := range receipt.Tags {
		if len(tag) >= 2 && tag[0] == "description" {
			sum := sha256.Sum256([]byte(tag[1]))
			return hex.EncodeToString(sum[:])
		}
	}
	t.Fatal("receipt has no description tag")
	return ""
}

// stubInvoice swaps DecodeBolt11 for the duration of the test.
func stubInvoice(t *testing.T, inv *Invoice) {
	t.Helper()
	original := DecodeBolt11
	t.Cleanup(func() { DecodeBolt11 = original })
	DecodeBolt11 = func(string) (*Invoice, error) { return inv, nil }
}
