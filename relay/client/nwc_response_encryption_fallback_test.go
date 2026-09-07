package client

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
)

// untaggedNIP44Response builds a normal NIP-44 v2 response event via
// nip47.NewResponseEvent (which correctly tags it), then strips the
// "encryption" tag before returning it — reproducing what a wallet that
// doesn't re-declare its response's encryption scheme sends (e.g.
// lokihub's own nip47Service.CreateResponse, which tags every response
// with only "p"/"e", regardless of which scheme actually encrypted its
// content). The event is still genuinely NIP-44 v2 encrypted; only the
// tag declaring that is missing.
func untaggedNIP44Response(t *testing.T, reqEvent *nip01.Event, preimage string) *nip01.Event {
	t.Helper()
	respEvent := signedPayInvoiceResponse(t, reqEvent, preimage)
	tags := make([][]string, 0, len(respEvent.Tags))
	for _, tag := range respEvent.Tags {
		if len(tag) > 0 && tag[0] == "encryption" {
			continue
		}
		tags = append(tags, tag)
	}
	respEvent.Tags = tags
	if err := respEvent.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return respEvent
}

// TestNWCClient_UntaggedNIP44Response_StillDecrypts is a regression test
// for the actual root cause behind a real, reproducible NWC round-trip
// failure found while investigating lokihub integration test timeouts:
// ParseResponseEvent defaulted to legacy NIP-04 whenever a response lacked
// its own "encryption" tag, rather than falling back to the scheme the
// client itself used for the original request. A NIP-47 response is
// always a reply to a request the client just encrypted under a scheme of
// its own choosing — plenty of real wallets (lokihub included) simply
// reply in kind without redundantly re-declaring that scheme on the
// response, which made every one of their NIP-44-v2 responses silently
// fail to decrypt (misinterpreted as NIP-04 ciphertext) and the call would
// hang until ctx's full timeout with no error surfaced anywhere.
func TestNWCClient_UntaggedNIP44Response_StillDecrypts(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		return []*nip01.Event{untaggedNIP44Response(t, reqEvent, "deadbeef")}
	})

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	result, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("PayInvoice() error = %v after %s (an untagged-but-genuinely-NIP-44-v2 response should still decrypt, using the encryption this client itself used for its own request)", err, elapsed)
	}
	if result.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want %q", result.Preimage, "deadbeef")
	}
	if elapsed >= 4*time.Second {
		t.Errorf("PayInvoice() took %s, want it to succeed promptly, not ride out most of the 5s deadline", elapsed)
	}
}
