package client

import (
	"context"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip47"
)

// deadRelayURL is a websocket URL nothing listens on. Port 0 never accepts, so
// the dial fails immediately rather than hanging the test.
const deadRelayURL = "ws://127.0.0.1:0"

// TestNWCClient_FailsOverToALaterRelay is the A-5 fix.
//
// NewNWCClient used to parse RelayURLs[0] and dial only that one, so a
// credential naming several relays was a single point of failure with decoys:
// if the first was down every holder was stuck, while healthy relays sat unused
// in the very same string. Nothing in the credential hinted that only entry zero
// was live, and an operator listing three relays reasonably believed they had
// redundancy.
//
// It matters more here than for an ordinary Nostr client because a cash bill is
// a bearer instrument: it can outlive the software that minted it, and its
// holder cannot be handed a corrected string without the hub's cooperation, so a
// dead relay takes the bill with it unless the others are tried.
func TestNWCClient_FailsOverToALaterRelay(t *testing.T) {
	server := newFakeClosingWalletServer(t, "unused", nil)
	pairing := newTestPairingWithServer(t, server)
	liveURL := pairing.RelayURLs[0]

	for _, tc := range []struct {
		name   string
		relays []string
	}{
		{"live relay first", []string{liveURL, deadRelayURL}},
		{"dead relay first", []string{deadRelayURL, liveURL}},
		{"two dead relays before the live one", []string{deadRelayURL, deadRelayURL, liveURL}},
		{"an unparseable hint does not strand the rest", []string{"://not a url", liveURL}},
		{"an empty hint is skipped, not fatal", []string{"", liveURL}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := *pairing
			p.RelayURLs = tc.relays
			client, err := NewNWCClient(context.Background(), &p, nip47.EncryptionNIP44V2)
			if err != nil {
				t.Fatalf("NewNWCClient() error = %v, want a connection via the live relay", err)
			}
			client.Close()
		})
	}
}

// TestNWCClient_AllRelaysUnreachable_ReportsEveryAttempt: when nothing can be
// reached the error names every hint that was tried, not just the last one.
// With failover the useful question is why ALL of them failed — a single
// last-error message sends the reader to the wrong relay.
func TestNWCClient_AllRelaysUnreachable_ReportsEveryAttempt(t *testing.T) {
	pairing := &nip47.PairingInfo{
		WalletPubkey: "ab",
		Secret:       testAppPrivKey,
		RelayURLs:    []string{deadRelayURL, "://not a url"},
	}
	_, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err == nil {
		t.Fatal("NewNWCClient() error = nil, want an error when no relay is reachable")
	}
	for _, want := range []string{deadRelayURL, "not a url"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention the attempt on %q", err, want)
		}
	}
}

// TestNWCClient_OnlyEmptyRelays_IsNotMistakenForNone distinguishes the two
// failure shapes: a credential with no relay entries at all, and one whose
// entries are all empty. Both are unusable, but they are different mistakes and
// the message should not blame the wrong one.
func TestNWCClient_OnlyEmptyRelays_IsNotMistakenForNone(t *testing.T) {
	pairing := &nip47.PairingInfo{
		WalletPubkey: "ab",
		Secret:       testAppPrivKey,
		RelayURLs:    []string{"", "   "},
	}
	_, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err == nil {
		t.Fatal("want an error for a pairing whose relay hints are all empty")
	}
	if !strings.Contains(err.Error(), "no usable relay") {
		t.Errorf("error = %q, want it to say the hints are unusable rather than absent", err)
	}
}
