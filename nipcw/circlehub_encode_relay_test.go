package nipcw

import (
	"slices"
	"testing"
)

// NIP-CW §The Circle Wallet Hub Connection: each relay entry MUST be non-empty. A
// blank entry beside a real one is dropped at encode, not written.
func TestEncodeCircleHubConnection_SkipsBlankRelayEntries(t *testing.T) {
	s, err := EncodeCircleHubConnection(CircleHubConnection{WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t),
		RelayURLs: []string{"", "wss://r.example", "  "}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeCircleHubConnection(s)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if want := []string{"wss://r.example"}; !slices.Equal(got.RelayURLs, want) {
		t.Errorf("relays = %q, want %q", got.RelayURLs, want)
	}
}
