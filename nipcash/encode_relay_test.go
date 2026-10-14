package nipcash

import (
	"slices"
	"testing"
)

// NIP-CASH §The Cash Token and §The Cash Hub Connection: each relay entry MUST be
// non-empty. A blank entry beside a real one is dropped at encode, not written.
func TestEncoders_SkipBlankRelayEntries(t *testing.T) {
	relays := []string{"", "wss://r.example", "  "}
	want := []string{"wss://r.example"}

	tok, err := Encode(Token{HRP: "lokicash", WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t), RelayURLs: relays})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(tok)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !slices.Equal(decoded.RelayURLs, want) {
		t.Errorf("cash token relays = %q, want %q", decoded.RelayURLs, want)
	}

	conn, err := EncodeCashHubConnection(CashHubConnection{WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t), RelayURLs: relays})
	if err != nil {
		t.Fatalf("EncodeCashHubConnection: %v", err)
	}
	hub, err := DecodeCashHubConnection(conn)
	if err != nil {
		t.Fatalf("DecodeCashHubConnection: %v", err)
	}
	if !slices.Equal(hub.RelayURLs, want) {
		t.Errorf("cashhub relays = %q, want %q", hub.RelayURLs, want)
	}
}
