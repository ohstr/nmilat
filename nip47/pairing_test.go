package nip47

import (
	"net/url"
	"testing"
)

func TestPairingURIRoundTrip(t *testing.T) {
	pubkey := pubkeyOf(t, testWalletPrivKey)
	extra := url.Values{"lud16": {"alice@example.com"}}

	uri := BuildPairingURI(pubkey, []string{"wss://relay.example"}, "abc123secret", extra)

	got, err := ParsePairingURI(uri)
	if err != nil {
		t.Fatalf("ParsePairingURI() error = %v", err)
	}
	if got.WalletPubkey != pubkey {
		t.Errorf("WalletPubkey = %q, want %q", got.WalletPubkey, pubkey)
	}
	if len(got.RelayURLs) != 1 || got.RelayURLs[0] != "wss://relay.example" {
		t.Errorf("RelayURLs = %v", got.RelayURLs)
	}
	if got.Secret != "abc123secret" {
		t.Errorf("Secret = %q", got.Secret)
	}
	if got.Extra.Get("lud16") != "alice@example.com" {
		t.Errorf("Extra[lud16] = %q", got.Extra.Get("lud16"))
	}
}

func TestPairingURIWithoutExtra(t *testing.T) {
	pubkey := pubkeyOf(t, testWalletPrivKey)
	uri := BuildPairingURI(pubkey, []string{"wss://relay.example"}, "secret", nil)

	got, err := ParsePairingURI(uri)
	if err != nil {
		t.Fatalf("ParsePairingURI() error = %v", err)
	}
	if got.WalletPubkey != pubkey || len(got.RelayURLs) != 1 || got.RelayURLs[0] != "wss://relay.example" || got.Secret != "secret" {
		t.Errorf("got = %+v", got)
	}
}

func TestPairingURIMultiRelayRoundTrip(t *testing.T) {
	pubkey := pubkeyOf(t, testWalletPrivKey)
	relays := []string{"wss://relay1.example", "wss://relay2.example"}

	uri := BuildPairingURI(pubkey, relays, "secret", nil)

	got, err := ParsePairingURI(uri)
	if err != nil {
		t.Fatalf("ParsePairingURI() error = %v", err)
	}
	if len(got.RelayURLs) != 2 || got.RelayURLs[0] != relays[0] || got.RelayURLs[1] != relays[1] {
		t.Errorf("RelayURLs = %v, want %v", got.RelayURLs, relays)
	}
}

func TestParsePairingURIErrors(t *testing.T) {
	pubkey := pubkeyOf(t, testWalletPrivKey)

	tests := []struct {
		name string
		uri  string
	}{
		{name: "wrong scheme", uri: "nostr+walletconnect2://" + pubkey + "?relay=wss://relay.example&secret=abc"},
		{name: "bad pubkey", uri: "nostr+walletconnect://not-a-pubkey?relay=wss://relay.example&secret=abc"},
		{name: "missing relay", uri: "nostr+walletconnect://" + pubkey + "?secret=abc"},
		{name: "missing secret", uri: "nostr+walletconnect://" + pubkey + "?relay=wss://relay.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePairingURI(tt.uri); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
