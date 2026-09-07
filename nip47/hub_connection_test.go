package nip47

import (
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

func TestHubConnectionRoundTrip(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	secret := pubkeyOf(t, testAppPrivKey)
	relays := []string{"wss://relay1.example", "wss://relay2.example"}

	s, err := EncodeHubConnection(HubConnection{
		HRP:          "circlehub",
		WalletPubkey: walletPubkey,
		Secret:       secret,
		RelayURLs:    relays,
		Label:        "Ada's Family Circle",
	})
	if err != nil {
		t.Fatalf("EncodeHubConnection() error = %v", err)
	}
	if !strings.HasPrefix(s, "circlehub1") {
		t.Errorf("encoded string = %q, want circlehub1... prefix", s)
	}

	got, err := DecodeHubConnection(s)
	if err != nil {
		t.Fatalf("DecodeHubConnection() error = %v", err)
	}
	if got.HRP != "circlehub" {
		t.Errorf("HRP = %q, want %q", got.HRP, "circlehub")
	}
	if got.WalletPubkey != walletPubkey {
		t.Errorf("WalletPubkey = %q, want %q", got.WalletPubkey, walletPubkey)
	}
	if got.Secret != secret {
		t.Errorf("Secret = %q, want %q", got.Secret, secret)
	}
	if len(got.RelayURLs) != 2 || got.RelayURLs[0] != relays[0] || got.RelayURLs[1] != relays[1] {
		t.Errorf("RelayURLs = %v, want %v", got.RelayURLs, relays)
	}
	if got.Label != "Ada's Family Circle" {
		t.Errorf("Label = %q", got.Label)
	}
}

func TestHubConnectionWithoutLabel(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	secret := pubkeyOf(t, testAppPrivKey)

	s, err := EncodeHubConnection(HubConnection{
		HRP:          "cashhub",
		WalletPubkey: walletPubkey,
		Secret:       secret,
		RelayURLs:    []string{"wss://relay.example"},
	})
	if err != nil {
		t.Fatalf("EncodeHubConnection() error = %v", err)
	}
	got, err := DecodeHubConnection(s)
	if err != nil {
		t.Fatalf("DecodeHubConnection() error = %v", err)
	}
	if got.Label != "" {
		t.Errorf("Label = %q, want empty", got.Label)
	}
}

func TestHubConnectionDifferentHRPs(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	secret := pubkeyOf(t, testAppPrivKey)

	for _, hrp := range []string{"cashhub", "circlehub"} {
		s, err := EncodeHubConnection(HubConnection{
			HRP: hrp, WalletPubkey: walletPubkey, Secret: secret,
			RelayURLs: []string{"wss://relay.example"},
		})
		if err != nil {
			t.Fatalf("EncodeHubConnection(%q) error = %v", hrp, err)
		}
		if !strings.HasPrefix(s, hrp+"1") {
			t.Errorf("encoded string = %q, want %s1... prefix", s, hrp)
		}
		got, err := DecodeHubConnection(s)
		if err != nil {
			t.Fatalf("DecodeHubConnection(%q) error = %v", hrp, err)
		}
		if got.HRP != hrp {
			t.Errorf("HRP = %q, want %q", got.HRP, hrp)
		}
	}
}

func TestHubConnectionUnknownTLVTypeIgnored(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	secret := pubkeyOf(t, testAppPrivKey)

	s, err := EncodeHubConnection(HubConnection{
		HRP: "cashhub", WalletPubkey: walletPubkey, Secret: secret,
		RelayURLs: []string{"wss://relay.example"},
	})
	if err != nil {
		t.Fatalf("EncodeHubConnection() error = %v", err)
	}

	hrp, bits5, err := bech32.DecodeNoLimit(s)
	if err != nil {
		t.Fatalf("decode bech32 error = %v", err)
	}
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		t.Fatalf("convert bits error = %v", err)
	}
	// Append an unrecognized TLV entry (type 99, 1-byte value) before re-encoding.
	data = append(data, 99, 1, 0xAB)
	bits5again, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		t.Fatalf("convert bits error = %v", err)
	}
	sWithExtra, err := bech32.Encode(hrp, bits5again)
	if err != nil {
		t.Fatalf("encode bech32 error = %v", err)
	}

	got, err := DecodeHubConnection(sWithExtra)
	if err != nil {
		t.Fatalf("DecodeHubConnection() with unknown TLV type error = %v, want nil (ignored)", err)
	}
	if got.WalletPubkey != walletPubkey || got.Secret != secret {
		t.Errorf("got = %+v, want walletPubkey=%q secret=%q", got, walletPubkey, secret)
	}
}

func TestDecodeHubConnectionErrors(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	secret := pubkeyOf(t, testAppPrivKey)

	validNoRelay, err := EncodeHubConnection(HubConnection{HRP: "cashhub", WalletPubkey: walletPubkey, Secret: secret})
	if err != nil {
		t.Fatalf("EncodeHubConnection() error = %v", err)
	}
	// A missing relay is not itself invalid at this layer (relay count is 0
	// or more, unlike wallet pubkey/secret) — DecodeHubConnection should
	// still succeed on it, just with an empty RelayURLs.
	if _, err := DecodeHubConnection(validNoRelay); err != nil {
		t.Errorf("DecodeHubConnection() with no relay, error = %v, want nil", err)
	}

	tests := []struct {
		name string
		s    string
	}{
		{name: "not bech32", s: "not-a-valid-bech32-string"},
		{name: "truncated", s: validNoRelay[:len(validNoRelay)-4]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeHubConnection(tt.s); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
