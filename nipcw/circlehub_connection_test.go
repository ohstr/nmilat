package nipcw

import (
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/ohstr/nmilat/nipcash"
)

func TestCircleHubConnectionRoundTrip(t *testing.T) {
	walletPubkey := randomKeyHex(t)
	secret := randomKeyHex(t)
	relays := []string{"wss://relay1.example", "wss://relay2.example"}

	s, err := EncodeCircleHubConnection(CircleHubConnection{
		WalletPubkey: walletPubkey,
		Secret:       secret,
		RelayURLs:    relays,
		Label:        "Ada's Family Circle",
	})
	if err != nil {
		t.Fatalf("EncodeCircleHubConnection() error = %v", err)
	}
	if !strings.HasPrefix(s, CircleHubConnectionHRP+"1") {
		t.Errorf("encoded string = %q, want %s1... prefix", s, CircleHubConnectionHRP)
	}

	got, err := DecodeCircleHubConnection(s)
	if err != nil {
		t.Fatalf("DecodeCircleHubConnection() error = %v", err)
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

func TestCircleHubConnectionWithoutLabel(t *testing.T) {
	s, err := EncodeCircleHubConnection(CircleHubConnection{
		WalletPubkey: randomKeyHex(t),
		Secret:       randomKeyHex(t),
		RelayURLs:    []string{"wss://relay.example"},
	})
	if err != nil {
		t.Fatalf("EncodeCircleHubConnection() error = %v", err)
	}
	got, err := DecodeCircleHubConnection(s)
	if err != nil {
		t.Fatalf("DecodeCircleHubConnection() error = %v", err)
	}
	if got.Label != "" {
		t.Errorf("Label = %q, want empty", got.Label)
	}
}

func TestCircleHubConnectionUnknownTLVTypeIgnored(t *testing.T) {
	walletPubkey := randomKeyHex(t)
	secret := randomKeyHex(t)

	s, err := EncodeCircleHubConnection(CircleHubConnection{
		WalletPubkey: walletPubkey, Secret: secret,
		RelayURLs: []string{"wss://relay.example"},
	})
	if err != nil {
		t.Fatalf("EncodeCircleHubConnection() error = %v", err)
	}

	hrp, bits5, err := bech32.DecodeNoLimit(s)
	if err != nil {
		t.Fatalf("decode bech32 error = %v", err)
	}
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		t.Fatalf("convert bits error = %v", err)
	}
	data = append(data, 99, 1, 0xAB)
	bits5again, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		t.Fatalf("convert bits error = %v", err)
	}
	sWithExtra, err := bech32.Encode(hrp, bits5again)
	if err != nil {
		t.Fatalf("encode bech32 error = %v", err)
	}

	got, err := DecodeCircleHubConnection(sWithExtra)
	if err != nil {
		t.Fatalf("DecodeCircleHubConnection() with unknown TLV type error = %v, want nil (ignored)", err)
	}
	if got.WalletPubkey != walletPubkey || got.Secret != secret {
		t.Errorf("got = %+v, want walletPubkey=%q secret=%q", got, walletPubkey, secret)
	}
}

func TestDecodeCircleHubConnectionErrors(t *testing.T) {
	walletPubkey := randomKeyHex(t)
	secret := randomKeyHex(t)

	validNoRelay, err := EncodeCircleHubConnection(CircleHubConnection{WalletPubkey: walletPubkey, Secret: secret})
	if err != nil {
		t.Fatalf("EncodeCircleHubConnection() error = %v", err)
	}
	if _, err := DecodeCircleHubConnection(validNoRelay); err != nil {
		t.Errorf("DecodeCircleHubConnection() with no relay, error = %v, want nil", err)
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
			if _, err := DecodeCircleHubConnection(tt.s); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestDecodeCircleHubConnectionWrongHRP(t *testing.T) {
	// A well-formed cashhub1... string has the right shape (bech32, TLV
	// wallet pubkey + secret) but the wrong HRP — must be rejected, not
	// silently accepted as a circle hub connection.
	s, err := nipcash.EncodeCashHubConnection(nipcash.CashHubConnection{
		WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t),
	})
	if err != nil {
		t.Fatalf("setup error = %v", err)
	}
	if _, err := DecodeCircleHubConnection(s); err == nil {
		t.Error("expected error decoding a cashhub1... string as a circle hub connection, got nil")
	}
}
