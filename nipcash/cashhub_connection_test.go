package nipcash

import (
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

func TestCashHubConnectionRoundTrip(t *testing.T) {
	walletPubkey := randomKeyHex(t)
	secret := randomKeyHex(t)
	relays := []string{"wss://relay1.example", "wss://relay2.example"}

	s, err := EncodeCashHubConnection(CashHubConnection{
		WalletPubkey: walletPubkey,
		Secret:       secret,
		RelayURLs:    relays,
		Label:        "Alice's Cash Hub",
	})
	if err != nil {
		t.Fatalf("EncodeCashHubConnection() error = %v", err)
	}
	if !strings.HasPrefix(s, CashHubConnectionHRP+"1") {
		t.Errorf("encoded string = %q, want %s1... prefix", s, CashHubConnectionHRP)
	}

	got, err := DecodeCashHubConnection(s)
	if err != nil {
		t.Fatalf("DecodeCashHubConnection() error = %v", err)
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
	if got.Label != "Alice's Cash Hub" {
		t.Errorf("Label = %q", got.Label)
	}
}

func TestCashHubConnectionWithoutLabel(t *testing.T) {
	s, err := EncodeCashHubConnection(CashHubConnection{
		WalletPubkey: randomKeyHex(t),
		Secret:       randomKeyHex(t),
		RelayURLs:    []string{"wss://relay.example"},
	})
	if err != nil {
		t.Fatalf("EncodeCashHubConnection() error = %v", err)
	}
	got, err := DecodeCashHubConnection(s)
	if err != nil {
		t.Fatalf("DecodeCashHubConnection() error = %v", err)
	}
	if got.Label != "" {
		t.Errorf("Label = %q, want empty", got.Label)
	}
}

func TestCashHubConnectionUnknownTLVTypeIgnored(t *testing.T) {
	walletPubkey := randomKeyHex(t)
	secret := randomKeyHex(t)

	s, err := EncodeCashHubConnection(CashHubConnection{
		WalletPubkey: walletPubkey, Secret: secret,
		RelayURLs: []string{"wss://relay.example"},
	})
	if err != nil {
		t.Fatalf("EncodeCashHubConnection() error = %v", err)
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

	got, err := DecodeCashHubConnection(sWithExtra)
	if err != nil {
		t.Fatalf("DecodeCashHubConnection() with unknown TLV type error = %v, want nil (ignored)", err)
	}
	if got.WalletPubkey != walletPubkey || got.Secret != secret {
		t.Errorf("got = %+v, want walletPubkey=%q secret=%q", got, walletPubkey, secret)
	}
}

func TestDecodeCashHubConnectionErrors(t *testing.T) {
	walletPubkey := randomKeyHex(t)
	secret := randomKeyHex(t)

	validNoRelay, err := EncodeCashHubConnection(CashHubConnection{WalletPubkey: walletPubkey, Secret: secret})
	if err != nil {
		t.Fatalf("EncodeCashHubConnection() error = %v", err)
	}
	if _, err := DecodeCashHubConnection(validNoRelay); err != nil {
		t.Errorf("DecodeCashHubConnection() with no relay, error = %v, want nil", err)
	}

	// A well-formed lokicash token has the right shape (bech32, TLV wallet
	// pubkey + secret) but the wrong HRP — must be rejected, not silently
	// accepted as a cashhub connection.
	lokicashToken, err := Encode(Token{HRP: "lokicash", WalletPubkey: walletPubkey, Secret: secret})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	tests := []struct {
		name string
		s    string
	}{
		{name: "not bech32", s: "not-a-valid-bech32-string"},
		{name: "truncated", s: validNoRelay[:len(validNoRelay)-4]},
		{name: "wrong hrp", s: lokicashToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeCashHubConnection(tt.s); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
