package nipcash

import (
	"errors"
	"slices"
	"testing"
)

// NIP-CASH §Relay Hints Are Mandatory: an encoder MUST NOT emit an empty or
// non-ASCII hint. A cash token refuses one, since relay_hash covers its hints as
// written; a connection string skips a blank one and signs what it writes.
func TestEncoders_BlankRelayEntries(t *testing.T) {
	relays := []string{"", "wss://r.example", "  "}
	tok := withTestProvenance(Token{HRP: "lokicash", WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t), RelayURLs: relays})
	if _, err := Encode(tok); !errors.Is(err, ErrBlankRelayHint) {
		t.Fatalf("Encode with blank hints: %v, want ErrBlankRelayHint", err)
	}
	tok.RelayURLs = []string{"wss://r.example", "wss://rélay"}
	if _, err := Encode(tok); !errors.Is(err, ErrNonASCIIRelayHint) {
		t.Fatalf("Encode with a non-ASCII hint: %v", err)
	}

	sign, _ := LocalChainSigner(key1, "bitcoin")
	c, err := SignCashHubConnection(CashHubConnection{Pubkey: randomKeyHex(t), Secret: randomKeyHex(t), Relays: relays,
		HubIdentity: kchIdentity, Chain: "bitcoin"}, sign, kchIdentity)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := EncodeCashHubConnection(c)
	if err != nil {
		t.Fatalf("EncodeCashHubConnection: %v", err)
	}
	hub, err := DecodeCashHubConnection(conn)
	if err != nil {
		t.Fatalf("DecodeCashHubConnection: %v", err)
	}
	if want := []string{"wss://r.example"}; !slices.Equal(hub.Relays, want) {
		t.Errorf("cashhub relays = %q, want %q", hub.Relays, want)
	}
	if err := hub.Verify(); err != nil {
		t.Errorf("the signature does not cover the hints written: %v", err)
	}
}

// withTestProvenance gives a token the provenance fields Encode requires: a
// well-formed but meaningless signature, for tests about the codec only.
func withTestProvenance(t Token) Token {
	if t.MintSignature == nil {
		t.MintSignature = make([]byte, mintSigLen)
		t.MintSignature[0] = 31
	}
	if t.AttestedAmountMillis == nil {
		amt := uint64(1000)
		t.AttestedAmountMillis = &amt
	}
	if t.Scheme == SchemeNone {
		t.Scheme = SchemeMintV1
	}
	return t
}

// mustCashTarget is a fresh cash target, failing the test on a CSPRNG error.
func mustCashTarget(t *testing.T) *CashTarget {
	t.Helper()
	c, err := NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testRID is a well-formed request_id for building requests in tests.
const testRID = "00112233445566778899aabbccddeeff"
