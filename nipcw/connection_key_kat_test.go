package nipcw

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// Known answers for the member-generated connection key (NIP-CW §Pairing
// Connection, §Identity Proof, §Response). Secret 0x11 repeated 32 times; its
// x-only pubkey is the standard published value for that key.
const (
	katConnSecret = "1111111111111111111111111111111111111111111111111111111111111111"
	katConnPubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
)

func TestConnectionKey_KnownAnswer(t *testing.T) {
	k, err := ConnectionKeyFromSecret(katConnSecret)
	if err != nil {
		t.Fatal(err)
	}
	if k.Pubkey() != katConnPubkey || k.Secret() != katConnSecret {
		t.Fatalf("key = (%s, %s), want pubkey %s", k.Pubkey(), k.Secret(), katConnPubkey)
	}
}

// The kind-23199 proof carries exactly one connection tag, equal to
// connection_pubkey, beside the d tag.
func TestIdentityProof_ConnectionTagKnownAnswer(t *testing.T) {
	k, err := ConnectionKeyFromSecret(katConnSecret)
	if err != nil {
		t.Fatal(err)
	}
	memberPriv, _ := generateTestKeypair(t)
	hub := strings.Repeat("cd", 32)
	req, err := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: k, MaxAmountMillis: 1}.Request(hub)
	if err != nil {
		t.Fatal(err)
	}
	var ev nip01.Event
	if err := json.Unmarshal([]byte(req.IdentityEvent), &ev); err != nil {
		t.Fatal(err)
	}
	if got := ev.GetTag("connection"); len(got) != 1 || got[0] != katConnPubkey {
		t.Fatalf("connection tag values = %v, want exactly [%s]", got, katConnPubkey)
	}
	if req.ConnectionPubkey != katConnPubkey {
		t.Fatalf("connection_pubkey = %s, want %s", req.ConnectionPubkey, katConnPubkey)
	}
}

// The member builds its own connection string from the Hub's wallet_pubkey and
// relays and the secret it kept. Expected text written out by hand: relays in
// order, query-escaped, then the secret.
func TestParseResult_ConnectionStringKnownAnswer(t *testing.T) {
	k, err := ConnectionKeyFromSecret(katConnSecret)
	if err != nil {
		t.Fatal(err)
	}
	memberPriv, memberPub := generateTestKeypair(t)
	hubPriv, hubPub := generateTestKeypair(t)
	details := `{"wallet_pubkey":"` + testWalletPubkey + `","relays":["wss://r1.example","wss://r2.example"]}`
	resp, err := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: k}.ParseResult(hubPub, hubReply(t, hubPriv, memberPub, details))
	if err != nil {
		t.Fatal(err)
	}
	want := "nostr+walletconnect://" + testWalletPubkey +
		"?relay=wss%3A%2F%2Fr1.example&relay=wss%3A%2F%2Fr2.example&secret=" + katConnSecret
	if resp.PairingURI != want {
		t.Fatalf("PairingURI:\n got %s\nwant %s", resp.PairingURI, want)
	}
}
