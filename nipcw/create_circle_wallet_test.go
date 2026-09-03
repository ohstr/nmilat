package nipcw

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/utils"
)

func randomKeyHex(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func generateTestKeypair(t *testing.T) (privKeyHex, pubKeyHex string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privKeyHex = hex.EncodeToString(priv.Serialize())
	pubKeyHex, err = utils.GetPublicKey(privKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return privKeyHex, pubKeyHex
}

func TestCreateCircleWalletParams_Request(t *testing.T) {
	privKeyHex, pubKeyHex := generateTestKeypair(t)
	hubPubkey := randomKeyHex(t)
	p := CreateCircleWalletParams{
		Credential:      BySigning(privKeyHex),
		MaxAmountMillis: 100_000,
		Expiry:          30 * 24 * time.Hour,
		BudgetRenewal:   "monthly",
	}
	req, err := p.Request(hubPubkey)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.Pubkey != pubKeyHex {
		t.Fatalf("Pubkey: got %s, want %s", req.Pubkey, pubKeyHex)
	}
	if req.MaxAmount != 100_000 {
		t.Fatalf("MaxAmount: got %d", req.MaxAmount)
	}
	if req.Expiry != 30*24*3600 {
		t.Fatalf("Expiry: got %d", req.Expiry)
	}
	if req.BudgetRenewal != "monthly" {
		t.Fatalf("BudgetRenewal: got %s", req.BudgetRenewal)
	}
	// The identity proof must be bound to hubPubkey via its d-tag.
	var ev struct {
		Tags [][]string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(req.IdentityEvent), &ev); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tag := range ev.Tags {
		if len(tag) == 2 && tag[0] == "d" && tag[1] == hubPubkey {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a d-tag bound to hubPubkey, got tags=%v", ev.Tags)
	}
}

func TestCreateCircleWalletParams_ParseResult_DecryptsPairingURI(t *testing.T) {
	memberPrivHex, memberPubHex := generateTestKeypair(t)
	hubPrivHex, hubPubHex := generateTestKeypair(t)

	// Simulate the server side: encrypt the pairing URI to the member's own
	// pubkey using the Hub's own privkey.
	ciphertext := encryptForTest(t, hubPrivHex, memberPubHex, "nostr+walletconnect://walletpubkey?relay=wss://r&secret=abc")

	p := CreateCircleWalletParams{Credential: BySigning(memberPrivHex), MaxAmountMillis: 1000}
	raw, err := json.Marshal(createCircleWalletResponseWire{
		EncryptedPairingURI: ciphertext,
		WalletPubkey:        "walletpubkey",
		ExpiresAt:           1234,
		BudgetRenewal:       "never",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.ParseResult(hubPubHex, raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if resp.PairingURI != "nostr+walletconnect://walletpubkey?relay=wss://r&secret=abc" {
		t.Fatalf("PairingURI: got %q", resp.PairingURI)
	}
	if resp.WalletPubkey != "walletpubkey" || resp.ExpiresAt != 1234 {
		t.Fatalf("resp: %+v", resp)
	}
}

func encryptForTest(t *testing.T, fromPrivHex, toPubHex, plaintext string) string {
	t.Helper()
	privBytes, err := hex.DecodeString(fromPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(toPubHex)
	if err != nil {
		t.Fatal(err)
	}
	toPub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nip44.GenerateConversationKey(priv, toPub)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := nip44.Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}
