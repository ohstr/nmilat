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

const testPairingURI = "nostr+walletconnect://walletpubkey?relay=wss://r&secret=abc"

func TestCreateCircleWalletParams_ParseResult_DecryptsDetails(t *testing.T) {
	memberPrivHex, memberPubHex := generateTestKeypair(t)
	hubPrivHex, hubPubHex := generateTestKeypair(t)

	// Simulate the server side: the whole result, not just the pairing URI, is
	// encrypted to the member's own pubkey using the Hub's own privkey.
	details, err := json.Marshal(circleWalletDetailsWire{
		PairingURI:    testPairingURI,
		WalletPubkey:  "walletpubkey",
		ExpiresAt:     1234,
		BudgetRenewal: "never",
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := encryptForTest(t, hubPrivHex, memberPubHex, string(details))

	p := CreateCircleWalletParams{Credential: BySigning(memberPrivHex), MaxAmountMillis: 1000}
	raw, err := json.Marshal(createCircleWalletResponseWire{EncryptedDetails: ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.ParseResult(hubPubHex, raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if resp.PairingURI != testPairingURI {
		t.Fatalf("PairingURI: got %q", resp.PairingURI)
	}
	if resp.WalletPubkey != "walletpubkey" || resp.ExpiresAt != 1234 || resp.BudgetRenewal != "never" {
		t.Fatalf("resp: %+v", resp)
	}
}

// TestCreateCircleWalletParams_ParseResult_NoDetailsIsAnError pins that a
// response with nothing to decrypt fails loudly. Returning a zero-valued
// CreateCircleWalletResponse would hand the caller a blank wallet pubkey and
// blank terms that read exactly like real ones.
func TestCreateCircleWalletParams_ParseResult_NoDetailsIsAnError(t *testing.T) {
	memberPrivHex, _ := generateTestKeypair(t)
	_, hubPubHex := generateTestKeypair(t)

	p := CreateCircleWalletParams{Credential: BySigning(memberPrivHex)}
	if _, err := p.ParseResult(hubPubHex, []byte(`{}`)); err == nil {
		t.Fatal("expected an error for a response with no encrypted_details")
	}
}

// TestCreateCircleWalletParams_ParseResult_CoMemberCannotDecrypt is the reason
// the details are nested at all: a circle join goes over the SHARED circlehub
// connection, so another member sees this exact response.
func TestCreateCircleWalletParams_ParseResult_CoMemberCannotDecrypt(t *testing.T) {
	_, memberPubHex := generateTestKeypair(t)
	coMemberPrivHex, _ := generateTestKeypair(t)
	hubPrivHex, hubPubHex := generateTestKeypair(t)

	details, err := json.Marshal(circleWalletDetailsWire{
		PairingURI:   testPairingURI,
		WalletPubkey: "walletpubkey",
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := encryptForTest(t, hubPrivHex, memberPubHex, string(details))
	raw, err := json.Marshal(createCircleWalletResponseWire{EncryptedDetails: ciphertext})
	if err != nil {
		t.Fatal(err)
	}

	coMember := CreateCircleWalletParams{Credential: BySigning(coMemberPrivHex)}
	if _, err := coMember.ParseResult(hubPubHex, raw); err == nil {
		t.Fatal("a co-member of the circle must not be able to decrypt another member's details")
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
