package nipcash

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip44"
)

func TestCashTransferParams_Request_FullTransfer(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	p := CashTransferParams{
		Credential:    BySigning(privKeyHex),
		To:            Pubkey("recipienthex"),
		CurrentAmount: 15000,
	}
	req, err := p.Request(randomKeyHex(t))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.AmountMillis != nil {
		t.Fatalf("a full transfer must omit amount_millis, got %v", *req.AmountMillis)
	}
	if req.NewIdentity.IdentityValue != "recipienthex" {
		t.Fatalf("NewIdentity: got %+v", req.NewIdentity)
	}
	// The proof itself must still bind to a concrete amount (the slice's
	// current full amount) even though the wire request omits it — decode
	// the signed proof and check its amount_millis tag directly.
	var ev struct {
		Tags [][]string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(req.IdentityEvent), &ev); err != nil {
		t.Fatalf("unmarshal identity_event: %v", err)
	}
	found := false
	for _, tag := range ev.Tags {
		if len(tag) == 2 && tag[0] == "amount_millis" && tag[1] == "15000" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the proof's amount_millis tag to bind to CurrentAmount (15000): tags=%v", ev.Tags)
	}
}

func TestCashTransferParams_Request_Split(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	split := uint64(5000)
	p := CashTransferParams{
		Credential:    BySigning(privKeyHex),
		To:            Pubkey("recipienthex"),
		CurrentAmount: 15000,
		SplitAmount:   &split,
	}
	req, err := p.Request(randomKeyHex(t))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.AmountMillis == nil || *req.AmountMillis != 5000 {
		t.Fatalf("AmountMillis: got %v, want 5000", req.AmountMillis)
	}
}

func TestCashTransferParams_ParseResult_InPlace(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	p := CashTransferParams{Credential: BySigning(privKeyHex), To: Pubkey("aa"), CurrentAmount: 1000}
	raw := []byte(`{"amount_millis":1000,"identity_type":"pubkey","identity_value":"aa"}`)
	result, err := p.ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if result.NewWalletToken != "" {
		t.Fatalf("an in-place reassignment must produce no new wallet token: %+v", result)
	}
}

func TestCashTransferParams_ParseResult_SpinOff_DecryptsToken(t *testing.T) {
	callerPrivHex, callerPubHex := generateTestKeypair(t)
	newWalletPrivHex, newWalletPubHex := generateTestKeypair(t)

	// Simulate the server side: encrypt a token to the caller's pubkey using
	// the new wallet's own privkey — the same nested-delivery key derivation
	// decryptFromPubkey (the caller side) must invert.
	ciphertext := encryptForTest(t, newWalletPrivHex, callerPubHex, "lokicash1thetoken")

	p := CashTransferParams{Credential: BySigning(callerPrivHex), To: Pubkey("bb"), CurrentAmount: 1000}
	raw, err := json.Marshal(cashTransferResponseWire{
		AmountMillis:    1000,
		NewWalletPubkey: newWalletPubHex,
		NewWalletToken:  ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if result.NewWalletToken != "lokicash1thetoken" {
		t.Fatalf("NewWalletToken: got %q, want decrypted plaintext", result.NewWalletToken)
	}
}

// encryptForTest mirrors decryptFromPubkey's own key derivation, in the
// opposite direction, to build a delivery ciphertext a real server would
// produce — ECDH is commutative, so deriving from (recipientPriv,
// senderPub) here must produce the same conversation key
// decryptFromPubkey(senderPriv, recipientPub, ...) derives on the other end.
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
