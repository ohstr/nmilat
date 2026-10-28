package nipcash

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip44"
)

func TestCashTransferParams_Request_FullTransfer(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	p := CashTransferParams{RequestID: testRID,
		Credential:    BySigning(privKeyHex),
		To:            Pubkey("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
		CurrentAmount: 15000,
	}
	req, err := p.Request(randomKeyHex(t))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.AmountMillis != nil {
		t.Fatalf("a full transfer must omit amount_millis, got %v", *req.AmountMillis)
	}
	if req.NewIdentity.IdentityValue != "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" {
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
	p := CashTransferParams{RequestID: testRID,
		Credential:    BySigning(privKeyHex),
		To:            Pubkey("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
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
	p := CashTransferParams{RequestID: testRID, Credential: BySigning(privKeyHex), To: Pubkey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), CurrentAmount: 1000}
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

	p := CashTransferParams{RequestID: testRID, Credential: BySigning(callerPrivHex), To: Pubkey("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), CurrentAmount: 1000}
	raw, err := json.Marshal(cashTransferResponseWire{
		AmountMillis:    1000,
		NewWalletPubkey: newWalletPubHex,
		NewWalletToken:  TokenOrTombstone{Token: ciphertext},
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

func TestCashTransferResult_RecipientToken_InPlaceFallsBackToOriginal(t *testing.T) {
	result := &CashTransferResult{NewWalletToken: ""}
	got, _ := result.RecipientToken("lokicash1original")
	if got != "lokicash1original" {
		t.Fatalf("RecipientToken() = %q, want the original token (in-place reassignment)", got)
	}
}

func TestCashTransferResult_RecipientToken_SpinOffUsesNewWalletToken(t *testing.T) {
	result := &CashTransferResult{NewWalletToken: "lokicash1spunoff"}
	got, _ := result.RecipientToken("lokicash1original")
	if got != "lokicash1spunoff" {
		t.Fatalf("RecipientToken() = %q, want the spun-off NewWalletToken", got)
	}
}

func TestCashTransferResult_RecipientToken_PartialSplitUsesNewWalletToken(t *testing.T) {
	// Both NewWalletToken and RemainderWalletToken set: the caller's own
	// remainder is a separate concern (RemainderWalletToken), not
	// RecipientToken's — this only ever answers "what does the recipient
	// need."
	result := &CashTransferResult{NewWalletToken: "lokicash1carvedoff", RemainderWalletToken: "lokicash1remainder"}
	got, _ := result.RecipientToken("lokicash1original")
	if got != "lokicash1carvedoff" {
		t.Fatalf("RecipientToken() = %q, want the carved-off NewWalletToken, not the caller's own remainder", got)
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

// A spin-off always carries its token: without one RecipientToken errors, as a
// *BillGone when a lookup answered the new bill's tombstone.
func TestCashTransferResult_RecipientToken_SpinOffWithoutToken(t *testing.T) {
	r := &CashTransferResult{NewWalletPubkey: strings.Repeat("ab", 32)}
	if tok, err := r.RecipientToken("orig"); err == nil || tok != "" {
		t.Fatalf("RecipientToken = %q, %v; want an error", tok, err)
	}
	r.NewWalletTombstone = &Tombstone{Status: StatusSpent, Reason: ReasonRedeemed}
	var gone *BillGone
	if _, err := r.RecipientToken("orig"); !errors.As(err, &gone) || gone.Tombstone.Reason != ReasonRedeemed {
		t.Fatalf("err = %v, want *BillGone", err)
	}
}

func TestChainForHRP(t *testing.T) {
	for hrp, want := range map[string]string{"satscash": "bitcoin", "SATSCASH": "bitcoin", "lokicash": "flokicoin"} {
		if got, ok := ChainForHRP(hrp); !ok || got != want {
			t.Errorf("ChainForHRP(%q) = %q, %v", hrp, got, ok)
		}
	}
	if _, ok := ChainForHRP("cashhub"); ok {
		t.Error("cashhub has no chain")
	}
}

// CASH-XFER-05: WithRemainder fills a missing remainder target for a partial
// split of a cash source only, keeps a supplied one, and the result builds.
func TestCashTransferParams_WithRemainder(t *testing.T) {
	source, err := NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	to, _ := NewCashTarget()
	half, full := uint64(500), uint64(1000)
	p := CashTransferParams{Credential: BySecret(source.Secret()), To: to, CurrentAmount: 1000, SplitAmount: &half,
		RequestID: strings.Repeat("ab", 32)}
	if !p.NeedsRemainder() {
		t.Fatal("a partial cash split needs a remainder")
	}
	got, err := p.WithRemainder()
	if err != nil || got.RemainderTarget == nil || CommitmentsEqual(got.RemainderTarget.Commitment(), source.Commitment()) {
		t.Fatalf("WithRemainder = %+v, %v", got.RemainderTarget, err)
	}
	req, err := got.Request(strings.Repeat("cd", 32))
	if err != nil || req.RemainderCommitment != got.RemainderTarget.Commitment() {
		t.Fatalf("Request = %+v, %v", req, err)
	}
	pc, err := got.Pending(strings.Repeat("cd", 32))
	if err != nil || len(pc.Secrets) != 2 || pc.Secrets[1].Role != SecretRoleRemainder || pc.Secrets[1].Secret != got.RemainderTarget.Secret() {
		t.Fatalf("Pending secrets = %+v, %v", pc.Secrets, err)
	}
	kept, _ := got.WithRemainder()
	if kept.RemainderTarget != got.RemainderTarget {
		t.Fatal("a supplied remainder target was replaced")
	}
	p.SplitAmount = &full
	if p.NeedsRemainder() {
		t.Fatal("a full transfer needs no remainder")
	}
	if same, _ := p.WithRemainder(); same.RemainderTarget != nil {
		t.Fatal("a full transfer got a remainder target")
	}
}
