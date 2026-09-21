package nipcash

import (
	"encoding/json"
	"testing"
)

func TestCashConsolidateParams_Request_TooFewSources(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	p := CashConsolidateParams{
		Sources: []Source{From(randomKeyHex(t), 1000, BySigning(privKeyHex))},
		To:      Pubkey("merged"),
	}
	if _, err := p.Request(); err != ErrTooFewSources {
		t.Fatalf("got %v, want ErrTooFewSources", err)
	}
}

func TestCashConsolidateParams_Request_BearerSourceRejected(t *testing.T) {
	p := CashConsolidateParams{
		Sources: []Source{
			From(randomKeyHex(t), 1000, BySecret("s1")),
			From(randomKeyHex(t), 1000, BySecret("s2")),
		},
		To: Pubkey("merged"),
	}
	if _, err := p.Request(); err != ErrBearerSource {
		t.Fatalf("got %v, want ErrBearerSource", err)
	}
}

func TestCashConsolidateParams_Request_NilTargetRejected(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	p := CashConsolidateParams{
		Sources: []Source{
			From(randomKeyHex(t), 1000, BySigning(privKeyHex)),
			From(randomKeyHex(t), 1000, BySigning(privKeyHex)),
		},
		To: nil,
	}
	if _, err := p.Request(); err != ErrConsolidateTargetInvalid {
		t.Fatalf("got %v, want ErrConsolidateTargetInvalid", err)
	}
}

func TestCashConsolidateParams_Request_BearerTargetAccepted(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	bt := NewBearerTarget()
	p := CashConsolidateParams{
		Sources: []Source{
			From(randomKeyHex(t), 1000, BySigning(privKeyHex)),
			From(randomKeyHex(t), 1000, BySigning(privKeyHex)),
		},
		To: bt,
	}
	req, err := p.Request()
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.NewIdentity.IdentityType != identityTypeBearer || req.NewIdentity.IdentityValue != bt.identityValue() {
		t.Fatalf("NewIdentity: %+v, want bearer/%s", req.NewIdentity, bt.identityValue())
	}
}

func TestCashConsolidateParams_Request_ConnectionKeyTargetAccepted(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	p := CashConsolidateParams{
		Sources: []Source{
			From(randomKeyHex(t), 1000, BySigning(privKeyHex)),
			From(randomKeyHex(t), 1000, BySigning(privKeyHex)),
		},
		To: ConnectionKey("discord", "someone", "iapub"),
	}
	req, err := p.Request()
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.NewIdentity.IdentityType != identityTypeConnectionKey {
		t.Fatalf("NewIdentity.IdentityType: got %s, want connection_key", req.NewIdentity.IdentityType)
	}
	if req.NewIdentity.IAPubkey != "iapub" {
		t.Fatalf("NewIdentity.IAPubkey: got %q, want \"iapub\" — previously dropped entirely, must now pass through", req.NewIdentity.IAPubkey)
	}
}

func TestCashConsolidateParams_Request_HappyPath(t *testing.T) {
	privKeyHex, pubKeyHex := generateTestKeypair(t)
	walletA, walletB := randomKeyHex(t), randomKeyHex(t)
	p := CashConsolidateParams{
		Sources: []Source{
			From(walletA, 10_000, BySigning(privKeyHex)),
			From(walletB, 15_000, BySigning(privKeyHex)),
		},
		To:            Pubkey(pubKeyHex),
		MintSignature: true,
	}
	req, err := p.Request()
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if len(req.Sources) != 2 {
		t.Fatalf("Sources: got %d, want 2", len(req.Sources))
	}
	if req.Sources[0].WalletPubkey != walletA || req.Sources[1].WalletPubkey != walletB {
		t.Fatalf("source wallet pubkeys: %+v", req.Sources)
	}
	for _, s := range req.Sources {
		if s.IdentityType != identityTypePubkey || s.IdentityValue != pubKeyHex || s.IdentityEvent == "" {
			t.Fatalf("source proof: %+v", s)
		}
	}
	if req.NewIdentity.IdentityValue != pubKeyHex {
		t.Fatalf("NewIdentity: %+v", req.NewIdentity)
	}
	if !req.MintSignature {
		t.Fatal("expected MintSignature true")
	}
}

func TestByProof_ParsesIdentityValueFromEvent(t *testing.T) {
	privKeyHex, pubKeyHex := generateTestKeypair(t)
	// Build a real signed proof the way BySigning would, to hand to
	// ByProof as a "captured earlier" credential.
	signing := BySigning(privKeyHex)
	_, _, identityEvent, _, _, err := signing.buildProof(proofBinding{
		WalletPubkey: randomKeyHex(t), NewIdentityHash: "hash", AmountMillis: uint64Ptr(1000),
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := ByProof(identityEvent)
	if err != nil {
		t.Fatalf("ByProof: %v", err)
	}
	identityType, identityValue, gotEvent, _, _, err := cred.buildProof(proofBinding{})
	if err != nil {
		t.Fatal(err)
	}
	if identityType != identityTypePubkey || identityValue != pubKeyHex {
		t.Fatalf("got type=%s value=%s, want pubkey=%s", identityType, identityValue, pubKeyHex)
	}
	if string(gotEvent) != string(identityEvent) {
		t.Fatal("ByProof must return the captured proof verbatim, not re-sign")
	}
}

func TestByProof_MalformedJSON(t *testing.T) {
	if _, err := ByProof([]byte("not json")); err == nil {
		t.Fatal("expected an error for malformed captured proof JSON")
	}
}

// cash_consolidate keys new_wallet_token's delivery to the target, not the
// caller — ParseResult must only decrypt when the target is the caller's
// own pubkey, and otherwise return the wire value as-is (plaintext for
// bearer/connection_key targets, still-opaque ciphertext for a third
// party's pubkey) without erroring.

func TestCashConsolidateParams_ParseResult_SelfTarget_Decrypts(t *testing.T) {
	callerPrivHex, callerPubHex := generateTestKeypair(t)
	newWalletPrivHex, newWalletPubHex := generateTestKeypair(t)

	// Self-consolidate: new_identity == the caller's own pubkey, so the Hub
	// encrypts to the same pubkey the caller's own credential can decrypt
	// with.
	ciphertext := encryptForTest(t, newWalletPrivHex, callerPubHex, "lokicash1thetoken")

	p := CashConsolidateParams{
		Sources: []Source{From(randomKeyHex(t), 1000, BySigning(callerPrivHex))},
		To:      Pubkey(callerPubHex),
	}
	raw, err := json.Marshal(cashConsolidateResponseWire{
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

func TestCashConsolidateParams_ParseResult_ThirdPartyPubkeyTarget_Decrypts(t *testing.T) {
	callerPrivHex, callerPubHex := generateTestKeypair(t)
	_, carolPubHex := generateTestKeypair(t)
	newWalletPrivHex, newWalletPubHex := generateTestKeypair(t)

	// The Hub encrypts to the CALLER even though the target is Carol (same
	// convention as cash_transfer) — the caller decrypts it themselves and
	// hands Carol a plain token out of band.
	ciphertext := encryptForTest(t, newWalletPrivHex, callerPubHex, "lokicash1forcarol")

	p := CashConsolidateParams{
		Sources: []Source{From(randomKeyHex(t), 1000, BySigning(callerPrivHex))},
		To:      Pubkey(carolPubHex),
	}
	raw, err := json.Marshal(cashConsolidateResponseWire{
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
	if result.NewWalletToken != "lokicash1forcarol" {
		t.Fatalf("NewWalletToken: got %q, want decrypted plaintext", result.NewWalletToken)
	}
}

func TestCashConsolidateParams_ParseResult_UndecryptableDelivery_FallsBackToRawValue(t *testing.T) {
	callerPrivHex, _ := generateTestKeypair(t)
	_, carolPubHex := generateTestKeypair(t)
	newWalletPrivHex, newWalletPubHex := generateTestKeypair(t)

	// Encrypted to a key the caller doesn't hold — e.g. a Hub still keying
	// pubkey-target delivery some other way. Decryption fails; ParseResult
	// must not error, just preserve the raw value instead of losing it.
	ciphertext := encryptForTest(t, newWalletPrivHex, carolPubHex, "lokicash1forcarol")

	p := CashConsolidateParams{
		Sources: []Source{From(randomKeyHex(t), 1000, BySigning(callerPrivHex))},
		To:      Pubkey(carolPubHex),
	}
	raw, err := json.Marshal(cashConsolidateResponseWire{
		AmountMillis:    1000,
		NewWalletPubkey: newWalletPubHex,
		NewWalletToken:  ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult must not error on an undecryptable delivery: %v", err)
	}
	if result.NewWalletToken != ciphertext {
		t.Fatalf("NewWalletToken: got %q, want the raw ciphertext preserved as-is", result.NewWalletToken)
	}
}

func TestCashConsolidateParams_ParseResult_BearerTarget_PassesThroughPlaintext(t *testing.T) {
	callerPrivHex, _ := generateTestKeypair(t)
	bt := NewBearerTarget()

	p := CashConsolidateParams{
		Sources: []Source{From(randomKeyHex(t), 1000, BySigning(callerPrivHex))},
		To:      bt,
	}
	raw, err := json.Marshal(cashConsolidateResponseWire{
		AmountMillis:    1000,
		NewWalletPubkey: randomKeyHex(t),
		NewWalletToken:  "lokicash1plaintext",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if result.NewWalletToken != "lokicash1plaintext" {
		t.Fatalf("NewWalletToken: got %q, want the plaintext value passed through unchanged", result.NewWalletToken)
	}
}

func TestCashConsolidateParams_ParseResult_ConnectionKeyTarget_PassesThroughPlaintext(t *testing.T) {
	callerPrivHex, _ := generateTestKeypair(t)

	p := CashConsolidateParams{
		Sources: []Source{From(randomKeyHex(t), 1000, BySigning(callerPrivHex))},
		To:      ConnectionKey("discord", "someone", "iapub"),
	}
	raw, err := json.Marshal(cashConsolidateResponseWire{
		AmountMillis:    1000,
		NewWalletPubkey: randomKeyHex(t),
		NewWalletToken:  "lokicash1plaintext",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if result.NewWalletToken != "lokicash1plaintext" {
		t.Fatalf("NewWalletToken: got %q, want the plaintext value passed through unchanged", result.NewWalletToken)
	}
}
