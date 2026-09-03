package nipcash

import "testing"

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

func TestCashConsolidateParams_Request_TargetMustBePubkey(t *testing.T) {
	privKeyHex, _ := generateTestKeypair(t)
	p := CashConsolidateParams{
		Sources: []Source{
			From(randomKeyHex(t), 1000, BySigning(privKeyHex)),
			From(randomKeyHex(t), 1000, BySigning(privKeyHex)),
		},
		To: ConnectionKey("discord", "someone", "iapub"),
	}
	if _, err := p.Request(); err != ErrConsolidateTargetNotPubkey {
		t.Fatalf("got %v, want ErrConsolidateTargetNotPubkey", err)
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
