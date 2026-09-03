package nipcash

import "testing"

// Compile-time checks of the Recipient/Target split (see Target's own doc
// comment): namedIdentity (Pubkey/ConnectionKey) satisfies both; bearerRecipient
// (Anyone()) satisfies only Recipient; *BearerTarget satisfies only Target.
// There's no way to assert the NEGATIVE ("bearerRecipient does NOT satisfy
// Target") in Go's type system directly — the real guarantee is that
// mint_cash.go/cash_transfer.go's own field types (Recipient vs. Target)
// simply won't compile against the wrong constructor's return value.
var (
	_ Recipient = namedIdentity{}
	_ Target    = namedIdentity{}
	_ Recipient = bearerRecipient{}
	_ Target    = (*BearerTarget)(nil)
)

func TestPubkeyConnectionKeyAnyone_IdentityTypes(t *testing.T) {
	pk := Pubkey("aa")
	if pk.identityType() != identityTypePubkey || pk.identityValue() != "aa" {
		t.Fatalf("Pubkey: got type=%s value=%s", pk.identityType(), pk.identityValue())
	}

	ck := ConnectionKey("discord", "some.user", "iapub")
	if ck.identityType() != identityTypeConnectionKey || ck.iaPubkey() != "iapub" {
		t.Fatalf("ConnectionKey: got type=%s ia=%s", ck.identityType(), ck.iaPubkey())
	}
	// Same (platform, externalID) must always hash to the same connection
	// key — ConnectionKey is deterministic (nipIC.NewConnectionKey).
	ck2 := ConnectionKey("discord", "some.user", "iapub")
	if ck.identityValue() != ck2.identityValue() {
		t.Fatal("ConnectionKey must be deterministic for the same (platform, externalID)")
	}

	anyone := Anyone().(targetFields)
	if anyone.identityType() != identityTypeBearer {
		t.Fatalf("Anyone: got type=%s", anyone.identityType())
	}
}

func TestNewBearerTarget_SecretAndCommitmentDiffer(t *testing.T) {
	bt := NewBearerTarget()
	f := Target(bt).(targetFields)
	if f.identityType() != identityTypeBearer {
		t.Fatalf("identityType: got %s", f.identityType())
	}
	if bt.Secret() == f.identityValue() {
		t.Fatal("the wire identity_value must be a commitment, never the raw secret")
	}
	if len(bt.Secret()) != 64 {
		t.Fatalf("Secret: got %d hex chars, want 64 (32 bytes)", len(bt.Secret()))
	}

	// Two calls must never collide.
	other := NewBearerTarget()
	if bt.Secret() == other.Secret() {
		t.Fatal("NewBearerTarget must generate a fresh secret every call")
	}
}

func TestSend_PairsRecipientWithAmount(t *testing.T) {
	a := Send(Pubkey("aa"), 5000)
	if a.AmountMillis != 5000 {
		t.Fatalf("AmountMillis: got %d, want 5000", a.AmountMillis)
	}
	f := a.Recipient.(targetFields)
	if f.identityValue() != "aa" {
		t.Fatalf("Recipient: got %s, want aa", f.identityValue())
	}
}
