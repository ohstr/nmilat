package nipcash

import (
	"testing"

	"github.com/ohstr/nmilat/nipIC"
)

// Compile-time checks of the Recipient/Target split (see Target's own doc
// comment): namedIdentity (Pubkey/ConnectionKey) satisfies both; cashRecipient
// (Anyone()) satisfies only Recipient; *CashTarget satisfies only Target.
// There's no way to assert the NEGATIVE ("cashRecipient does NOT satisfy
// Target") in Go's type system directly — the real guarantee is that
// mint_cash.go/cash_transfer.go's own field types (Recipient vs. Target)
// simply won't compile against the wrong constructor's return value.
var (
	_ Recipient = namedIdentity{}
	_ Target    = namedIdentity{}
	_ Recipient = cashRecipient{}
	_ Target    = (*CashTarget)(nil)
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
	if anyone.identityType() != identityTypeCash {
		t.Fatalf("Anyone: got type=%s", anyone.identityType())
	}
}

func TestResolvedConnectionKey_MatchesConnectionKeyWithoutRehashing(t *testing.T) {
	// ConnectionKey hashes (platform, externalID) internally; a caller who
	// only has the already-hashed key (e.g. decoded from an nconnection1...
	// string) has no externalID to feed it. ResolvedConnectionKey must
	// produce an identical identity_type/identity_value/ia_pubkey given
	// that same key directly, with no external ID involved at all.
	viaExternalID := ConnectionKey("discord", "some.user", "iapub")
	key := nipIC.NewConnectionKey("discord", "some.user")
	viaKey := ResolvedConnectionKey(key, "discord", "iapub")

	if viaKey.identityType() != viaExternalID.identityType() {
		t.Fatalf("identityType mismatch: got %s, want %s", viaKey.identityType(), viaExternalID.identityType())
	}
	if viaKey.identityValue() != viaExternalID.identityValue() {
		t.Fatalf("identityValue mismatch: got %s, want %s", viaKey.identityValue(), viaExternalID.identityValue())
	}
	if viaKey.iaPubkey() != "iapub" {
		t.Fatalf("iaPubkey: got %s, want iapub", viaKey.iaPubkey())
	}
}

func TestNewCashTarget_SecretAndCommitmentDiffer(t *testing.T) {
	bt := NewCashTarget()
	f := Target(bt).(targetFields)
	if f.identityType() != identityTypeCash {
		t.Fatalf("identityType: got %s", f.identityType())
	}
	if bt.Secret() == f.identityValue() {
		t.Fatal("the wire identity_value must be a commitment, never the raw secret")
	}
	if len(bt.Secret()) != 64 {
		t.Fatalf("Secret: got %d hex chars, want 64 (32 bytes)", len(bt.Secret()))
	}

	// Two calls must never collide.
	other := NewCashTarget()
	if bt.Secret() == other.Secret() {
		t.Fatal("NewCashTarget must generate a fresh secret every call")
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
