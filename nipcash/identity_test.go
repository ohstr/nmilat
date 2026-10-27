package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
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
	_ Recipient = (*CashTarget)(nil)
	_ Target    = (*CashTarget)(nil)
)

func TestPubkeyConnectionKeyAnyone_IdentityTypes(t *testing.T) {
	pk := Pubkey("aa")
	if pk.identityType() != identityTypePubkey || pk.identityValue() != "aa" {
		t.Fatalf("Pubkey: got type=%s value=%s", pk.identityType(), pk.identityValue())
	}

	ck, err := ConnectionKey("discord", "80351110224678912", "iapub")
	if err != nil {
		t.Fatal(err)
	}
	if ck.identityType() != identityTypeConnectionKey || ck.iaPubkey() != "iapub" {
		t.Fatalf("ConnectionKey: got type=%s ia=%s", ck.identityType(), ck.iaPubkey())
	}
	// Same (platform, externalID) must always hash to the same connection
	// key — ConnectionKey is deterministic (nipIC.NewConnectionKey).
	ck2, _ := ConnectionKey("discord", "80351110224678912", "iapub")
	if ck.identityValue() != ck2.identityValue() {
		t.Fatal("ConnectionKey must be deterministic for the same (platform, externalID)")
	}

	cash := targetFields(mustCashTarget(t))
	if cash.identityType() != identityTypeCash || !ValidCommitment(cash.identityValue()) {
		t.Fatalf("CashTarget: got type=%s value=%s", cash.identityType(), cash.identityValue())
	}
}

func TestResolvedConnectionKey_MatchesConnectionKeyWithoutRehashing(t *testing.T) {
	// ConnectionKey hashes (platform, externalID) internally; a caller who
	// only has the already-hashed key (e.g. decoded from an nconnection1...
	// string) has no externalID to feed it. ResolvedConnectionKey must
	// produce an identical identity_type/identity_value/ia_pubkey given
	// that same key directly, with no external ID involved at all.
	viaExternalID, err := ConnectionKey("discord", "80351110224678912", "iapub")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := nipIC.NewConnectionKey("discord", "80351110224678912")
	viaKey, err := ResolvedConnectionKey(key, "discord", "iapub")
	if err != nil {
		t.Fatal(err)
	}

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
	bt := mustCashTarget(t)
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
	other := mustCashTarget(t)
	if bt.Secret() == other.Secret() {
		t.Fatal("NewCashTarget must generate a fresh secret every call")
	}
}

// NIP-CASH §Cash-Mode Slices: the wire identity_value is sha256 of the secret's
// raw bytes. Any other commitment funds a slice no holder of the secret can spend,
// and "differs from the secret" alone would not notice.
func TestNewCashTarget_CommitmentIsSHA256OfSecret(t *testing.T) {
	for range 8 {
		bt := mustCashTarget(t)
		raw, err := hex.DecodeString(bt.Secret())
		if err != nil {
			t.Fatalf("Secret is not hex: %v", err)
		}
		sum := sha256.Sum256(raw)
		if got, want := Target(bt).(targetFields).identityValue(), hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("commitment = %s, want hex(sha256(secret)) = %s", got, want)
		}
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

// T05-17, T05-19: typed input must be canonical; a key from an nconnection needs
// its IA; a resolved key must be 64 lowercase hex.
func TestConnectionKeyConstructors_Refuse(t *testing.T) {
	if _, err := ConnectionKey("discord", "080351110224678912", "ia"); !errors.Is(err, nipIC.ErrNotCanonical) {
		t.Errorf("leading zero: %v", err)
	}
	if _, err := ConnectionKey("github", "Alice", "ia"); !errors.Is(err, nipIC.ErrTypedInputNotCanonical) {
		t.Errorf("typed github: %v", err)
	}
	key, _ := nipIC.ConnectionKeyFromAttested("github", "Alice")
	if _, err := ConnectionKeyFromNConnection(key, "github", ""); !errors.Is(err, ErrMissingIAPubkey) {
		t.Errorf("nconnection without IA: %v", err)
	}
	if _, err := ResolvedConnectionKey(nipIC.ConnectionKey(strings.ToUpper(string(key))), "github", "ia"); err == nil {
		t.Error("uppercase key resolved")
	}
	if id, err := ConnectionKeyFromNConnection(key, "github", "ia"); err != nil || id.identityValue() != string(key) {
		t.Errorf("nconnection key: %v", err)
	}
}
