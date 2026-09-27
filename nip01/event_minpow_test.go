package nip01

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
)

func minPowTestKey(t *testing.T) string {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(priv.Serialize())
}

// TestVerify_MinPowDifficulty_CheckedBeforeSignature is the security property,
// and it is about ORDERING rather than about PoW itself.
//
// Signature verification is the most expensive step in Verify — hundreds of
// microseconds of secp256k1. A difficulty floor enforced *after* it cannot
// defend a relay against flooding, because the flood has already been paid for
// by the time the floor is consulted.
//
// The event here has a well-formed ID that genuinely matches its contents, a
// deliberately corrupted signature, and difficulty below the floor. If the floor
// is evaluated first, Verify reports insufficient PoW. If the ordering ever
// regresses, it reports "invalid signature" instead and this test fails.
func TestVerify_MinPowDifficulty_CheckedBeforeSignature(t *testing.T) {
	privHex := minPowTestKey(t)

	ev := NewEvent(1, "ordering check")
	if err := ev.Sign(privHex); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Corrupt the signature while leaving ID and content consistent.
	sigBytes, err := hex.DecodeString(ev.Sig)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes[0] ^= 0xff
	ev.Sig = hex.EncodeToString(sigBytes)

	// Sanity: without a floor, this event is rejected for its signature. That
	// is what makes the assertion below meaningful.
	err = ev.Verify(WithoutPowCheck())
	if err == nil {
		t.Fatal("expected the corrupted signature to be rejected")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected a signature error without a pow floor, got %v", err)
	}

	// With a floor this event cannot meet, PoW must be what rejects it —
	// proving the schnorr verify was never reached.
	err = ev.Verify(WithoutPowCheck(), WithMinPowDifficulty(24))
	var powErr *InsufficientPowError
	if !errors.As(err, &powErr) {
		t.Fatalf("expected an InsufficientPowError (pow must be checked before the signature), got %v", err)
	}
	if powErr.Want != 24 {
		t.Errorf("Want = %d, expected the configured floor 24", powErr.Want)
	}
	if powErr.Got >= 24 {
		t.Errorf("Got = %d, which should be below the floor", powErr.Got)
	}
	// The message is part of the relay's wire contract.
	if !strings.HasPrefix(powErr.Error(), "pow: ") {
		t.Errorf("error message = %q, want a \"pow: \" prefix", powErr.Error())
	}
}

// TestVerify_MinPowDifficulty_ZeroIsDisabled pins that the option is opt-in: a
// zero floor must not reject ordinary unmined events.
func TestVerify_MinPowDifficulty_ZeroIsDisabled(t *testing.T) {
	privHex := minPowTestKey(t)
	ev := NewEvent(1, "unmined")
	if err := ev.Sign(privHex); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := ev.Verify(WithMinPowDifficulty(0)); err != nil {
		t.Fatalf("a zero floor must not reject an unmined event: %v", err)
	}
}

// TestVerify_MinPowDifficulty_IDMustMatchContentFirst closes the obvious bypass:
// difficulty is a property of the ID, so an unvalidated ID is only a claim. A
// flooder must not be able to assert an ID full of leading zeros that its own
// content does not hash to and thereby clear the floor for free.
func TestVerify_MinPowDifficulty_IDMustMatchContentFirst(t *testing.T) {
	privHex := minPowTestKey(t)
	ev := NewEvent(1, "claimed id")
	if err := ev.Sign(privHex); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// An ID of all zeros trivially "meets" any floor, but is not this event's hash.
	ev.ID = strings.Repeat("0", 64)

	err := ev.Verify(WithoutPowCheck(), WithMinPowDifficulty(16))
	if err == nil {
		t.Fatal("a forged high-difficulty ID must not pass verification")
	}
	var powErr *InsufficientPowError
	if errors.As(err, &powErr) {
		t.Fatal("the forged ID was measured for difficulty; the ID/content match must be checked first")
	}
	if !strings.Contains(err.Error(), "ID mismatch") {
		t.Errorf("expected an ID mismatch error, got %v", err)
	}
}
