package nipcash

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipIC"
)

func buildTestAttestation(t *testing.T, iaPrivHex, userPubHex string, connectionKey nipIC.ConnectionKey, expirationDays int) *nipIC.Attestation {
	t.Helper()
	ev, err := nipIC.NewAttestation(nipIC.AttestationParams{
		PrivateKey:     iaPrivHex,
		ConnectionKey:  connectionKey,
		UserPubkey:     userPubHex,
		Platform:       "discord",
		ExpirationDays: expirationDays,
		Evidence:       nipIC.Evidence{Platform: "discord", UserID: "12345"},
	})
	if err != nil {
		t.Fatal(err)
	}
	att, err := nipIC.ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func TestBySigningConnectionKey_MandatoryExpiration(t *testing.T) {
	iaPrivHex, _ := generateTestKeypair(t)
	userPrivHex, userPubHex := generateTestKeypair(t)
	connectionKey := nipIC.NewConnectionKey("discord", "some.user")

	t.Run("no expiration at all is rejected", func(t *testing.T) {
		// ExpirationDays: 0 means "no expiry" in nipIC's own model —
		// nipIC.ParseAttestation accepts this happily (its own parse is
		// permissive), but this package's stricter policy MUST reject it.
		att := buildTestAttestation(t, iaPrivHex, userPubHex, connectionKey, 0)
		if att.ExpiresAt != nil {
			t.Fatal("test setup: expected a nil ExpiresAt for ExpirationDays: 0")
		}
		cred := BySigningConnectionKey(userPrivHex, "discord", "some.user", att)
		_, _, _, _, _, err := cred.buildProof(proofBinding{WalletPubkey: randomKeyHex(t), Bolt11Hash: "h"})
		if err != ErrAttestationExpired {
			t.Fatalf("got %v, want ErrAttestationExpired", err)
		}
	})

	t.Run("already expired is rejected", func(t *testing.T) {
		att := buildTestAttestation(t, iaPrivHex, userPubHex, connectionKey, 1)
		// Force it into the past — nipIC has no negative-days option, so
		// mutate the parsed result directly for this test.
		past := time.Now().Add(-time.Hour)
		att.ExpiresAt = &past
		cred := BySigningConnectionKey(userPrivHex, "discord", "some.user", att)
		_, _, _, _, _, err := cred.buildProof(proofBinding{WalletPubkey: randomKeyHex(t), Bolt11Hash: "h"})
		if err != ErrAttestationExpired {
			t.Fatalf("got %v, want ErrAttestationExpired", err)
		}
	})

	t.Run("nil attestation is rejected", func(t *testing.T) {
		cred := BySigningConnectionKey(userPrivHex, "discord", "some.user", nil)
		_, _, _, _, _, err := cred.buildProof(proofBinding{WalletPubkey: randomKeyHex(t), Bolt11Hash: "h"})
		if err != ErrAttestationExpired {
			t.Fatalf("got %v, want ErrAttestationExpired", err)
		}
	})

	t.Run("valid unexpired attestation succeeds", func(t *testing.T) {
		att := buildTestAttestation(t, iaPrivHex, userPubHex, connectionKey, 90)
		cred := BySigningConnectionKey(userPrivHex, "discord", "some.user", att)
		identityType, identityValue, identityEvent, attestationEvent, _, err := cred.buildProof(proofBinding{
			WalletPubkey: randomKeyHex(t), Bolt11Hash: "h",
		})
		if err != nil {
			t.Fatalf("buildProof: %v", err)
		}
		if identityType != identityTypeConnectionKey {
			t.Fatalf("identityType: got %s", identityType)
		}
		if identityValue != connectionKey.String() {
			t.Fatalf("identityValue: got %s, want %s", identityValue, connectionKey.String())
		}
		if identityEvent == nil || attestationEvent == nil {
			t.Fatal("expected both identityEvent and attestationEvent to be set")
		}
		// The identity proof must reference the attestation's own event ID
		// via an "e" tag, and carry the connection_key tag.
		var ev struct {
			Tags [][]string `json:"tags"`
		}
		if err := json.Unmarshal(identityEvent, &ev); err != nil {
			t.Fatal(err)
		}
		var haveE, haveConnKey bool
		for _, tag := range ev.Tags {
			if len(tag) == 2 && tag[0] == "e" && tag[1] == att.ID {
				haveE = true
			}
			if len(tag) == 2 && tag[0] == "connection_key" && tag[1] == connectionKey.String() {
				haveConnKey = true
			}
		}
		if !haveE {
			t.Fatal("expected an e-tag referencing the attestation event")
		}
		if !haveConnKey {
			t.Fatal("expected a connection_key tag")
		}
	})
}

func TestNewIdentityHash_Deterministic(t *testing.T) {
	a := newIdentityHash(Pubkey("aa"))
	b := newIdentityHash(Pubkey("aa"))
	if a != b {
		t.Fatal("newIdentityHash must be deterministic for the same target")
	}
	c := newIdentityHash(Pubkey("bb"))
	if a == c {
		t.Fatal("different targets must hash differently")
	}
}
