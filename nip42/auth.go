// Package nip42 implements NIP-42: Relay Authentication, letting a relay
// challenge a client to prove control of a pubkey (via a signed kind:22242
// event) before granting access to restricted reads/writes.
package nip42

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
)

const KindClientAuth = 22242

// ValidateAuthEvent failure modes, for callers that need to distinguish
// them (e.g. via errors.Is) rather than match on message text.
var (
	ErrWrongKind          = errors.New("nip42: unexpected kind")
	ErrTimestampOutOfSync = errors.New("nip42: created_at is too far from now")
	ErrRelayTagMismatch   = errors.New("nip42: relay tag missing or incorrect")
	ErrChallengeMismatch  = errors.New("nip42: challenge tag missing or incorrect")
)

func NewChallenge() string {
	return uuid.NewString()
}

// NewAuthEvent builds an unsigned kind:22242 client authentication event
// answering relayURL's challenge. Caller must sign it.
func NewAuthEvent(challenge, relayURL string) *nip01.Event {
	return nip01.NewEvent(KindClientAuth, "",
		[]string{"relay", relayURL},
		[]string{"challenge", challenge},
	)
}

// ValidateAuthEvent validates an authentication event for a relay.
// It checks the kind, creation time, and required tags ("relay", "challenge").
func ValidateAuthEvent(kind int, tags [][]string, createdAt uint64, challenge, relayURL string) error {
	if kind != KindClientAuth {
		return fmt.Errorf("%w: got %d, want %d", ErrWrongKind, kind, KindClientAuth)
	}

	// created_at should be within a reasonable window (e.g. 10 minutes)
	now := uint64(time.Now().Unix())
	if createdAt > now+600 || createdAt < now-600 {
		return ErrTimestampOutOfSync
	}

	foundRelay := false
	foundChallenge := false

	for _, tag := range tags {
		if len(tag) < 2 {
			continue
		}
		if tag[0] == "relay" && tag[1] == relayURL {
			foundRelay = true
		}
		if tag[0] == "challenge" && tag[1] == challenge {
			foundChallenge = true
		}
	}

	if !foundRelay {
		return ErrRelayTagMismatch
	}
	if !foundChallenge {
		return ErrChallengeMismatch
	}

	return nil
}
