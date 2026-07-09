// Package nip26 implements NIP-26: Delegated Event Signing, letting an
// issuer authorize a delegate pubkey to sign events on its behalf within
// caller-defined conditions (event kind, creation-time window).
package nip26

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
)

// Failure modes for VerifyDelegationToken/ValidateConditions, for callers
// that need to distinguish them (e.g. via errors.Is) rather than match on
// message text.
var (
	ErrInvalidPubkey    = errors.New("nip26: invalid pubkey")
	ErrInvalidSignature = errors.New("nip26: invalid delegation signature")
	ErrInvalidCondition = errors.New("nip26: malformed condition")
	ErrConditionNotMet  = errors.New("nip26: event does not satisfy delegation condition")
)

// SignDelegationToken signs a delegation token for a delegate pubkey and conditions.
// privkey: Issuer's private key (hex)
// delegatePubkey: Delegate's public key (hex)
// conditions: Delegation conditions (e.g., "kind=25521")
func SignDelegationToken(privkey, delegatePubkey, conditions string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privkey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	// String to sign: delegation:<delegate_pubkey>:<conditions>
	tokenStr := fmt.Sprintf("delegation:%s:%s", delegatePubkey, conditions)
	h := sha256.Sum256([]byte(tokenStr))

	sig, err := schnorr.Sign(privKey, h[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign delegation token: %w", err)
	}

	return hex.EncodeToString(sig.Serialize()), nil
}

// VerifyDelegationToken verifies a delegation token signature.
func VerifyDelegationToken(issuerPubkey, delegatePubkey, conditions, sigHex string) error {
	issuerBytes, err := hex.DecodeString(issuerPubkey)
	if err != nil {
		return fmt.Errorf("%w: issuer pubkey: %w", ErrInvalidPubkey, err)
	}

	issuer, err := schnorr.ParsePubKey(issuerBytes)
	if err != nil {
		return fmt.Errorf("%w: issuer pubkey: %w", ErrInvalidPubkey, err)
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	tokenStr := fmt.Sprintf("delegation:%s:%s", delegatePubkey, conditions)
	h := sha256.Sum256([]byte(tokenStr))

	if !sig.Verify(h[:], issuer) {
		return fmt.Errorf("%w (string: %s)", ErrInvalidSignature, tokenStr)
	}

	return nil
}

// ValidateConditions checks if an event satisfies the delegation conditions.
func ValidateConditions(conditions string, kind int, createdAt uint64) error {
	if conditions == "" {
		return nil
	}

	for part := range strings.SplitSeq(conditions, "&") {
		if part == "" {
			continue
		}

		// Find the operator
		var op string
		var key, val string
		if strings.Contains(part, ">") {
			op = ">"
		} else if strings.Contains(part, "<") {
			op = "<"
		} else if strings.Contains(part, "=") {
			op = "="
		} else {
			return fmt.Errorf("%w: %q", ErrInvalidCondition, part)
		}

		kv := strings.SplitN(part, op, 2)
		if len(kv) != 2 {
			return fmt.Errorf("%w: %q", ErrInvalidCondition, part)
		}
		key = strings.ToLower(kv[0])
		val = kv[1]

		switch key {
		case "kind":
			if op != "=" {
				return fmt.Errorf("%w: operator %q not valid for kind", ErrInvalidCondition, op)
			}
			allowedKinds := strings.Split(val, ",")
			match := false
			for _, kStr := range allowedKinds {
				k, err := strconv.Atoi(kStr)
				if err == nil && k == kind {
					match = true
					break
				}
			}
			if !match {
				return fmt.Errorf("%w: kind %d not in %s", ErrConditionNotMet, kind, val)
			}
		case "created_at":
			limit, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return fmt.Errorf("%w: created_at value %q: %w", ErrInvalidCondition, val, err)
			}

			switch op {
			case ">":
				if createdAt <= limit {
					return fmt.Errorf("%w: created_at %d too old, must be > %d", ErrConditionNotMet, createdAt, limit)
				}
			case "<":
				if createdAt >= limit {
					return fmt.Errorf("%w: created_at %d too new, must be < %d", ErrConditionNotMet, createdAt, limit)
				}
			case "=":
				if createdAt != limit {
					return fmt.Errorf("%w: created_at %d, expected %d", ErrConditionNotMet, createdAt, limit)
				}
			}
		}
	}

	return nil
}
