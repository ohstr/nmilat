package nip26

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/flokiorg/go-flokicoin/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDelegation(t *testing.T) {
	// Setup keys
	issuerPrivHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	issuerPrivBytes, _ := hex.DecodeString(issuerPrivHex)
	_, issuerPub := crypto.PrivKeyFromBytes(issuerPrivBytes)
	issuerPubHex := hex.EncodeToString(issuerPub.SerializeCompressed()[1:])

	relayPubHex := "abfd717be2535fd03f2a059a2dd7b199be5f276b5a030e9aa52f9c602874101f"
	conditions := "kind=1&created_at<2000000000"

	t.Run("Create and Verify Success", func(t *testing.T) {
		token, err := SignDelegationToken(issuerPrivHex, relayPubHex, conditions)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		err = VerifyDelegationToken(issuerPubHex, relayPubHex, conditions, token)
		assert.NoError(t, err)
	})

	t.Run("Verify Failure - Wrong Relay Pubkey", func(t *testing.T) {
		token, _ := SignDelegationToken(issuerPrivHex, relayPubHex, conditions)
		wrongRelay := "821467621f228603a1466465a3f00fb8948698f72f161541129c595e3b9aaddc"
		err := VerifyDelegationToken(issuerPubHex, wrongRelay, conditions, token)
		assert.Error(t, err)
	})

	t.Run("Verify Failure - Wrong Conditions", func(t *testing.T) {
		token, _ := SignDelegationToken(issuerPrivHex, relayPubHex, conditions)
		wrongConditions := "kind=1&created_at<100"
		err := VerifyDelegationToken(issuerPubHex, relayPubHex, wrongConditions, token)
		assert.Error(t, err)
	})

	t.Run("Verify Failure - Invalid Signature", func(t *testing.T) {
		invalidSig := hex.EncodeToString(make([]byte, 64))
		err := VerifyDelegationToken(issuerPubHex, relayPubHex, conditions, invalidSig)
		assert.Error(t, err)
	})
}

func TestValidateConditions(t *testing.T) {
	now := uint64(time.Now().Unix())

	tests := []struct {
		name        string
		conditions  string
		kind        int
		createdAt   uint64
		expectedErr bool
	}{
		{
			name:        "Simple Kind Match",
			conditions:  "kind=1",
			kind:        1,
			createdAt:   now,
			expectedErr: false,
		},
		{
			name:        "Kind Mismatch",
			conditions:  "kind=1",
			kind:        2,
			createdAt:   now,
			expectedErr: true,
		},
		{
			name:        "Created After Match",
			conditions:  "created_at>1000",
			kind:        1,
			createdAt:   2000,
			expectedErr: false,
		},
		{
			name:        "Created After Mismatch",
			conditions:  "created_at>2000",
			kind:        1,
			createdAt:   1000,
			expectedErr: true,
		},
		{
			name:        "Created Before Match",
			conditions:  "created_at<2000",
			kind:        1,
			createdAt:   1000,
			expectedErr: false,
		},
		{
			name:        "Created Before Mismatch",
			conditions:  "created_at<1000",
			kind:        1,
			createdAt:   2000,
			expectedErr: true,
		},
		{
			name:        "Multiple Conditions Success",
			conditions:  "kind=1&created_at>100&created_at<2000000000",
			kind:        1,
			createdAt:   now,
			expectedErr: false,
		},
		{
			name:        "Multiple Conditions Failure - Kind",
			conditions:  "kind=1&created_at>100",
			kind:        2,
			createdAt:   now,
			expectedErr: true,
		},
		{
			name:        "Multiple Conditions Failure - Time",
			conditions:  "kind=1&created_at>1000000000000",
			kind:        1,
			createdAt:   now,
			expectedErr: true,
		},
		{
			name:        "Case Insensitive Keys",
			conditions:  "KIND=1",
			kind:        1,
			createdAt:   now,
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConditions(tt.conditions, tt.kind, tt.createdAt)
			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConditionsMultipleKinds(t *testing.T) {
	t.Run("Comma Separated Kinds", func(t *testing.T) {
		conditions := "kind=1,25521"
		err := ValidateConditions(conditions, 25521, uint64(time.Now().Unix()))
		assert.NoError(t, err)
	})

	t.Run("Multiple Kinds in List", func(t *testing.T) {
		conditions := "kind=1,3,4,25521"
		err := ValidateConditions(conditions, 3, uint64(time.Now().Unix()))
		assert.NoError(t, err)
	})
}

func TestValidateConditionsSentinelErrors(t *testing.T) {
	if err := ValidateConditions("kind=1", 2, uint64(time.Now().Unix())); !errors.Is(err, ErrConditionNotMet) {
		t.Errorf("expected errors.Is(err, ErrConditionNotMet), got %v", err)
	}
	if err := ValidateConditions("not-a-condition", 1, uint64(time.Now().Unix())); !errors.Is(err, ErrInvalidCondition) {
		t.Errorf("expected errors.Is(err, ErrInvalidCondition), got %v", err)
	}
}

func TestVerifyDelegationTokenSentinelErrors(t *testing.T) {
	if err := VerifyDelegationToken("not-hex", "delegate", "kind=1", "sig"); !errors.Is(err, ErrInvalidPubkey) {
		t.Errorf("expected errors.Is(err, ErrInvalidPubkey), got %v", err)
	}
}
