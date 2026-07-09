package nip42

import (
	"errors"
	"testing"
	"time"
)

func TestNewChallenge(t *testing.T) {
	c1 := NewChallenge()
	c2 := NewChallenge()

	if len(c1) == 0 {
		t.Error("NewChallenge() returned empty string")
	}

	if c1 == c2 {
		t.Error("NewChallenge() returned duplicate strings")
	}
}

func TestNewAuthEvent(t *testing.T) {
	ev := NewAuthEvent("test-challenge", "ws://test.relay")

	if ev.Kind != KindClientAuth {
		t.Errorf("expected kind %d, got %d", KindClientAuth, ev.Kind)
	}
	if err := ValidateAuthEvent(ev.Kind, ev.Tags, ev.CreatedAt, "test-challenge", "ws://test.relay"); err != nil {
		t.Errorf("expected NewAuthEvent's output to pass ValidateAuthEvent, got: %v", err)
	}
}

func TestValidateAuthEvent(t *testing.T) {
	validChallenge := "test-challenge"
	validRelay := "ws://test.relay"
	now := uint64(time.Now().Unix())

	tests := []struct {
		name      string
		kind      int
		tags      [][]string
		createdAt uint64
		challenge string
		relayURL  string
		wantErrIs error
	}{
		{
			name: "valid auth event",
			kind: KindClientAuth,
			tags: [][]string{
				{"relay", validRelay},
				{"challenge", validChallenge},
			},
			createdAt: now,
			challenge: validChallenge,
			relayURL:  validRelay,
			wantErrIs: nil,
		},
		{
			name: "invalid kind",
			kind: 1, // Text note
			tags: [][]string{
				{"relay", validRelay},
				{"challenge", validChallenge},
			},
			createdAt: now,
			challenge: validChallenge,
			relayURL:  validRelay,
			wantErrIs: ErrWrongKind,
		},
		{
			name: "created too long ago",
			kind: KindClientAuth,
			tags: [][]string{
				{"relay", validRelay},
				{"challenge", validChallenge},
			},
			createdAt: now - 601,
			challenge: validChallenge,
			relayURL:  validRelay,
			wantErrIs: ErrTimestampOutOfSync,
		},
		{
			name: "created too far in future",
			kind: KindClientAuth,
			tags: [][]string{
				{"relay", validRelay},
				{"challenge", validChallenge},
			},
			createdAt: now + 601,
			challenge: validChallenge,
			relayURL:  validRelay,
			wantErrIs: ErrTimestampOutOfSync,
		},
		{
			name: "missing relay tag",
			kind: KindClientAuth,
			tags: [][]string{
				{"challenge", validChallenge},
			},
			createdAt: now,
			challenge: validChallenge,
			relayURL:  validRelay,
			wantErrIs: ErrRelayTagMismatch,
		},
		{
			name: "wrong relay tag",
			kind: KindClientAuth,
			tags: [][]string{
				{"relay", "ws://wrong.relay"},
				{"challenge", validChallenge},
			},
			createdAt: now,
			challenge: validChallenge,
			relayURL:  validRelay,
			wantErrIs: ErrRelayTagMismatch,
		},
		{
			name: "missing challenge tag",
			kind: KindClientAuth,
			tags: [][]string{
				{"relay", validRelay},
			},
			createdAt: now,
			challenge: validChallenge,
			relayURL:  validRelay,
			wantErrIs: ErrChallengeMismatch,
		},
		{
			name: "wrong challenge tag",
			kind: KindClientAuth,
			tags: [][]string{
				{"relay", validRelay},
				{"challenge", "wrong-challenge"},
			},
			createdAt: now,
			challenge: validChallenge,
			relayURL:  validRelay,
			wantErrIs: ErrChallengeMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuthEvent(tt.kind, tt.tags, tt.createdAt, tt.challenge, tt.relayURL)
			if tt.wantErrIs == nil {
				if err != nil {
					t.Errorf("ValidateAuthEvent() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErrIs) {
				t.Errorf("ValidateAuthEvent() error = %v, want errors.Is match for %v", err, tt.wantErrIs)
			}
		})
	}
}
