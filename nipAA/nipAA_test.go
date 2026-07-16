package nipAA

import (
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipOA"
)

// Official NIP-OA test vectors (see nipOA/nipOA_test.go), reused here so
// NIP-AA's own tests exercise the real cryptographic path, not a stub.
const (
	vectorOwnerPubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	vectorAgentPubkey = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	vectorConditions  = "kind=1&created_at<1713957000"
	vectorSig         = "8b7df2575caf0a108374f8471722b233c53f9ff827a8b0f91861966c3b9dd5cb2e189eae9f49d72187674c2f5bd244145e10ff86c9f257ffe65a1ee5f108b369"
)

func vectorTag() []string {
	return []string{"auth", vectorOwnerPubkey, vectorConditions, vectorSig}
}

func TestValidateFreshness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	window := DefaultFreshnessWindow

	tests := []struct {
		name      string
		createdAt uint64
		wantErr   bool
	}{
		{name: "exactly now", createdAt: uint64(now.Unix()), wantErr: false},
		{name: "within window", createdAt: uint64(now.Unix()) - 60, wantErr: false},
		{name: "at boundary", createdAt: uint64(now.Unix()) - uint64(window.Seconds()), wantErr: false},
		{name: "past window", createdAt: uint64(now.Unix()) - uint64(window.Seconds()) - 1, wantErr: true},
		{name: "future beyond window", createdAt: uint64(now.Unix()) + uint64(window.Seconds()) + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFreshness(tt.createdAt, now, window)
			if tt.wantErr && !errors.Is(err, ErrStale) {
				t.Fatalf("err = %v, want errors.Is(_, ErrStale)", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
		})
	}
}

func TestEvaluateCredential_NoAuthTag(t *testing.T) {
	tag, err := EvaluateCredential(vectorAgentPubkey, [][]string{{"p", "irrelevant"}}, 1713956400)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if tag != nil {
		t.Fatalf("tag = %v, want nil", tag)
	}
}

func TestEvaluateCredential_ValidCredential(t *testing.T) {
	tags := [][]string{vectorTag()}
	// The official vector's conditions are kind=1&created_at<1713957000;
	// 1713956400 satisfies created_at<1713957000.
	tag, err := EvaluateCredential(vectorAgentPubkey, tags, 1713956400)
	if err != nil {
		t.Fatalf("EvaluateCredential() on the official vector: %v", err)
	}
	if tag == nil {
		t.Fatal("EvaluateCredential() = nil, want a parsed Tag")
	}
	if tag.OwnerPubkey != vectorOwnerPubkey {
		t.Errorf("OwnerPubkey = %q, want %q", tag.OwnerPubkey, vectorOwnerPubkey)
	}
}

func TestEvaluateCredential_MultipleAuthTags(t *testing.T) {
	tags := [][]string{vectorTag(), vectorTag()}
	_, err := EvaluateCredential(vectorAgentPubkey, tags, 1713956400)
	if !errors.Is(err, nipOA.ErrMultipleAuthTags) {
		t.Fatalf("err = %v, want errors.Is(_, nipOA.ErrMultipleAuthTags)", err)
	}
}

func TestEvaluateCredential_MalformedTag(t *testing.T) {
	tags := [][]string{{"auth", vectorOwnerPubkey, vectorConditions}} // missing sig element
	_, err := EvaluateCredential(vectorAgentPubkey, tags, 1713956400)
	if !errors.Is(err, nipOA.ErrWrongElementCount) {
		t.Fatalf("err = %v, want errors.Is(_, nipOA.ErrWrongElementCount)", err)
	}
}

func TestEvaluateCredential_SelfAttestation(t *testing.T) {
	tags := [][]string{{"auth", vectorAgentPubkey, vectorConditions, vectorSig}}
	_, err := EvaluateCredential(vectorAgentPubkey, tags, 1713956400)
	if !errors.Is(err, nipOA.ErrSelfAttestation) {
		t.Fatalf("err = %v, want errors.Is(_, nipOA.ErrSelfAttestation)", err)
	}
}

func TestEvaluateCredential_StaleCreatedAt(t *testing.T) {
	tags := [][]string{vectorTag()}
	// 1713957001 does NOT satisfy created_at<1713957000 -- the spec's own
	// reject-case example.
	_, err := EvaluateCredential(vectorAgentPubkey, tags, 1713957001)
	if !errors.Is(err, ErrCredentialTimestampUnsatisfied) {
		t.Fatalf("err = %v, want errors.Is(_, ErrCredentialTimestampUnsatisfied)", err)
	}
}

func TestEvaluateCredential_SatisfiedAtBoundary(t *testing.T) {
	tags := [][]string{vectorTag()}
	// created_at<1713957000 is satisfied by anything strictly less --
	// 1713956999 is the boundary-adjacent passing case.
	if _, err := EvaluateCredential(vectorAgentPubkey, tags, 1713956999); err != nil {
		t.Fatalf("unexpected err at the passing boundary: %v", err)
	}
	// 1713957000 itself is NOT strictly less, so it must fail.
	if _, err := EvaluateCredential(vectorAgentPubkey, tags, 1713957000); !errors.Is(err, ErrCredentialTimestampUnsatisfied) {
		t.Fatalf("err = %v, want errors.Is(_, ErrCredentialTimestampUnsatisfied) at the exact boundary value", err)
	}
}

func TestEvaluateCredential_KindClauseNotEvaluated(t *testing.T) {
	// The spec's own point: kind= clauses are NOT evaluated at connection
	// admission. A credential scoped to kind=1 must still evaluate
	// successfully here regardless of any notion of "what kind is this
	// AUTH event" -- there is no event kind involved in AUTH at all, only
	// the credential's own created_at conditions matter to this function.
	tags := [][]string{vectorTag()}
	tag, err := EvaluateCredential(vectorAgentPubkey, tags, 1713956400)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(tag.Conditions.Kinds) != 1 || tag.Conditions.Kinds[0] != 1 {
		t.Fatalf("Conditions.Kinds = %v, want [1] (present but unevaluated here)", tag.Conditions.Kinds)
	}
}
