package transport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// NIP-CASH §Item Proofs: a proof's created_at MUST fall inside kind-23199's window,
// five minutes past and one minute future. Checked at both edges with literal
// durations, so widening the window turns this red.
func TestVerifyBillProof_FreshnessWindowEdges(t *testing.T) {
	ph, err := CanonicalParamsHash(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now()
	b := ProofBinding{Target: strings.Repeat("aa", 32), HubXOnly: strings.Repeat("ab", 32), Method: "cash_status",
		ParamsHash: ph, Nonce: strings.Repeat("ef", 32), NotAfter: created.Add(time.Hour).Unix()}
	proof, err := BuildBillProof(strings.Repeat("03", 32), b)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		now   time.Time
		fresh bool
	}{
		{"4m50s after", created.Add(4*time.Minute + 50*time.Second), true},
		{"5m10s after", created.Add(5*time.Minute + 10*time.Second), false},
		{"50s before", created.Add(-50 * time.Second), true},
		{"1m10s before", created.Add(-time.Minute - 10*time.Second), false},
	} {
		_, err := VerifyBillProof(proof, b, tc.now)
		if tc.fresh && err != nil {
			t.Errorf("%s: %v, want fresh", tc.name, err)
		}
		if !tc.fresh && !errors.Is(err, ErrProofStale) {
			t.Errorf("%s: err = %v, want ErrProofStale", tc.name, err)
		}
	}
}
