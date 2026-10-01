package transport

import (
	"encoding/json"
	"testing"
)

// Session D, Security Auditor B, surface 2.
//
// FuzzDecode and FuzzDecodeResponse both pin DefaultLimits(), so the whole policy space a
// real hub may legally run is unfuzzed. This round's attacker model includes a misconfiguring
// operator, so the limits themselves are input: this target derives a policy from the fuzz
// bytes, keeps only policies Validate() accepts, and asserts the invariants a later stage
// relies on hold for EVERY legal policy rather than just the default one.
func FuzzAuditDSecBDecodeUnderOperatorLimits(f *testing.F) {
	f.Add([]byte(`{"v":1,"not_after":1,"nonce":"","reply_to":"","items":[]}`), uint16(56*1024), uint8(32), uint16(8*1024), uint8(48))
	f.Add([]byte(`{}`), uint16(2914), uint8(1), uint16(2048), uint8(2))
	f.Add([]byte(`{"v":1,"items":[{"id":"a","params":{"sources":[{},{},{}]}}]}`), uint16(65535), uint8(255), uint16(2048), uint8(60))

	f.Fuzz(func(t *testing.T, data []byte, maxBytes uint16, maxItems uint8, padBucket uint16, maxSources uint8) {
		limits := Limits{
			MaxEnvelopeBytes:      int(maxBytes),
			MaxItems:              int(maxItems),
			PadBucketBytes:        int(padBucket),
			MaxVerifyBudget:       DefaultMaxVerifyBudget,
			MaxConsolidateSources: int(maxSources),
		}
		if err := limits.Validate(); err != nil {
			// Not a legal hub policy; Decode must refuse it rather than act on it, which is
			// itself worth asserting -- a decoder that honoured an incoherent policy would
			// make every downstream bound meaningless.
			if _, err := Decode(data, limits); err == nil {
				t.Fatal("Decode accepted an envelope under a policy Validate() rejects")
			}
			return
		}

		decoded, err := Decode(data, limits)
		if err != nil {
			if decoded != nil {
				t.Fatal("Decode returned both an envelope and an error")
			}
			return
		}

		// Every bound the hub relies on after Decode, under this operator's policy.
		if len(data) > limits.MaxEnvelopeBytes {
			t.Fatalf("accepted %d bytes over a %d limit", len(data), limits.MaxEnvelopeBytes)
		}
		if len(decoded.Items) == 0 || len(decoded.Items) > limits.MaxItems {
			t.Fatalf("accepted %d items against a limit of %d", len(decoded.Items), limits.MaxItems)
		}
		budget := 0
		seen := map[string]struct{}{}
		for _, item := range decoded.Items {
			if len(item.Target) != keyHexLen || !isLowerHex(item.Target) {
				t.Fatalf("accepted a malformed target %q", item.Target)
			}
			if item.ID == "" {
				t.Fatal("accepted an item with no id")
			}
			if _, dup := seen[item.ID]; dup {
				t.Fatalf("accepted a duplicate item id %q", item.ID)
			}
			seen[item.ID] = struct{}{}
			if !item.HasBillProof() {
				t.Fatalf("accepted item %q with no bill proof", item.ID)
			}
			if got := item.SourceCount(); got > limits.MaxConsolidateSources {
				t.Fatalf("accepted %d consolidate sources against a limit of %d", got, limits.MaxConsolidateSources)
			}
			budget += item.VerificationCost()
		}
		if budget > limits.MaxVerifyBudget {
			t.Fatalf("accepted a %d-verification envelope against a %d budget", budget, limits.MaxVerifyBudget)
		}
		if len(decoded.Nonce) != keyHexLen || !isLowerHex(decoded.Nonce) {
			t.Fatalf("accepted a malformed nonce %q", decoded.Nonce)
		}
		if len(decoded.ReplyTo) != keyHexLen || !isLowerHex(decoded.ReplyTo) {
			t.Fatalf("accepted a malformed reply_to %q", decoded.ReplyTo)
		}

		// And the round trip: re-encoding what was just accepted must not panic, and must
		// either succeed within the same limits or fail cleanly. A decoded envelope that
		// cannot be re-encoded under the policy that admitted it is the shape of bug that
		// loses a reply for work already done.
		if out, err := decoded.Encode(limits); err == nil && len(out) > limits.MaxEnvelopeBytes {
			t.Fatalf("re-encoded to %d bytes over a %d limit", len(out), limits.MaxEnvelopeBytes)
		}

		// json.Marshal of the decoded form must round-trip through Decode's own checks.
		raw, err := json.Marshal(decoded)
		if err != nil {
			t.Fatalf("a decoded envelope will not marshal: %v", err)
		}
		if len(raw) <= limits.MaxEnvelopeBytes {
			if _, err := Decode(raw, limits); err != nil {
				t.Fatalf("a decoded envelope does not survive re-decoding: %v", err)
			}
		}
	})
}
