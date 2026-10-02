package transport

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// AUDIT-B SEC-A / F1: ProofBinding.NotAfter is SIGNED but NEVER VERIFIED.
//
// proofRequiredTags (proof.go:217-223) omits tagExpiration, so proofTags never
// collects the "expiration" tag and verifyProof never compares it to
// want.NotAfter. The doc comment on ProofBinding says every field is "a separate
// substitution an aggregator could otherwise perform"; this one is not.
func TestAuditBSecA_NotAfterIsNotBound(t *testing.T) {
	connPriv, binding := testBinding(t)
	proof, err := BuildBillProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}

	for _, sub := range []struct {
		name  string
		value int64
	}{
		{"an hour later", time.Now().Add(time.Hour).Unix()},
		{"an hour earlier", time.Now().Add(-time.Hour).Unix()},
		{"a decade later", time.Now().Add(24 * 3650 * time.Hour).Unix()},
		{"zero", 0},
	} {
		t.Run(sub.name, func(t *testing.T) {
			want := binding
			want.NotAfter = sub.value
			if _, err := VerifyBillProof(proof, want, time.Now()); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Logf("AUDITB-SECA-F1: bill proof signed for not_after=%d VERIFIED against want.NotAfter=%d",
				binding.NotAfter, sub.value)
		})
	}

	// Precision matters here: the tag IS inside the signed event id, so an attacker
	// cannot remove or rewrite it. The defect is narrower and still real — the hub
	// never compares the value, so the proof does not actually commit to the
	// envelope's not_after, and its only enforced lifetime is created_at +/- the
	// freshness window.
	stripped := stripTag(t, proof, "expiration")
	if _, err := VerifyBillProof(stripped, binding, time.Now()); err == nil {
		t.Fatal("removing the expiration tag should break the event id")
	}
	t.Log("AUDITB-SECA-F1: the expiration tag is integrity-protected (removing it breaks the id) " +
		"but its VALUE is never compared to want.NotAfter, because proofRequiredTags omits it. " +
		"So the proof's enforced lifetime is ProofFreshnessPast (5m), NOT the envelope's " +
		"MaxNotAfterWindow (120s).")
}

// AUDIT-B SEC-A / F1b: the cross-envelope lift.
//
// The nonce is the ONLY thing tying a proof to one envelope. Because NotAfter is
// unbound, the same signed proof verifies unchanged inside a SECOND envelope that
// merely reuses the nonce with a fresh, later not_after — for the whole
// ProofFreshnessPast window (5 minutes) after it was created.
//
// An aggregator legitimately holds other people's proofs while assembling an
// envelope (see ProofBinding's own doc comment), so this is the aggregator's lever.
func TestAuditBSecA_ProofLiftsIntoASecondEnvelopeReusingTheNonce(t *testing.T) {
	connPriv, binding := testBinding(t)

	// Envelope 1, as the honest signer built it: nonce N, a short window.
	binding.NotAfter = time.Now().Add(20 * time.Second).Unix()
	proof, err := BuildBillProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}
	slice, err := BuildItemProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}

	// Envelope 1 has long expired. 4m30s later the attacker builds envelope 2 with
	// the SAME nonce and a brand-new 120s window, and drops the signer's proofs in
	// verbatim. Nothing is mutated, so no signature work is needed.
	later := time.Now().Add(4*time.Minute + 30*time.Second)
	lifted := binding
	lifted.NotAfter = later.Add(120 * time.Second).Unix() // a legal MaxNotAfterWindow

	if _, err := VerifyBillProof(proof, lifted, later); err != nil {
		t.Fatalf("bill proof did NOT lift: %v", err)
	}
	if _, err := VerifyItemProof(slice, lifted, later); err != nil {
		t.Fatalf("slice proof did NOT lift: %v", err)
	}
	t.Logf("AUDITB-SECA-F1b BUG PRESENT: a proof pair signed for an envelope that expired at %d "+
		"verified %s later inside a NEW envelope declaring not_after=%d, because the only "+
		"envelope-binding is the nonce and not_after is unchecked",
		binding.NotAfter, later.Sub(time.Unix(binding.NotAfter, 0)).Round(time.Second), lifted.NotAfter)

	// CONTROL, in the same test: change anything the proof DOES bind and it fails.
	// This is what makes the result above a property of not_after rather than of the
	// verifier being permissive.
	otherNonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	control := lifted
	control.Nonce = otherNonce
	if _, err := VerifyBillProof(proof, control, later); err == nil {
		t.Fatal("CONTROL FAILED: a fresh nonce should have rejected the lift")
	}
	control = lifted
	control.Method = "cash_status"
	if _, err := VerifyBillProof(proof, control, later); err == nil {
		t.Fatal("CONTROL FAILED: a substituted method should have rejected the lift")
	}
	otherHash, err := CanonicalParamsHash(json.RawMessage(`{"invoice":"attacker"}`))
	if err != nil {
		t.Fatal(err)
	}
	control = lifted
	control.ParamsHash = otherHash
	if _, err := VerifyBillProof(proof, control, later); err == nil {
		t.Fatal("CONTROL FAILED: substituted params should have rejected the lift")
	}
	t.Log("AUDITB-SECA-F1b CONTROL: nonce, method and params substitutions all still reject, " +
		"so the lift is specifically not_after going unchecked — reusing the nonce is the whole trick")

	// And the outer bound: past ProofFreshnessPast the lift dies.
	tooLate := time.Unix(int64(mustCreatedAt(t, proof)), 0).Add(ProofFreshnessPast + time.Second)
	if _, err := VerifyBillProof(proof, lifted, tooLate); err == nil {
		t.Fatal("a proof should not lift past its freshness window")
	}
	t.Logf("AUDITB-SECA-F1b: the lift window is exactly ProofFreshnessPast = %s", ProofFreshnessPast)
}

// AUDIT-B SEC-A / kind confusion, BOTH directions, at hub-relevant shape:
// re-confirmed here only because the assignment names it. Both are refused.
func TestAuditBSecA_KindConfusionBothDirections(t *testing.T) {
	priv, binding := testBinding(t)
	slice, _ := BuildItemProof(priv, binding)
	bill, _ := BuildBillProof(priv, binding)

	if _, err := VerifyBillProof(slice, binding, time.Now()); err == nil {
		t.Fatal("a 23192 slice proof verified as a bill proof")
	}
	if _, err := VerifyItemProof(bill, binding, time.Now()); err == nil {
		t.Fatal("a 23193 bill proof verified as a slice proof")
	}
	// The interesting variant the existing test does not cover: rewrite the kind
	// field on the signed event. The id/sig cover the kind, so this must fail on
	// SIGNATURE, not on kind — proving the kind is inside the commitment and not
	// merely compared.
	relabelled := setKind(t, slice, KindBillProof)
	_, err := VerifyBillProof(relabelled, binding, time.Now())
	if err == nil {
		t.Fatal("a relabelled slice proof verified as a bill proof")
	}
	t.Logf("AUDITB-SECA: relabelling kind 23192 -> 23193 fails with %v (the kind is inside the event id)", err)
}

func stripTag(t *testing.T, raw json.RawMessage, name string) json.RawMessage {
	t.Helper()
	var ev nip01.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	out := ev.Tags[:0:0]
	for _, tag := range ev.Tags {
		if len(tag) > 0 && tag[0] == name {
			continue
		}
		out = append(out, tag)
	}
	ev.Tags = out
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func setKind(t *testing.T, raw json.RawMessage, kind int) json.RawMessage {
	t.Helper()
	var ev nip01.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	ev.Kind = kind
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustCreatedAt(t *testing.T, raw json.RawMessage) int64 {
	t.Helper()
	var ev nip01.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	return int64(ev.CreatedAt)
}
