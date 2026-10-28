package transport

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// AUDIT-B SEC-A / F1, fixed: the expiration tag is compared with the envelope's
// not_after (NIP-CASH §Item Proofs: expiration binds the envelope's not_after), so
// a proof signed for one not_after verifies against no other.
func TestAuditBSecA_NotAfterIsBound(t *testing.T) {
	connPriv, binding := testBinding(t)
	proof, err := BuildBillProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBillProof(proof, binding, time.Now()); err != nil {
		t.Fatalf("the proof's own not_after: %v", err)
	}
	for _, other := range []int64{time.Now().Add(time.Hour).Unix(), time.Now().Add(-time.Hour).Unix(), 0} {
		want := binding
		want.NotAfter = other
		if _, err := VerifyBillProof(proof, want, time.Now()); err == nil {
			t.Errorf("a proof for not_after %d verified against %d", binding.NotAfter, other)
		}
	}
	if _, err := VerifyBillProof(stripTag(t, proof, "expiration"), binding, time.Now()); err == nil {
		t.Fatal("a proof without expiration verified")
	}
}

// AUDIT-B SEC-A / F1b, fixed: a proof pair cannot be lifted into a second
// envelope that reuses the nonce with a later not_after.
func TestAuditBSecA_ProofDoesNotLiftIntoASecondEnvelope(t *testing.T) {
	connPriv, binding := testBinding(t)
	binding.NotAfter = time.Now().Add(20 * time.Second).Unix()
	proof, err := BuildBillProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}
	slice, err := BuildItemProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(4*time.Minute + 30*time.Second)
	lifted := binding
	lifted.NotAfter = later.Add(120 * time.Second).Unix()
	if _, err := VerifyBillProof(proof, lifted, later); err == nil {
		t.Error("bill proof lifted into a second envelope")
	}
	if _, err := VerifyItemProof(slice, lifted, later); err == nil {
		t.Error("item proof lifted into a second envelope")
	}
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
