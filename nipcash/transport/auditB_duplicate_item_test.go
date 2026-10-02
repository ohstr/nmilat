package transport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// A proof binds target, hub, method, params, nonce and expiry — but NOT the item
// id. So one signed pair authorizes any number of otherwise-identical items, and
// the only thing stopping the duplicates from executing is each method's own
// idempotency guard: a redeem marks the slice claimed, so copies 2..N find nothing
// left to take.
//
// That makes those guards the single line of defence. The amplifier is what is
// removed here: an envelope may no longer repeat a request, so a bill method added
// later without a guard of its own does not silently inherit a
// duplicate-execution hole.
//
// Deliberately NOT fixed by adding the id to the proof binding. That is the root
// fix and it invalidates every signature already in circulation, which is not worth
// it for something with no demonstrated money impact.
func TestAuditB_EnvelopeRefusesARepeatedItem(t *testing.T) {
	const priv = "0000000000000000000000000000000000000000000000000000000000000001"
	target := strings.Repeat("a", 64)
	hub := strings.Repeat("b", 64)
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	replyTo, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(time.Minute).Unix()

	params := json.RawMessage(`{"scope":"all"}`)
	ph, err := CanonicalParamsHash(params)
	if err != nil {
		t.Fatal(err)
	}
	binding := ProofBinding{Target: target, HubXOnly: hub, Method: "cash_status",
		ParamsHash: ph, Nonce: nonce, NotAfter: notAfter}
	slice, err := BuildItemProof(priv, binding)
	if err != nil {
		t.Fatal(err)
	}
	bill, err := BuildBillProof(priv, binding)
	if err != nil {
		t.Fatal(err)
	}

	one := Item{ID: "1", Target: target, Method: "cash_status", Params: params, Proof: slice, BillProof: bill}
	two := one
	two.ID = "2" // distinct id, identical request

	env := Envelope{Version: EnvelopeVersion, NotAfter: notAfter, Nonce: nonce,
		ReplyTo: replyTo, Items: []Item{one, two}}
	_, err = env.Encode(DefaultLimits())
	if !errors.Is(err, ErrDuplicateItem) {
		t.Fatalf("an envelope repeating one signed request must be refused: got %v, want ErrDuplicateItem", err)
	}
	t.Logf("refused: %v", err)

	// CONTROL 1 — one copy is of course fine, so the refusal above is about the
	// repetition and not about the item being malformed.
	solo := env
	solo.Items = []Item{one}
	if _, err := solo.Encode(DefaultLimits()); err != nil {
		t.Fatalf("CONTROL 1: a single item must still encode: %v", err)
	}

	// CONTROL 2 — the load-bearing one. Batching exists so a caller can do several
	// things to one bill in one envelope, and that must keep working. Same bill, same
	// method, DIFFERENT params is a different request and must be allowed.
	//
	// Its proof necessarily differs too, since params are part of the binding — which
	// is exactly why keying on the params hash matches the set of items one signature
	// actually covers.
	otherParams := json.RawMessage(`{"scope":"mine"}`)
	otherHash, err := CanonicalParamsHash(otherParams)
	if err != nil {
		t.Fatal(err)
	}
	otherBinding := binding
	otherBinding.ParamsHash = otherHash
	otherSlice, err := BuildItemProof(priv, otherBinding)
	if err != nil {
		t.Fatal(err)
	}
	otherBill, err := BuildBillProof(priv, otherBinding)
	if err != nil {
		t.Fatal(err)
	}
	different := Item{ID: "3", Target: target, Method: "cash_status",
		Params: otherParams, Proof: otherSlice, BillProof: otherBill}

	mixed := env
	mixed.Items = []Item{one, different}
	if _, err := mixed.Encode(DefaultLimits()); err != nil {
		t.Fatalf("CONTROL 2: two DIFFERENT requests on one bill must still batch: %v", err)
	}
	t.Log("control: same bill + same method + different params still batches, as batching requires")
}

// TestAuditB_DuplicateDetectionIsCanonical pins that the check keys on the params
// HASH, not the raw bytes. Re-serialising the same params with different key order
// must still be caught, since the proof binds the canonical hash and therefore
// covers both spellings equally.
func TestAuditB_DuplicateDetectionIsCanonical(t *testing.T) {
	const priv = "0000000000000000000000000000000000000000000000000000000000000001"
	target := strings.Repeat("c", 64)
	hub := strings.Repeat("d", 64)
	nonce, _ := NewNonce()
	replyTo, _ := NewNonce()
	notAfter := time.Now().Add(time.Minute).Unix()

	a := json.RawMessage(`{"identity_type":"pubkey","scope":"all"}`)
	b := json.RawMessage(`{"scope":"all","identity_type":"pubkey"}`) // same thing, reordered

	ph, err := CanonicalParamsHash(a)
	if err != nil {
		t.Fatal(err)
	}
	phB, err := CanonicalParamsHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ph != phB {
		t.Skipf("params hashing is not key-order canonical (%s vs %s); this test's premise does not hold", ph, phB)
	}

	binding := ProofBinding{Target: target, HubXOnly: hub, Method: "cash_status",
		ParamsHash: ph, Nonce: nonce, NotAfter: notAfter}
	slice, _ := BuildItemProof(priv, binding)
	bill, _ := BuildBillProof(priv, binding)

	env := Envelope{Version: EnvelopeVersion, NotAfter: notAfter, Nonce: nonce, ReplyTo: replyTo,
		Items: []Item{
			{ID: "1", Target: target, Method: "cash_status", Params: a, Proof: slice, BillProof: bill},
			{ID: "2", Target: target, Method: "cash_status", Params: b, Proof: slice, BillProof: bill},
		}}
	if _, err := env.Encode(DefaultLimits()); !errors.Is(err, ErrDuplicateItem) {
		t.Fatalf("reordered-but-identical params must still be caught: got %v", err)
	}
	t.Log("reordering the params does not evade the check, because the proof binds the canonical hash")
}
