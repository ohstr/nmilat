package nipcash

import (
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// TestGrantItem_BuildsAndValidates is the SDK half of §Pre-Authorisation: a
// delegate who holds a grant but NOT the bill's connection secret builds a
// cash_status item that carries the grant in place of a bill proof, and the
// envelope both encodes (shape) and validates (semantics). The delegate never
// touches the connection secret, yet produces a coherent, sendable item.
func TestGrantItem_BuildsAndValidates(t *testing.T) {
	_, hubXOnly := itemTestKeypair(t)
	b := testBinding(t, hubXOnly)
	_, billTarget := itemTestKeypair(t)
	delegatePriv, delegate := itemTestKeypair(t)

	// The grant is signed by the bill's connection secret — the same key a bill
	// proof would be signed with — and names the delegate for one method.
	grant, err := transport.BuildGrant(connSecretFor(billTarget), transport.GrantParams{
		Delegate:  delegate,
		Target:    billTarget,
		HubXOnly:  hubXOnly,
		Method:    "cash_status",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("BuildGrant: %v", err)
	}

	// The delegate passes no connection secret ("") — the grant stands in for it.
	item, err := StatusItem("g1", billTarget, "", CashStatusParams{}, BySigningGrant(delegatePriv, grant), b)
	if err != nil {
		t.Fatalf("StatusItem(grant): %v", err)
	}

	if !item.HasGrant() {
		t.Error("grant item carries no grant")
	}
	if item.HasBillProof() {
		t.Error("grant item carries a bill proof; the grant stands in its place")
	}
	if !item.HasProof() {
		t.Error("grant item carries no slice proof; the grant needs one to bind the delegate")
	}
	// One possession signature (the grant, in place of a bill proof) + one slice proof.
	if got := item.VerificationCost(); got != 2 {
		t.Errorf("VerificationCost() = %d, want 2 (grant + slice proof)", got)
	}

	env := transport.Envelope{Nonce: b.Nonce, ReplyTo: strings.Repeat("22", 32), NotAfter: b.NotAfter, Items: []transport.Item{item}}
	// Shape, then semantics — both must pass with no fixing up in between.
	if _, err := env.Encode(transport.DefaultLimits()); err != nil {
		t.Fatalf("Encode() refuses a grant item: %v", err)
	}
	if err := env.Validate(hubXOnly, time.Now()); err != nil {
		t.Fatalf("Validate() rejects a coherent grant item: %v", err)
	}
}

// TestGrantItem_WrongDelegateIsRejected pins the one load-bearing rule. A grant
// authorises delegate A, but the item's slice proof is signed by someone else. The
// shape is still legal (grant + slice proof, no bill proof), so Encode passes — but
// Validate must reject the mismatch. Were it accepted, a leaked grant would be a
// second bearer secret usable by anyone who got hold of it.
func TestGrantItem_WrongDelegateIsRejected(t *testing.T) {
	_, hubXOnly := itemTestKeypair(t)
	b := testBinding(t, hubXOnly)
	_, billTarget := itemTestKeypair(t)
	_, delegateA := itemTestKeypair(t)
	impostorPriv, _ := itemTestKeypair(t)

	grant, err := transport.BuildGrant(connSecretFor(billTarget), transport.GrantParams{
		Delegate:  delegateA, // authorises A
		Target:    billTarget,
		HubXOnly:  hubXOnly,
		Method:    "cash_status",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// ...but the impostor signs the slice proof, carrying A's grant.
	item, err := StatusItem("g1", billTarget, "", CashStatusParams{}, BySigningGrant(impostorPriv, grant), b)
	if err != nil {
		t.Fatalf("StatusItem: %v", err)
	}
	env := transport.Envelope{Nonce: b.Nonce, ReplyTo: strings.Repeat("22", 32), NotAfter: b.NotAfter, Items: []transport.Item{item}}
	// The shape is legal, so Encode accepts it — the mismatch is a semantic failure.
	if _, err := env.Encode(transport.DefaultLimits()); err != nil {
		t.Fatalf("Encode() refused a well-shaped grant item: %v", err)
	}
	if err := env.Validate(hubXOnly, time.Now()); err == nil {
		t.Fatal("Validate() accepted a grant used by the wrong delegate — a leaked grant would be a second bearer secret")
	}
}
