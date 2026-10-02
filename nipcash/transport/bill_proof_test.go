package transport

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// The kind-23193 bill proof, at the level of the primitive.
//
// It shares its binding, its tag set and its freshness window with the kind-23192
// slice proof, and that is exactly why it needs its own tests: the ONE thing
// separating "I hold this bill" from "I control some key" is the event kind. Every
// other field is identical, so a verifier that checked everything except the kind
// would accept a slice proof as possession and look entirely correct while doing it.

func TestBillProof_RoundTrips(t *testing.T) {
	connPriv, binding := testBinding(t)
	connPub, err := publicFromPrivate(connPriv)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := BuildBillProof(connPriv, binding)
	if err != nil {
		t.Fatalf("BuildBillProof: %v", err)
	}
	signer, err := VerifyBillProof(proof, binding, time.Now())
	if err != nil {
		t.Fatalf("VerifyBillProof: %v", err)
	}
	if signer != connPub {
		t.Errorf("signer = %s, want the connection pubkey %s", signer, connPub)
	}
}

// TestBillProof_KindsAreNotInterchangeable is the load-bearing test in this file.
//
// A slice proof must not verify as a bill proof, in either direction. If it did,
// possession would be provable by anyone who can sign anything — and possession is
// what gates whether a hub will confirm a bill exists at all, so the failure mode is
// an existence oracle rather than a wrong answer.
func TestBillProof_KindsAreNotInterchangeable(t *testing.T) {
	priv, binding := testBinding(t)

	sliceProof, err := BuildItemProof(priv, binding)
	if err != nil {
		t.Fatal(err)
	}
	billProof, err := BuildBillProof(priv, binding)
	if err != nil {
		t.Fatal(err)
	}

	// Same key, same binding, same tags: only the kind differs. So this pair is the
	// strongest possible statement that the kind alone is doing the separating.
	if _, err := VerifyBillProof(sliceProof, binding, time.Now()); !errors.Is(err, ErrProofMalformed) {
		t.Errorf("a kind-23192 slice proof verified as a BILL proof (err = %v) — possession would be forgeable by anyone with a key", err)
	}
	if _, err := VerifyItemProof(billProof, binding, time.Now()); !errors.Is(err, ErrProofMalformed) {
		t.Errorf("a kind-23193 bill proof verified as a SLICE proof (err = %v)", err)
	}
}

// TestBillProof_RejectsEverySubstitution mirrors the slice proof's own binding
// tests. The bindings are what stop an aggregator — who legitimately holds other
// people's bill proofs while assembling an envelope — from reusing one.
func TestBillProof_RejectsEverySubstitution(t *testing.T) {
	connPriv, binding := testBinding(t)
	proof, err := BuildBillProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}

	_, otherKey := testKeypair(t)
	otherHash, err := CanonicalParamsHash(json.RawMessage(`{"invoice":"different"}`))
	if err != nil {
		t.Fatal(err)
	}
	otherNonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		want error
		mut  func(ProofBinding) ProofBinding
		why  string
	}{
		{
			name: "a different bill",
			want: ErrProofWrongTarget,
			mut:  func(b ProofBinding) ProofBinding { b.Target = otherKey; return b },
			why:  "a proof must not be liftable onto another bill",
		},
		{
			name: "a different hub",
			want: ErrProofWrongHub,
			mut:  func(b ProofBinding) ProofBinding { b.HubXOnly = otherKey; return b },
			why:  "an item must not be replayable at another hub",
		},
		{
			name: "a different method",
			want: ErrProofWrongMethod,
			mut:  func(b ProofBinding) ProofBinding { b.Method = "cash_status"; return b },
			why:  "a proof for one method must not authorise another (testBinding signs cash_redeem)",
		},
		{
			name: "different params",
			want: ErrProofWrongParams,
			mut:  func(b ProofBinding) ProofBinding { b.ParamsHash = otherHash; return b },
			why:  "an aggregator must not re-point an item's params",
		},
		{
			name: "a different envelope",
			want: ErrProofWrongNonce,
			mut:  func(b ProofBinding) ProofBinding { b.Nonce = otherNonce; return b },
			why:  "a banked proof must not be replayable later",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyBillProof(proof, tc.mut(binding), time.Now()); !errors.Is(err, tc.want) {
				t.Errorf("VerifyBillProof() = %v, want %v — %s", err, tc.want, tc.why)
			}
		})
	}
}

// TestBillProof_RejectsAForeignSigner: the signature must verify, and the caller is
// told WHO signed so the hub can compare against the bill's own connection pubkey.
// A proof signed by the wrong key is structurally valid, so this is the hub's
// comparison, not the verifier's — the verifier's job is to report the signer
// honestly.
func TestBillProof_RejectsAForeignSigner(t *testing.T) {
	_, binding := testBinding(t)
	attackerPriv, _ := testKeypair(t)
	attackerPub, err := publicFromPrivate(attackerPriv)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := BuildBillProof(attackerPriv, binding)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := VerifyBillProof(proof, binding, time.Now())
	if err != nil {
		t.Fatalf("a well-formed proof by the wrong key must still verify structurally: %v", err)
	}
	if signer != attackerPub {
		t.Errorf("signer = %s, want the attacker's own pubkey %s — the verifier must report who actually signed, so the hub can reject it",
			signer, attackerPub)
	}
}

func TestBillProof_RejectsStale(t *testing.T) {
	connPriv, binding := testBinding(t)
	proof, err := BuildBillProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}

	tooLate := time.Now().Add(ProofFreshnessPast + time.Minute)
	if _, err := VerifyBillProof(proof, binding, tooLate); !errors.Is(err, ErrProofStale) {
		t.Errorf("VerifyBillProof() = %v, want ErrProofStale — a captured proof must expire", err)
	}
	tooEarly := time.Now().Add(-(ProofFreshnessFuture + time.Minute))
	if _, err := VerifyBillProof(proof, binding, tooEarly); !errors.Is(err, ErrProofStale) {
		t.Errorf("VerifyBillProof() = %v, want ErrProofStale for a proof from the future", err)
	}
}

func TestBillProof_RejectsMalformed(t *testing.T) {
	_, binding := testBinding(t)
	for _, tc := range []struct {
		name  string
		proof json.RawMessage
	}{
		{"empty", nil},
		{"json null", json.RawMessage(`null`)},
		{"not json", json.RawMessage(`{oops`)},
		{"empty object", json.RawMessage(`{}`)},
		{"wrong kind entirely", json.RawMessage(`{"kind":1}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyBillProof(tc.proof, binding, time.Now()); err == nil {
				t.Error("VerifyBillProof() = nil error; a malformed proof must never verify")
			}
		})
	}
}

func TestBuildBillProof_RequiresAFullBinding(t *testing.T) {
	connPriv, full := testBinding(t)
	for _, name := range []string{"target", "hub", "method", "params", "nonce"} {
		t.Run(name, func(t *testing.T) {
			b := full
			switch name {
			case "target":
				b.Target = ""
			case "hub":
				b.HubXOnly = ""
			case "method":
				b.Method = ""
			case "params":
				b.ParamsHash = ""
			case "nonce":
				b.Nonce = ""
			}
			if _, err := BuildBillProof(connPriv, b); !errors.Is(err, ErrProofMalformed) {
				t.Errorf("BuildBillProof() = %v, want ErrProofMalformed — an unbound proof is a replayable one", err)
			}
		})
	}
}

// TestItem_HasBillProof_TreatsNullAsAbsent is the null-literal hazard, which has
// already caused one live outage on the slice proof: a nil json.RawMessage marshals
// to `null`, and decoding that yields FOUR BYTES, so a length check reads it as a
// proof that is present and unverifiable.
//
// For the bill proof the consequence would be the inverse and worse: an item whose
// possession proof is literally absent would pass a length check and reach the
// signature comparison with junk, and any code path that treated "present" as
// "checked" would admit it.
func TestItem_HasBillProof_TreatsNullAsAbsent(t *testing.T) {
	var absent Item
	if absent.HasBillProof() {
		t.Error("an item with no bill proof reports having one")
	}

	nullish := Item{BillProof: json.RawMessage(`null`)}
	if nullish.HasBillProof() {
		t.Error(`BillProof:null reports as present; it is four bytes, not a proof`)
	}
	if len(nullish.BillProof) == 0 {
		t.Fatal("test premise broken: `null` should be four bytes, which is why a length check fails")
	}

	spaced := Item{BillProof: json.RawMessage("  null  ")}
	if spaced.HasBillProof() {
		t.Error("whitespace-padded null reports as present")
	}

	real := Item{BillProof: json.RawMessage(`{"kind":23193}`)}
	if !real.HasBillProof() {
		t.Error("a genuine bill proof reports as absent")
	}
}

// TestEnvelope_RequiresABillProofOnEveryItem: unconditional, cash-mode included.
// The codec is a coherence aid rather than an authorization boundary — the hub
// verifies for itself — but catching it locally is the only place a caller can be
// TOLD, since the hub's answer is an information-free omission.
func TestEnvelope_RequiresABillProofOnEveryItem(t *testing.T) {
	_, hub := testKeypair(t)
	env := coherentEnvelope(t, hub, 2)

	env.Items[1].BillProof = nil
	if _, err := env.Encode(DefaultLimits()); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("Encode() = %v, want ErrEnvelopeMalformed for an item with no bill proof", err)
	}

	// And a bearer item is not exempt: its cash secret authorizes the SLICE, which
	// is a different claim from holding the bill.
	bearer := bearerItem(t, "b")
	bearer.BillProof = nil
	env2 := coherentEnvelope(t, hub, 1)
	env2.Items = append(env2.Items, bearer)
	if _, err := env2.Encode(DefaultLimits()); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("Encode() = %v, want ErrEnvelopeMalformed — a bearer item still needs a bill proof", err)
	}
}
