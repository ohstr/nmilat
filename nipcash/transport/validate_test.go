package transport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// coherentEnvelope builds an envelope that is actually valid: every item bound to
// ONE hub, with a proof matching its own target, method, params and this envelope's
// nonce. Nothing in this package built such a thing before — newTestEnvelope's
// helper generates a fresh random hub per item, which is shape-valid and
// semantically nonsense.
func coherentEnvelope(t *testing.T, hubXOnly string, bills int) Envelope {
	t.Helper()

	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	replyTo, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(60 * time.Second).Unix()

	env := Envelope{Version: EnvelopeVersion, NotAfter: notAfter, Nonce: nonce, ReplyTo: replyTo}
	for i := 0; i < bills; i++ {
		billPriv, billTarget := testKeypair(t)
		const params = `{}`
		hash, err := CanonicalParamsHash(json.RawMessage(params))
		if err != nil {
			t.Fatal(err)
		}
		proof, err := BuildItemProof(billPriv, ProofBinding{
			Target: billTarget, HubXOnly: hubXOnly, Method: "cash_status",
			ParamsHash: hash, Nonce: nonce, NotAfter: notAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
		env.Items = append(env.Items, Item{
			ID: strings.Repeat("i", i+1), Target: billTarget,
			Method: "cash_status", Params: json.RawMessage(params), Proof: proof,
		})
	}
	return env
}

// TestValidate_AcceptsACoherentMultiBillEnvelope: the shape the transport exists
// for — several different bills, each signed by a different key, one hub.
func TestValidate_AcceptsACoherentMultiBillEnvelope(t *testing.T) {
	_, hub := testKeypair(t)
	env := coherentEnvelope(t, hub, 6)

	if err := env.Validate(hub, time.Now()); err != nil {
		t.Fatalf("Validate() error = %v, want nil for a coherent 6-bill envelope", err)
	}
	// And it must still satisfy the shape rules, so the two checks compose.
	if _, err := env.Encode(DefaultLimits()); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
}

// TestValidate_CatchesWhatTheHubAnswersWithSilence is F3.
//
// Every case below is shape-valid — Encode accepts it — and unservable. At the hub
// each produces OMISSION, which is deliberately information-free, so the client
// could never tell these apart from "that bill isn't here". Local validation is the
// only place they are diagnosable, which is why each one must be caught here.
func TestValidate_CatchesWhatTheHubAnswersWithSilence(t *testing.T) {
	_, hub := testKeypair(t)

	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, env *Envelope)
		wantErr error
	}{
		{
			name: "proof bound to a different target",
			mutate: func(t *testing.T, env *Envelope) {
				_, other := testKeypair(t)
				env.Items[0].Target = other // proof still names the original
			},
			wantErr: ErrProofWrongTarget,
		},
		{
			name: "proof bound to a different method",
			mutate: func(t *testing.T, env *Envelope) {
				// The dangerous direction: a status read turned into a transfer.
				env.Items[0].Method = "cash_transfer"
			},
			wantErr: ErrProofWrongMethod,
		},
		{
			name: "params changed after the proof was built",
			mutate: func(t *testing.T, env *Envelope) {
				// What a re-pointed cash_redeem invoice looks like on the wire.
				env.Items[0].Params = json.RawMessage(`{"invoice":"lnbc-attacker"}`)
			},
			wantErr: ErrProofWrongParams,
		},
		{
			name: "proofs carry a stale envelope nonce",
			mutate: func(t *testing.T, env *Envelope) {
				// Regenerating the nonce without rebuilding proofs — the exact
				// mistake a retry path makes.
				fresh, err := NewNonce()
				if err != nil {
					t.Fatal(err)
				}
				env.Nonce = fresh
			},
			wantErr: ErrProofWrongNonce,
		},
		{
			name: "an item bound to a different hub",
			mutate: func(t *testing.T, env *Envelope) {
				_, otherHub := testKeypair(t)
				env.Items = append(env.Items, coherentEnvelope(t, otherHub, 1).Items[0])
				// Give it a unique id so shape validation still passes.
				env.Items[len(env.Items)-1].ID = "foreign"
			},
			wantErr: ErrEnvelopeMixedHubs,
		},
		{
			name: "a method the transport does not serve",
			mutate: func(t *testing.T, env *Envelope) {
				env.Items[0].Method = "mint_cash"
			},
			wantErr: ErrMethodNotServable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := coherentEnvelope(t, hub, 2)
			tc.mutate(t, &env)

			// Precondition: this is SHAPE-valid. If Encode rejected it the case
			// would be proving nothing about Validate.
			if _, err := env.Encode(DefaultLimits()); err != nil {
				t.Fatalf("precondition failed — Encode rejected it (%v), so this case "+
					"does not demonstrate a semantic-only defect", err)
			}

			err := env.Validate(hub, time.Now())
			if err == nil {
				t.Fatal("Validate() = nil; the hub would answer this with silence")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Validate() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidate_RejectsStaleProofs: a proof already outside its freshness window
// locally is certainly stale at the hub, so there is no reason to send it.
func TestValidate_RejectsStaleProofs(t *testing.T) {
	_, hub := testKeypair(t)
	env := coherentEnvelope(t, hub, 1)

	future := time.Now().Add(ProofFreshnessPast + time.Minute)
	if err := env.Validate(hub, future); !errors.Is(err, ErrProofStale) {
		t.Fatalf("Validate() error = %v, want ErrProofStale", err)
	}
}

// TestValidate_RejectsAWrongHubEvenWhenInternallyConsistent: an envelope whose
// items all agree with each other but name a hub other than the one being addressed
// is still unservable. Consistency is not sufficient — it has to be THIS hub.
func TestValidate_RejectsAWrongHubEvenWhenInternallyConsistent(t *testing.T) {
	_, hubA := testKeypair(t)
	_, hubB := testKeypair(t)

	env := coherentEnvelope(t, hubA, 3)
	if err := env.Validate(hubA, time.Now()); err != nil {
		t.Fatalf("sanity: envelope must be valid for its own hub, got %v", err)
	}
	if err := env.Validate(hubB, time.Now()); !errors.Is(err, ErrEnvelopeMixedHubs) {
		t.Fatalf("Validate() against another hub = %v, want ErrEnvelopeMixedHubs", err)
	}
}

func TestIsServableMethod(t *testing.T) {
	for _, m := range []string{
		"cash_status", "cash_redeem",
		"cash_transfer", "cash_consolidate", "create_circle_wallet",
	} {
		if !IsServableMethod(m) {
			t.Errorf("IsServableMethod(%q) = false, want true", m)
		}
	}
	// mint_cash is the one deliberate exclusion: hub-owner method, and the only
	// one with no retry idempotency.
	for _, m := range []string{"mint_cash", "get_balance", "pay_invoice", "", "cash_status "} {
		if IsServableMethod(m) {
			t.Errorf("IsServableMethod(%q) = true, want false", m)
		}
	}
}

// bearerItem builds a cash-mode item: a secret in params and NO proof, which is
// what a bearer bill can actually produce. A cash credential has no keypair, so
// there is no kind-23192 proof available to it at all.
func bearerItem(t *testing.T, id string) Item {
	t.Helper()
	_, target := testKeypair(t)
	return Item{
		ID:     id,
		Target: target,
		Method: "cash_redeem",
		Params: json.RawMessage(`{"invoice":"lnbc1","cash_secret":"deadbeef"}`),
	}
}

// TestBearerItems_AreValidWithoutAProof is the bearer-bill decision.
//
// Two of the four credential kinds — BySecret and ByProof — have no signing key, so
// they cannot build a kind-23192 item proof. Requiring one would shut bearer bills
// out of the private transport entirely, which is backwards: they are arguably the
// bills most in need of the privacy batching provides.
//
// It is sound because the proof's binding adds nothing for a bearer bill. Anyone
// holding the envelope already holds the secret and could spend it regardless, so
// there is no substitution a proof would prevent. And the reason NIP-CASH bans
// cash-mode sources from cash_consolidate does not apply here: that ban is about a
// secret sitting in a request readable by co-recipients of a SHARED calling
// connection, while this transport encrypts to the hub's inbox alone.
func TestBearerItems_AreValidWithoutAProof(t *testing.T) {
	_, hub := testKeypair(t)

	env := coherentEnvelope(t, hub, 1)
	env.Items = append(env.Items, bearerItem(t, "bearer"))

	if _, err := env.Encode(DefaultLimits()); err != nil {
		t.Fatalf("Encode() error = %v; a proofless cash-mode item must encode", err)
	}
	if err := env.Validate(hub, time.Now()); err != nil {
		t.Fatalf("Validate() error = %v; a proofless cash-mode item must validate", err)
	}
}

// TestBearerItems_MixFreelyWithIdentityBoundOnes: one envelope may carry both kinds,
// which is the realistic case — a wallet holds whatever it was given.
func TestBearerItems_MixFreelyWithIdentityBoundOnes(t *testing.T) {
	_, hub := testKeypair(t)

	env := coherentEnvelope(t, hub, 3)
	env.Items = append(env.Items, bearerItem(t, "b1"), bearerItem(t, "b2"))

	if _, err := env.Encode(DefaultLimits()); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if err := env.Validate(hub, time.Now()); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

// TestProoflessItem_WithoutASecretIsStillRejected: dropping a proof is only
// legitimate when a secret takes its place. An item with neither authorizes nothing
// and must not encode.
func TestProoflessItem_WithoutASecretIsStillRejected(t *testing.T) {
	_, hub := testKeypair(t)

	env := coherentEnvelope(t, hub, 1)
	env.Items[0].Proof = nil // no proof, and params carry no cash_secret

	if _, err := env.Encode(DefaultLimits()); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("Encode() error = %v, want ErrEnvelopeMalformed", err)
	}
	_ = hub
}

// TestBearerItem_MustNotCarryBothSecretAndProof: the two authorize differently and
// an item asserting both is incoherent — a hub would have to choose, and either
// choice hides the caller's mistake.
func TestBearerItem_MustNotCarryBothSecretAndProof(t *testing.T) {
	_, hub := testKeypair(t)

	env := coherentEnvelope(t, hub, 1)
	// Graft a secret onto an item that already has a real proof.
	env.Items[0].Params = json.RawMessage(`{"cash_secret":"deadbeef"}`)

	if err := env.Validate(hub, time.Now()); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("Validate() error = %v, want ErrEnvelopeMalformed", err)
	}
}

// TestBearerItem_CostsNoVerificationBudget: a hub's verify budget exists to bound
// signature work. A bearer item involves none, so charging it would make a hub
// refuse batches it could comfortably serve.
func TestBearerItem_CostsNoVerificationBudget(t *testing.T) {
	bearer := bearerItem(t, "b")
	if got := bearer.VerificationCost(); got != 0 {
		t.Errorf("bearer VerificationCost() = %d, want 0 — there is no signature to verify", got)
	}

	_, hub := testKeypair(t)
	identityBound := coherentEnvelope(t, hub, 1).Items[0]
	if got := identityBound.VerificationCost(); got != 1 {
		t.Errorf("identity-bound VerificationCost() = %d, want 1", got)
	}
}
