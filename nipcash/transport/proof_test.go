package transport

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
)

func testKeypair(t *testing.T) (privHex, xonlyHex string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(priv.Serialize()), hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
}

// testBinding returns a coherent binding plus the key that should sign it.
func testBinding(t *testing.T) (connPriv string, b ProofBinding) {
	t.Helper()
	connPriv, _ = testKeypair(t)
	_, hubXOnly := testKeypair(t)
	_, target := testKeypair(t)

	paramsHash, err := CanonicalParamsHash(json.RawMessage(`{"invoice":"lnbc1","amount":1000}`))
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return connPriv, ProofBinding{
		Target:     target,
		HubXOnly:   hubXOnly,
		Method:     "cash_redeem",
		ParamsHash: paramsHash,
		Nonce:      nonce,
		NotAfter:   time.Now().Add(60 * time.Second).Unix(),
	}
}

func TestItemProof_RoundTrip(t *testing.T) {
	priv, binding := testBinding(t)

	proof, err := BuildItemProof(priv, binding)
	if err != nil {
		t.Fatalf("BuildItemProof: %v", err)
	}
	signer, err := VerifyItemProof(proof, binding, time.Now())
	if err != nil {
		t.Fatalf("VerifyItemProof: %v", err)
	}

	var ev nip01.Event
	if err := json.Unmarshal(proof, &ev); err != nil {
		t.Fatal(err)
	}
	if signer != ev.PubKey {
		t.Errorf("signer = %q, want the proof's own pubkey %q", signer, ev.PubKey)
	}
	if ev.Kind != KindItemProof {
		t.Errorf("kind = %d, want %d", ev.Kind, KindItemProof)
	}
}

// TestItemProof_RejectsEverySubstitution is the attack matrix for one item.
//
// Each case is a substitution an aggregator could attempt: whoever assembles a
// batch holds OTHER PEOPLE'S signed proofs, so every field the proof commits to
// is a field they would otherwise be free to change.
func TestItemProof_RejectsEverySubstitution(t *testing.T) {
	otherHash, err := CanonicalParamsHash(json.RawMessage(`{"invoice":"lnbc-attacker","amount":1000}`))
	if err != nil {
		t.Fatal(err)
	}
	otherNonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		tamper func(*ProofBinding)
		want   error
	}{
		"re-pointed at another wallet":     {func(b *ProofBinding) { _, b.Target = mustKey(t) }, ErrProofWrongTarget},
		"replayed at another hub":          {func(b *ProofBinding) { _, b.HubXOnly = mustKey(t) }, ErrProofWrongHub},
		"method swapped for a transfer":    {func(b *ProofBinding) { b.Method = "cash_transfer" }, ErrProofWrongMethod},
		"params re-pointed at own invoice": {func(b *ProofBinding) { b.ParamsHash = otherHash }, ErrProofWrongParams},
		"lifted into another envelope":     {func(b *ProofBinding) { b.Nonce = otherNonce }, ErrProofWrongNonce},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			priv, signed := testBinding(t)
			proof, err := BuildItemProof(priv, signed)
			if err != nil {
				t.Fatal(err)
			}

			// The hub computes the binding from what it actually received, which
			// is where the attacker's substitution shows up.
			received := signed
			tc.tamper(&received)

			_, err = VerifyItemProof(proof, received, time.Now())
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyItemProof() = %v, want %v", err, tc.want)
			}
		})
	}
}

func mustKey(t *testing.T) (string, string) {
	t.Helper()
	return testKeypair(t)
}

// TestItemProof_RejectsForgedSignature covers the case where the attacker does not
// hold the connection key at all and simply signs with their own.
func TestItemProof_RejectsForgedSignature(t *testing.T) {
	_, binding := testBinding(t)
	attackerPriv, _ := testKeypair(t)

	// A structurally perfect proof, signed by the wrong key. It verifies as an
	// event — so only the pubkey the hub looks up afterwards distinguishes it.
	proof, err := BuildItemProof(attackerPriv, binding)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := VerifyItemProof(proof, binding, time.Now())
	if err != nil {
		t.Fatalf("a well-formed proof must verify; authorisation is the caller's job: %v", err)
	}

	var ev nip01.Event
	if err := json.Unmarshal(proof, &ev); err != nil {
		t.Fatal(err)
	}
	if signer != ev.PubKey {
		t.Fatal("VerifyItemProof must return the signer so the hub can decide whether it is the right one")
	}
	// The point: the returned pubkey is the ATTACKER's, so the hub's wallet
	// lookup is what refuses it. Verification proves possession of a key, never
	// that it is the right key.
	attackerXOnly, err := publicFromPrivate(attackerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if signer != attackerXOnly {
		t.Errorf("signer = %q, want the attacker's own pubkey %q", signer, attackerXOnly)
	}
}

func publicFromPrivate(privHex string) (string, error) {
	b, err := hex.DecodeString(privHex)
	if err != nil {
		return "", err
	}
	priv, _ := btcec.PrivKeyFromBytes(b)
	return hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey())), nil
}

// TestItemProof_RejectsTamperedSignature is the plain forgery: a real proof whose
// signature bytes were altered.
func TestItemProof_RejectsTamperedSignature(t *testing.T) {
	priv, binding := testBinding(t)
	proof, err := BuildItemProof(priv, binding)
	if err != nil {
		t.Fatal(err)
	}

	var ev nip01.Event
	if err := json.Unmarshal(proof, &ev); err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(ev.Sig)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	ev.Sig = hex.EncodeToString(sig)
	tampered, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyItemProof(tampered, binding, time.Now()); !errors.Is(err, ErrProofSignature) {
		t.Fatalf("VerifyItemProof() = %v, want ErrProofSignature", err)
	}
}

// TestItemProof_FreshnessWindow checks both edges. A proof from too long ago is a
// captured one; a proof from the future is a client trying to extend its own
// validity.
func TestItemProof_FreshnessWindow(t *testing.T) {
	priv, binding := testBinding(t)
	proof, err := BuildItemProof(priv, binding)
	if err != nil {
		t.Fatal(err)
	}
	signedAt := time.Now()

	// Just inside both edges.
	for _, now := range []time.Time{
		signedAt.Add(ProofFreshnessPast - time.Second),
		signedAt.Add(-(ProofFreshnessFuture - time.Second)),
	} {
		if _, err := VerifyItemProof(proof, binding, now); err != nil {
			t.Errorf("proof should be accepted at %v: %v", now.Sub(signedAt), err)
		}
	}
	// Just outside both edges.
	for _, now := range []time.Time{
		signedAt.Add(ProofFreshnessPast + 2*time.Second),
		signedAt.Add(-(ProofFreshnessFuture + 2*time.Second)),
	} {
		if _, err := VerifyItemProof(proof, binding, now); !errors.Is(err, ErrProofStale) {
			t.Errorf("proof should be stale at %v, got %v", now.Sub(signedAt), err)
		}
	}
}

// TestItemProof_RejectsDuplicateBindingTag closes an ambiguity that would itself be
// a substitution vector: a proof carrying two different method tags does not
// authorise one thing, and an implementation that silently took the first or last
// would let an attacker choose which.
func TestItemProof_RejectsDuplicateBindingTag(t *testing.T) {
	priv, binding := testBinding(t)

	tags := binding.tags()
	tags = append(tags, []string{tagMethod, "cash_transfer"})
	ev, err := nip01.NewSignedEvent(KindItemProof, "", priv, tags...)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyItemProof(proof, binding, time.Now()); !errors.Is(err, ErrProofMalformed) {
		t.Fatalf("VerifyItemProof() = %v, want ErrProofMalformed for a duplicate tag", err)
	}
}

func TestItemProof_RejectsMissingTagsAndWrongKind(t *testing.T) {
	priv, binding := testBinding(t)

	// Each binding tag omitted in turn.
	all := binding.tags()
	for i := range all {
		subset := make([][]string, 0, len(all)-1)
		for j, tag := range all {
			if j != i {
				subset = append(subset, tag)
			}
		}
		ev, err := nip01.NewSignedEvent(KindItemProof, "", priv, subset...)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		// The expiration tag is not part of the verified binding, so dropping it
		// is tolerated; every other omission must be refused.
		if all[i][0] == tagExpiration {
			continue
		}
		if _, err := VerifyItemProof(proof, binding, time.Now()); !errors.Is(err, ErrProofMalformed) {
			t.Errorf("omitting %q: got %v, want ErrProofMalformed", all[i][0], err)
		}
	}

	// A proof of the wrong kind, even correctly signed and bound.
	ev, err := nip01.NewSignedEvent(KindPrivateRequest, "", priv, binding.tags()...)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyItemProof(proof, binding, time.Now()); !errors.Is(err, ErrProofMalformed) {
		t.Errorf("wrong kind: got %v, want ErrProofMalformed", err)
	}
}

func TestBuildItemProof_RequiresAFullBinding(t *testing.T) {
	priv, full := testBinding(t)

	for name, tamper := range map[string]func(*ProofBinding){
		"no target":      func(b *ProofBinding) { b.Target = "" },
		"no hub":         func(b *ProofBinding) { b.HubXOnly = "" },
		"no method":      func(b *ProofBinding) { b.Method = "" },
		"no params hash": func(b *ProofBinding) { b.ParamsHash = "" },
		"no nonce":       func(b *ProofBinding) { b.Nonce = "" },
	} {
		t.Run(name, func(t *testing.T) {
			b := full
			tamper(&b)
			if _, err := BuildItemProof(priv, b); !errors.Is(err, ErrProofMalformed) {
				t.Fatalf("BuildItemProof() = %v, want ErrProofMalformed", err)
			}
		})
	}
}

// TestCanonicalParamsHash_IsStableAcrossSerialisation is what makes the params
// binding robust: two encodings of the same params must hash alike, or an
// intermediary reformatting JSON would break every proof for no visible reason.
func TestCanonicalParamsHash_IsStableAcrossSerialisation(t *testing.T) {
	same := []string{
		`{"invoice":"lnbc1","amount":1000}`,
		`{"amount":1000,"invoice":"lnbc1"}`,
		"{\n  \"invoice\": \"lnbc1\",\n  \"amount\": 1000\n}",
	}
	var want string
	for i, params := range same {
		got, err := CanonicalParamsHash(json.RawMessage(params))
		if err != nil {
			t.Fatalf("CanonicalParamsHash(%q): %v", params, err)
		}
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Errorf("CanonicalParamsHash(%q) = %s, want %s — reordering or whitespace changed the hash", params, got, want)
		}
	}

	// Absent and empty params must agree, so an item with neither is still bindable.
	empty, err := CanonicalParamsHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	braces, err := CanonicalParamsHash(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if empty != braces {
		t.Errorf("absent params hash %s != empty-object hash %s", empty, braces)
	}
}

// TestCanonicalParamsHash_PreservesLargeIntegers guards a real corruption risk:
// an amount in millis can exceed float64's exact integer range, and canonicalising
// through float64 would silently round it — changing what the caller signed for.
func TestCanonicalParamsHash_PreservesLargeIntegers(t *testing.T) {
	// 2^53 + 1 is the first integer float64 cannot represent exactly.
	a, err := CanonicalParamsHash(json.RawMessage(`{"amount_millis":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalParamsHash(json.RawMessage(`{"amount_millis":9007199254740992}`))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two amounts one apart hashed identically — precision was lost canonicalising")
	}
}

func TestCanonicalParamsHash_RejectsInvalidJSON(t *testing.T) {
	for _, bad := range []string{`{`, `{"a":}`, `{"a":1}{"b":2}`, `not json`} {
		if _, err := CanonicalParamsHash(json.RawMessage(bad)); err == nil {
			t.Errorf("CanonicalParamsHash(%q) succeeded, want an error", bad)
		}
	}
}
