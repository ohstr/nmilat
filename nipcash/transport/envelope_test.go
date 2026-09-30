package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// newTestEnvelope builds a valid single-item envelope with a real signed proof.
func newTestEnvelope(t *testing.T, items ...Item) Envelope {
	t.Helper()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	replyTo, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		items = []Item{newTestItem(t, "1", "cash_status", `{}`, nonce)}
	}
	return Envelope{
		Version:  EnvelopeVersion,
		NotAfter: time.Now().Add(60 * time.Second).Unix(),
		Nonce:    nonce,
		ReplyTo:  replyTo,
		Items:    items,
	}
}

func newTestItem(t *testing.T, id, method, params, nonce string) Item {
	t.Helper()
	connPriv, _ := testKeypair(t)
	_, hubXOnly := testKeypair(t)
	_, target := testKeypair(t)

	hash, err := CanonicalParamsHash(json.RawMessage(params))
	if err != nil {
		t.Fatal(err)
	}
	binding := ProofBinding{
		Target: target, HubXOnly: hubXOnly, Method: method,
		ParamsHash: hash, Nonce: nonce, NotAfter: time.Now().Add(60 * time.Second).Unix(),
	}
	proof, err := BuildItemProof(connPriv, binding)
	if err != nil {
		t.Fatal(err)
	}
	// A distinct key from the slice proof's, so a fixture can never pass by having
	// signed both with the same one — the two proofs answer different questions and
	// are meant to be separable.
	billPriv, _ := testKeypair(t)
	billProof, err := BuildBillProof(billPriv, binding)
	if err != nil {
		t.Fatal(err)
	}
	return Item{
		ID: id, Target: target, Method: method, Params: json.RawMessage(params),
		Proof: proof, BillProof: billProof,
	}
}

func TestEnvelope_RoundTrip(t *testing.T) {
	limits := DefaultLimits()
	original := newTestEnvelope(t)

	plaintext, err := original.Encode(limits)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(plaintext, limits)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if decoded.Nonce != original.Nonce || decoded.ReplyTo != original.ReplyTo {
		t.Error("nonce or reply_to did not survive the round trip")
	}
	if len(decoded.Items) != 1 || decoded.Items[0].ID != "1" {
		t.Fatalf("items did not survive: %+v", decoded.Items)
	}
	// The params bytes must survive intact, because the proof binds their hash.
	gotHash, err := CanonicalParamsHash(decoded.Items[0].Params)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, err := CanonicalParamsHash(original.Items[0].Params)
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != wantHash {
		t.Error("params hash changed across the round trip, which would invalidate every proof")
	}
}

// TestEnvelope_EncodePadsToBuckets is the size-leak property end to end: whatever
// is inside, the plaintext handed to NIP-44 lands on a bucket boundary.
func TestEnvelope_EncodePadsToBuckets(t *testing.T) {
	limits := DefaultLimits()

	sizes := map[int]struct{}{}
	for items := 1; items <= 8; items++ {
		env := newTestEnvelope(t)
		for i := 2; i <= items; i++ {
			env.Items = append(env.Items, newTestItem(t, fmt.Sprintf("%d", i), "cash_status", `{}`, env.Nonce))
		}
		plaintext, err := env.Encode(limits)
		if err != nil {
			t.Fatalf("Encode with %d items: %v", items, err)
		}
		if len(plaintext)%limits.PadBucketBytes != 0 {
			t.Errorf("%d items encoded to %d bytes, not a multiple of %d",
				items, len(plaintext), limits.PadBucketBytes)
		}
		sizes[len(plaintext)] = struct{}{}
	}
	// 1 through 8 small items must not each have their own distinguishable size;
	// if they did, padding would be disclosing the batch count.
	if len(sizes) > 3 {
		t.Errorf("1-8 items produced %d distinct wire sizes, padding is leaking batch size", len(sizes))
	}
	t.Logf("1-8 items collapse to %d distinct padded sizes", len(sizes))
}

func TestEnvelope_RejectsMalformedShape(t *testing.T) {
	limits := DefaultLimits()

	tests := map[string]struct {
		tamper func(*Envelope)
		want   error
	}{
		"wrong version":      {func(e *Envelope) { e.Version = 99 }, ErrEnvelopeVersion},
		"no items":           {func(e *Envelope) { e.Items = nil }, ErrEnvelopeNoItems},
		"short nonce":        {func(e *Envelope) { e.Nonce = "abcd" }, ErrEnvelopeMalformed},
		"uppercase nonce":    {func(e *Envelope) { e.Nonce = strings.ToUpper(e.Nonce) }, ErrEnvelopeMalformed},
		"short reply_to":     {func(e *Envelope) { e.ReplyTo = "00" }, ErrEnvelopeMalformed},
		"item without id":    {func(e *Envelope) { e.Items[0].ID = "" }, ErrEnvelopeMalformed},
		"item without proof": {func(e *Envelope) { e.Items[0].Proof = nil }, ErrEnvelopeMalformed},
		"item bad target":    {func(e *Envelope) { e.Items[0].Target = "xyz" }, ErrEnvelopeMalformed},
		"item no method":     {func(e *Envelope) { e.Items[0].Method = "" }, ErrEnvelopeMalformed},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newTestEnvelope(t)
			tc.tamper(&env)
			if _, err := env.Encode(limits); !errors.Is(err, tc.want) {
				t.Errorf("Encode() = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestEnvelope_RejectsDuplicateItemID matters because the response demuxes by id:
// two items sharing one would make a result ambiguous about which request it
// answers.
func TestEnvelope_RejectsDuplicateItemID(t *testing.T) {
	env := newTestEnvelope(t)
	env.Items = append(env.Items, newTestItem(t, "1", "cash_status", `{}`, env.Nonce))

	if _, err := env.Encode(DefaultLimits()); !errors.Is(err, ErrDuplicateItemID) {
		t.Fatalf("Encode() = %v, want ErrDuplicateItemID", err)
	}
}

func TestEnvelope_RejectsTooManyItems(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxItems = 3

	env := newTestEnvelope(t)
	for i := 2; i <= 5; i++ {
		env.Items = append(env.Items, newTestItem(t, fmt.Sprintf("%d", i), "cash_status", `{}`, env.Nonce))
	}
	if _, err := env.Encode(limits); !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("Encode() = %v, want ErrTooManyItems", err)
	}
}

// TestEnvelope_VerificationBudgetIsCountedStructurally is the DoS property, and the
// assertion is about ORDER as much as outcome: the envelope must be refused from
// the shape of its params alone, with no signature verified. Here that is shown by
// the proofs being deliberate nonsense — if anything tried to verify them it would
// fail differently, or cost the time the budget exists to prevent.
func TestEnvelope_VerificationBudgetIsCountedStructurally(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxVerifyBudget = 10
	limits.MaxConsolidateSources = 50

	sources := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		sources = append(sources, `{"wallet_pubkey":"aa","identity_event":"{}"}`)
	}
	params := `{"sources":[` + strings.Join(sources, ",") + `]}`

	env := newTestEnvelope(t)
	env.Items = []Item{{
		ID: "1", Target: strings.Repeat("a", 64), Method: "cash_consolidate",
		Params:    json.RawMessage(params),
		Proof:     json.RawMessage(`{"not":"a real proof"}`),
		BillProof: json.RawMessage(`{"not":"a real proof"}`),
	}}

	_, err := env.Encode(limits)
	if !errors.Is(err, ErrVerifyBudgetExceeded) {
		t.Fatalf("Encode() = %v, want ErrVerifyBudgetExceeded", err)
	}
}

// Every cost below counts TWO signatures for an identity-bound item, not one: the
// kind-23192 slice proof and the kind-23193 bill proof. The bill proof is
// unconditional, so it is the baseline every case starts from.
//
// This is the hub's DoS budget, so undercounting is the dangerous direction — it
// would admit a batch that costs more secp256k1 time than the hub authorised.
func TestItem_VerificationCost(t *testing.T) {
	tests := map[string]struct {
		params string
		want   int
	}{
		"no params":               {`{}`, 2},
		"simple method":           {`{"invoice":"lnbc1"}`, 2},
		"two sources with proofs": {`{"sources":[{"identity_event":"{}"},{"identity_event":"{}"}]}`, 4},
		"source with attestation": {`{"sources":[{"identity_event":"{}","attestation_event":"{}"}]}`, 4},
		"sources without proofs":  {`{"sources":[{"wallet_pubkey":"aa"},{"wallet_pubkey":"bb"}]}`, 2},
		"unparseable params":      {`{oops`, 2},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Proof set, so this is an identity-bound item: slice proof + bill proof.
			item := Item{Params: json.RawMessage(tc.params), Proof: json.RawMessage(`{}`)}
			if got := item.VerificationCost(); got != tc.want {
				t.Errorf("VerificationCost() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestEnvelope_RejectsTooManyConsolidateSources is the cap that exists because a
// maximal consolidate cannot be encrypted at all.
func TestEnvelope_RejectsTooManyConsolidateSources(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxConsolidateSources = 4

	sources := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		sources = append(sources, `{"wallet_pubkey":"aa"}`)
	}
	env := newTestEnvelope(t)
	env.Items = []Item{{
		ID: "1", Target: strings.Repeat("a", 64), Method: "cash_consolidate",
		Params:    json.RawMessage(`{"sources":[` + strings.Join(sources, ",") + `]}`),
		Proof:     json.RawMessage(`{}`),
		BillProof: json.RawMessage(`{}`),
	}}

	if _, err := env.Encode(limits); !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("Encode() = %v, want ErrTooManyItems", err)
	}
}

// TestEnvelope_DecodeRejectsOversizePlaintext guards the receive side: an
// attacker is not bound by our encoder.
func TestEnvelope_DecodeRejectsOversizePlaintext(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxEnvelopeBytes = 4096
	limits.PadBucketBytes = 1024
	limits.MaxConsolidateSources = 3

	oversize := make([]byte, limits.MaxEnvelopeBytes+1)
	if _, err := Decode(oversize, limits); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Fatalf("Decode() = %v, want ErrEnvelopeTooLarge", err)
	}
}

func TestEnvelope_CheckFreshness(t *testing.T) {
	now := time.Now()
	env := Envelope{NotAfter: now.Add(60 * time.Second).Unix()}

	if err := env.CheckFreshness(now); err != nil {
		t.Errorf("a 60s window must be accepted: %v", err)
	}
	if err := env.CheckFreshness(now.Add(2 * time.Minute)); !errors.Is(err, ErrEnvelopeExpired) {
		t.Errorf("CheckFreshness past not_after = %v, want ErrEnvelopeExpired", err)
	}

	// A client must not be able to mint itself an arbitrarily long-lived envelope:
	// not_after also bounds how long the hub has to remember the nonce.
	greedy := Envelope{NotAfter: now.Add(time.Hour).Unix()}
	if err := greedy.CheckFreshness(now); !errors.Is(err, ErrEnvelopeTooFresh) {
		t.Errorf("CheckFreshness with an hour-long window = %v, want ErrEnvelopeTooFresh", err)
	}
}

// FuzzDecode checks the decoder never panics on hostile input. It runs before any
// signature work, so it is the first thing an attacker reaches.
func FuzzDecode(f *testing.F) {
	limits := DefaultLimits()

	env := Envelope{
		Version: EnvelopeVersion, NotAfter: time.Now().Unix(),
		Nonce: strings.Repeat("a", 64), ReplyTo: strings.Repeat("b", 64),
		Items: []Item{{ID: "1", Target: strings.Repeat("c", 64), Method: "cash_status",
			Params: json.RawMessage(`{}`), Proof: json.RawMessage(`{}`)}},
	}
	seed, err := json.Marshal(env)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"v":1,"items":[]}`))
	f.Add([]byte(`{"v":1,"nonce":"","items":[{"id":"1"}]}`))
	f.Add([]byte(`{"v":1,"items":[{"id":"1","params":{`))
	f.Add([]byte(`{"v":1,"not_after":-9223372036854775808,"items":[{"id":"a"}]}`))
	f.Add([]byte(`{"v":1,"pad":"aaaa","items":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := Decode(data, limits)
		if err != nil {
			return
		}
		// Anything that decoded must satisfy every invariant the checks promise,
		// so a later stage can rely on them without re-checking.
		if decoded.Version != EnvelopeVersion {
			t.Fatalf("accepted version %d", decoded.Version)
		}
		if len(decoded.Items) == 0 || len(decoded.Items) > limits.MaxItems {
			t.Fatalf("accepted %d items", len(decoded.Items))
		}
		if len(decoded.Nonce) != keyHexLen || len(decoded.ReplyTo) != keyHexLen {
			t.Fatal("accepted a malformed nonce or reply_to")
		}
		seen := map[string]bool{}
		for _, item := range decoded.Items {
			if item.ID == "" || seen[item.ID] {
				t.Fatalf("accepted a missing or duplicate item id %q", item.ID)
			}
			seen[item.ID] = true
			if len(item.Target) != keyHexLen || item.Method == "" || len(item.Proof) == 0 {
				t.Fatal("accepted an incomplete item")
			}
		}
	})
}

// TestItem_ProofSurvivesARoundTripAsAbsent is the regression test for the bug that
// made cash-mode bills impossible to serve over the private transport.
//
// `Proof json.RawMessage` without omitempty marshals a nil proof to `"proof":null`,
// and decoding that literal yields a FOUR-BYTE value. So `len(Proof) == 0` was false
// on the receiving side, a proofless bearer item looked like it carried a proof, the
// hub verified garbage, failed, and OMITTED the item — which is information-free by
// design, so no client could ever learn why its cash-mode bill vanished.
//
// Two assertions, because either alone is insufficient: the wire form must not carry
// a null, AND HasProof must be right even if a peer sends one anyway.
func TestItem_ProofSurvivesARoundTripAsAbsent(t *testing.T) {
	bearer := Item{ID: "b1", Target: "aa", Method: "cash_status", Params: []byte(`{"cash_secret":"s"}`)}
	if bearer.HasProof() {
		t.Fatal("a freshly built bearer item must not report a proof")
	}

	encoded, err := json.Marshal(bearer)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "null") {
		t.Errorf("a nil proof must be omitted, not serialized as null: %s", encoded)
	}

	var back Item
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back.HasProof() {
		t.Errorf("a bearer item grew a proof across a round trip: proof=%q", back.Proof)
	}

	// A peer that sends an explicit null must not fool us either — this is the
	// spelling that caused the original failure, and nothing stops another
	// implementation from emitting it.
	var explicitNull Item
	if err := json.Unmarshal([]byte(`{"id":"b1","proof":null}`), &explicitNull); err != nil {
		t.Fatal(err)
	}
	if explicitNull.HasProof() {
		t.Errorf(`an explicit "proof":null must read as no proof, got %q`, explicitNull.Proof)
	}

	// And a real proof must still read as present.
	withProof := Item{ID: "p1", Proof: []byte(`{"kind":23192}`)}
	if !withProof.HasProof() {
		t.Error("a real proof must read as present")
	}
}
