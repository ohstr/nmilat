package nipcash

import (
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

func itemTestKeypair(t *testing.T) (privHex, xonlyHex string) {
	t.Helper()
	priv := randomKeyHex(t)
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func testBinding(t *testing.T, hubXOnly string) ItemBinding {
	t.Helper()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return ItemBinding{HubXOnly: hubXOnly, Nonce: nonce, NotAfter: time.Now().Add(60 * time.Second).Unix()}
}

// TestItemConstructors_ProduceEnvelopesThatValidate is the whole point of building
// items in this package rather than letting callers assemble them.
//
// transport.Envelope.Validate exists because four kinds of incoherence — a proof
// bound to a different target, method or params, or to another envelope — are each
// answered by a hub with OMISSION, which is information-free, so a caller could
// never diagnose them. These constructors are the other half of that: they derive
// every one of those bindings from a single source, so there is no way to call them
// and get an item that fails validation.
//
// If this test ever fails, a caller can build an envelope whose failure they cannot
// diagnose.
func TestItemConstructors_ProduceEnvelopesThatValidate(t *testing.T) {
	hubPriv, hubXOnly := itemTestKeypair(t)
	_ = hubPriv
	b := testBinding(t, hubXOnly)

	billPriv, billTarget := itemTestKeypair(t)
	otherPriv, otherTarget := itemTestKeypair(t)

	amount := uint64(1000)
	items := []struct {
		name string
		make func() (transport.Item, error)
	}{
		{"cash_status", func() (transport.Item, error) {
			return StatusItem("s1", billTarget, BySigning(billPriv), b)
		}},
		{"cash_redeem", func() (transport.Item, error) {
			return CashRedeemParams{
				Invoice:    testInvoice,
				Credential: BySigning(billPriv),
				Amount:     &amount,
			}.Item("r1", billTarget, b)
		}},
		{"cash_redeem, bearer", func() (transport.Item, error) {
			return CashRedeemParams{
				Invoice:    testInvoice,
				Credential: BySecret("a-cash-secret"),
			}.Item("r2", otherTarget, b)
		}},
		{"cash_status, second bill, different key", func() (transport.Item, error) {
			return StatusItem("s2", otherTarget, BySigning(otherPriv), b)
		}},
	}

	env := transport.Envelope{Version: transport.EnvelopeVersion, NotAfter: b.NotAfter, Nonce: b.Nonce}
	replyTo, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	env.ReplyTo = replyTo

	for _, tc := range items {
		item, err := tc.make()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		env.Items = append(env.Items, item)
	}

	// Shape, then semantics. Both must pass with no fixing up in between.
	if _, err := env.Encode(transport.DefaultLimits()); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if err := env.Validate(hubXOnly, time.Now()); err != nil {
		t.Fatalf("Validate() error = %v — a constructor produced an item whose failure "+
			"a caller could not have diagnosed", err)
	}
}

// TestItemConstructors_BearerCarriesNoProof: the bearer path must genuinely omit the
// proof, not attach an empty or placeholder one, or VerificationCost and the hub's
// bearer handling would both be wrong.
func TestItemConstructors_BearerCarriesNoProof(t *testing.T) {
	_, hubXOnly := itemTestKeypair(t)
	_, target := itemTestKeypair(t)
	b := testBinding(t, hubXOnly)

	item, err := CashRedeemParams{
		Invoice:    testInvoice,
		Credential: BySecret("a-cash-secret"),
	}.Item("r1", target, b)
	if err != nil {
		t.Fatal(err)
	}

	if len(item.Proof) != 0 {
		t.Errorf("bearer item carries a proof (%d bytes); it must carry none", len(item.Proof))
	}
	if !item.IsBearer() {
		t.Error("transport does not recognise the item as bearer — the secret did not reach params")
	}
	if got := item.VerificationCost(); got != 0 {
		t.Errorf("VerificationCost() = %d, want 0", got)
	}
}

// TestItemConstructors_CapturedProofIsRefusedLocally: ByProof holds a finished
// kind-23198, not a key, so it cannot sign the kind-23192 an item needs. It must fail
// HERE, with a reason, rather than produce an item a hub silently omits.
func TestItemConstructors_CapturedProofIsRefusedLocally(t *testing.T) {
	_, hubXOnly := itemTestKeypair(t)
	billPriv, target := itemTestKeypair(t)
	b := testBinding(t, hubXOnly)

	// A real captured proof, built the way a caller would have obtained one.
	signed, err := CashRedeemParams{Invoice: testInvoice, Credential: BySigning(billPriv)}.Request(target)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := ByProof([]byte(signed.IdentityEvent))
	if err != nil {
		t.Fatalf("ByProof() error = %v", err)
	}

	_, err = CashRedeemParams{Invoice: testInvoice, Credential: captured}.Item("r1", target, b)
	if !errors.Is(err, ErrCapturedProofNotBatchable) {
		t.Fatalf("Item() error = %v, want ErrCapturedProofNotBatchable", err)
	}
}

// TestItemConstructors_RefuseAnUnservableMethod guards the one thing a constructor
// cannot derive: the method is an argument in buildItem, and an unservable one must
// be refused locally rather than sent to be omitted.
func TestItemConstructors_RefuseAnUnservableMethod(t *testing.T) {
	_, hubXOnly := itemTestKeypair(t)
	billPriv, target := itemTestKeypair(t)
	b := testBinding(t, hubXOnly)

	if _, err := buildItem("m1", target, MethodMintCash, struct{}{}, BySigning(billPriv), b); err == nil {
		t.Fatal("buildItem() = nil error for mint_cash; it is not servable over this transport")
	}
}
