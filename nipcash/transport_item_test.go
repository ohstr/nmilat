package nipcash

import (
	"errors"
	"strings"
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
			return StatusItem("s1", billTarget, CashStatusParams{}, BySigning(billPriv), b)
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
			return StatusItem("s2", otherTarget, CashStatusParams{}, BySigning(otherPriv), b)
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

// TestIsValidCashStatusScope pins the shared rule. It is exported precisely so a
// client and a Hub check the same list — each keeping its own is the kind of drift
// that surfaces as a request silently answered with the wrong amount of data.
func TestIsValidCashStatusScope(t *testing.T) {
	for _, s := range []string{"", ScopeAll, ScopeMine} {
		if !IsValidCashStatusScope(s) {
			t.Errorf("IsValidCashStatusScope(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"ALL", "Mine", "everything", "own", " mine"} {
		if IsValidCashStatusScope(s) {
			t.Errorf("IsValidCashStatusScope(%q) = true, want false", s)
		}
	}
}

// TestStatusItem_RejectsAnUnknownScopeLocally matters because of how a hub answers
// a malformed item: it omits it, and an omission is information-free by design. A
// caller who sent an unknown scope would learn nothing about why their item
// vanished, so the only place they can ever find out is here.
func TestStatusItem_RejectsAnUnknownScopeLocally(t *testing.T) {
	priv, pub := itemTestKeypair(t)
	b := ItemBinding{HubXOnly: pub, Nonce: strings.Repeat("11", 32), NotAfter: time.Now().Add(time.Minute).Unix()}

	if _, err := StatusItem("s1", pub, CashStatusParams{Scope: "everything"}, BySigning(priv), b); err == nil {
		t.Fatal("StatusItem accepted an unknown scope, want a local error")
	}
	// The two real values, and absent, must all build.
	for _, scope := range []string{"", ScopeAll, ScopeMine} {
		if _, err := StatusItem("s1", pub, CashStatusParams{Scope: scope}, BySigning(priv), b); err != nil {
			t.Errorf("StatusItem(scope=%q) error = %v, want accepted", scope, err)
		}
	}
}

// TestStatusItem_ScopeTravelsInParams confirms the scope actually reaches the wire
// — and that an absent one sends no scope field at all, which is what lets a hub
// apply its own transport-specific default rather than receiving a guess.
func TestStatusItem_ScopeTravelsInParams(t *testing.T) {
	priv, pub := itemTestKeypair(t)
	b := ItemBinding{HubXOnly: pub, Nonce: strings.Repeat("11", 32), NotAfter: time.Now().Add(time.Minute).Unix()}

	item, err := StatusItem("s1", pub, CashStatusParams{Scope: ScopeAll}, BySigning(priv), b)
	if err != nil {
		t.Fatalf("StatusItem: %v", err)
	}
	if got := string(item.Params); !strings.Contains(got, `"scope":"all"`) {
		t.Errorf("params = %s, want the scope to travel", got)
	}

	bare, err := StatusItem("s1", pub, CashStatusParams{}, BySigning(priv), b)
	if err != nil {
		t.Fatalf("StatusItem: %v", err)
	}
	if got := string(bare.Params); strings.Contains(got, "scope") {
		t.Errorf("params = %s, want no scope field at all so the hub applies its own default", got)
	}
}

// TestStatusItem_CashModeCarriesItsSecret is the regression test for a bug that made
// cash-mode bills unreadable over the private transport entirely.
//
// buildItem returns early for a cash-mode credential, on the explicit assumption
// that the secret is already inside wireParams because "every params type puts it
// there via buildProof". cash_status had no such field and no such path, so its item
// came out with NEITHER a proof NOR a secret — malformed, refused by the codec, and
// therefore never even sent. The failure surfaced only against a live hub.
func TestStatusItem_CashModeCarriesItsSecret(t *testing.T) {
	_, pub := itemTestKeypair(t)
	b := ItemBinding{HubXOnly: pub, Nonce: strings.Repeat("11", 32), NotAfter: time.Now().Add(time.Minute).Unix()}

	item, err := StatusItem("s1", pub, CashStatusParams{Scope: ScopeMine}, BySecret("the-secret"), b)
	if err != nil {
		t.Fatalf("StatusItem(cash-mode): %v", err)
	}
	if len(item.Proof) != 0 {
		t.Error("a cash-mode item must carry no proof — there is no key to sign with")
	}
	if !item.IsBearer() {
		t.Fatalf("a cash-mode item must be recognisable as a bearer item, or the codec refuses it as malformed: params=%s", item.Params)
	}
	if !strings.Contains(string(item.Params), "the-secret") {
		t.Errorf("the cash secret never reached the params: %s", item.Params)
	}
	// The scope must survive alongside it.
	if !strings.Contains(string(item.Params), `"scope":"mine"`) {
		t.Errorf("the scope was lost when the request type changed: %s", item.Params)
	}
}
