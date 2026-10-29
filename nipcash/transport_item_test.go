package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
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

	items := []struct {
		name string
		make func() (transport.Item, error)
	}{
		{"cash_status", func() (transport.Item, error) {
			return StatusItem("s1", billTarget, connSecretFor(billTarget), CashStatusParams{}, BySigning(billPriv), b)
		}},
		{"cash_redeem", func() (transport.Item, error) {
			return CashRedeemParams{
				Invoice:    testInvoice,
				Credential: BySigning(billPriv),
			}.Item("r1", billTarget, connSecretFor(billTarget), b)
		}},
		{"cash_redeem, bearer", func() (transport.Item, error) {
			return CashRedeemParams{
				Invoice:    testInvoice,
				Credential: BySecret("a-cash-secret"),
			}.Item("r2", otherTarget, connSecretFor(otherTarget), b)
		}},
		{"cash_status, second bill, different key", func() (transport.Item, error) {
			return StatusItem("s2", otherTarget, connSecretFor(otherTarget), CashStatusParams{}, BySigning(otherPriv), b)
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
	}.Item("r1", target, connSecretFor(target), b)
	if err != nil {
		t.Fatal(err)
	}

	if len(item.Proof) != 0 {
		t.Errorf("bearer item carries a proof (%d bytes); it must carry none", len(item.Proof))
	}
	if !item.IsBearer() {
		t.Error("transport does not recognise the item as bearer — the secret did not reach params")
	}
	// One, not zero: no slice proof, but a bill proof like every other item. The
	// bearer saving is the slice proof, not the whole cost.
	if got := item.VerificationCost(); got != 1 {
		t.Errorf("VerificationCost() = %d, want 1 (bill proof only)", got)
	}
	if !item.HasBillProof() {
		t.Error("a bearer item must still carry a bill proof — holding the bill is a separate claim from holding the slice")
	}
}

// TestItemConstructors_RefuseAnUnservableMethod guards the one thing a constructor
// cannot derive: the method is an argument in buildItem, and an unservable one must
// be refused locally rather than sent to be omitted.
func TestItemConstructors_RefuseAnUnservableMethod(t *testing.T) {
	_, hubXOnly := itemTestKeypair(t)
	billPriv, target := itemTestKeypair(t)
	b := testBinding(t, hubXOnly)

	if _, err := buildItem("m1", target, connSecretFor(target), MethodMintCash, struct{}{}, BySigning(billPriv), b); err == nil {
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

	if _, err := StatusItem("s1", pub, connSecretFor(pub), CashStatusParams{Scope: "everything"}, BySigning(priv), b); err == nil {
		t.Fatal("StatusItem accepted an unknown scope, want a local error")
	}
	// The two real values, and absent, must all build.
	for _, scope := range []string{"", ScopeAll, ScopeMine} {
		if _, err := StatusItem("s1", pub, connSecretFor(pub), CashStatusParams{Scope: scope}, BySigning(priv), b); err != nil {
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

	item, err := StatusItem("s1", pub, connSecretFor(pub), CashStatusParams{Scope: ScopeAll}, BySigning(priv), b)
	if err != nil {
		t.Fatalf("StatusItem: %v", err)
	}
	if got := string(item.Params); !strings.Contains(got, `"scope":"all"`) {
		t.Errorf("params = %s, want the scope to travel", got)
	}

	bare, err := StatusItem("s1", pub, connSecretFor(pub), CashStatusParams{}, BySigning(priv), b)
	if err != nil {
		t.Fatalf("StatusItem: %v", err)
	}
	if got := string(bare.Params); strings.Contains(got, "scope") {
		t.Errorf("params = %s, want no scope field at all so the hub applies its own default", got)
	}
}

// T10-19: a cash-mode cash_status item carries no proof and no cash_secret
// (NIP-CASH §Scoping the Roster): its bill proof alone names the row, and the
// codec accepts it.
func TestStatusItem_CashModeCarriesNoSecret(t *testing.T) {
	_, pub := itemTestKeypair(t)
	b := ItemBinding{HubXOnly: pub, Nonce: strings.Repeat("11", 32), NotAfter: time.Now().Add(time.Minute).Unix()}
	ct := mustCashTarget(t)
	item, err := StatusItem("s1", pub, connSecretFor(pub), CashStatusParams{}, BySecret(ct.Secret()), b)
	if err != nil {
		t.Fatalf("StatusItem(cash-mode): %v", err)
	}
	if len(item.Proof) != 0 || item.IsBearer() || string(item.Params) != "{}" || !item.HasBillProof() {
		t.Fatalf("cash-mode status item: proof %d params %s", len(item.Proof), item.Params)
	}
	env := transport.Envelope{Nonce: b.Nonce, ReplyTo: strings.Repeat("22", 32), NotAfter: b.NotAfter, Items: []transport.Item{item}}
	if _, err := env.Encode(transport.DefaultLimits()); err != nil {
		t.Fatalf("the codec refuses it: %v", err)
	}
	priv, _ := itemTestKeypair(t)
	signed, _ := StatusItem("s2", pub, connSecretFor(pub), CashStatusParams{Scope: ScopeAll}, BySigning(priv), b)
	if string(signed.Params) != `{"scope":"all"}` || len(signed.Proof) == 0 {
		t.Errorf("pubkey status item: %s", signed.Params)
	}
}

// connSecretFor gives each bill in a test its own deterministic connection secret.
//
// Deterministic so a test can build a second item for the same bill and get a
// matching proof, and DISTINCT per bill so nothing passes by accidentally reusing
// one bill's secret for another — which is precisely the substitution a bill proof
// exists to catch.
func connSecretFor(target string) string {
	sum := sha256.Sum256([]byte("conn-secret:" + target))
	return hex.EncodeToString(sum[:])
}

// NIP-CASH §Item Proofs: an item proof is signed by the key that signed the item's claim proof, so a Hub's
// ItemSignerMatchesClaim holds. For a consolidate that is Sources[0]'s key, never another source's.
func TestItemConstructors_ItemProofSignerIsTheClaimSigner(t *testing.T) {
	_, hubXOnly := itemTestKeypair(t)
	b := testBinding(t, hubXOnly)
	priv, wallet := itemTestKeypair(t)
	secondPriv, secondWallet := itemTestKeypair(t)
	_, toPub := itemTestKeypair(t)
	iaPriv, _ := itemTestKeypair(t)
	ckPriv, ckPub := itemTestKeypair(t)
	ckCred, err := BySigningConnectionKey(ckPriv, buildTestAttestation(t, iaPriv, ckPub, testDiscordKey(t), 1))
	if err != nil {
		t.Fatal(err)
	}
	signerOf := func(t *testing.T, raw string) string {
		t.Helper()
		var ev nip01.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil || ev.PubKey == "" {
			t.Fatalf("not a signed event: %v %q", err, raw)
		}
		return ev.PubKey
	}
	claimSigners := func(t *testing.T, item transport.Item) []string {
		t.Helper()
		var p struct {
			IdentityEvent string `json:"identity_event"`
			Sources       []struct {
				IdentityEvent string `json:"identity_event"`
			} `json:"sources"`
		}
		if err := json.Unmarshal(item.Params, &p); err != nil {
			t.Fatal(err)
		}
		if p.IdentityEvent != "" {
			return []string{signerOf(t, p.IdentityEvent)}
		}
		var out []string
		for _, s := range p.Sources {
			out = append(out, signerOf(t, s.IdentityEvent))
		}
		return out
	}
	for _, c := range []struct {
		name string
		make func() (transport.Item, error)
	}{
		{"cash_redeem, pubkey", func() (transport.Item, error) {
			return CashRedeemParams{Invoice: testInvoice, Credential: BySigning(priv)}.Item("r", wallet, connSecretFor(wallet), b)
		}},
		{"cash_redeem, connection_key", func() (transport.Item, error) {
			return CashRedeemParams{Invoice: testInvoice, Credential: ckCred}.Item("k", wallet, connSecretFor(wallet), b)
		}},
		{"cash_transfer", func() (transport.Item, error) {
			return CashTransferParams{RequestID: testRID, Credential: BySigning(priv), To: Pubkey(toPub), CurrentAmount: 1000}.
				Item("t", wallet, connSecretFor(wallet), b)
		}},
		{"cash_consolidate", func() (transport.Item, error) {
			return CashConsolidateParams{RequestID: testRID, To: Pubkey(toPub), Sources: []Source{
				{WalletPubkey: wallet, Amount: 1000, Credential: BySigning(priv)},
				{WalletPubkey: secondWallet, Amount: 2000, Credential: BySigning(secondPriv)},
			}}.Item("c", wallet, connSecretFor(wallet), b)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			item, err := c.make()
			if err != nil {
				t.Fatal(err)
			}
			itemSigner := signerOf(t, string(item.Proof))
			signers := claimSigners(t, item)
			if len(signers) == 0 || !ItemSignerMatchesClaim(itemSigner, ClaimVerdict{Signer: signers[0]}) {
				t.Fatalf("item proof signed by %s, claim proof by %v", itemSigner, signers)
			}
			for _, other := range signers[1:] {
				if ItemSignerMatchesClaim(itemSigner, ClaimVerdict{Signer: other}) {
					t.Fatalf("item proof signed by a later source's key %s", other)
				}
			}
		})
	}
}
