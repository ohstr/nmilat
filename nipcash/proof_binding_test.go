package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipIC"
)

// proofTag parses a kind-23198 identity_event and returns its tag's value, "" if absent.
func proofTag(t *testing.T, identityEvent, name string) string {
	t.Helper()
	var ev nip01.Event
	if err := json.Unmarshal([]byte(identityEvent), &ev); err != nil {
		t.Fatalf("identity_event: %v", err)
	}
	if values := ev.GetTag(name); len(values) > 0 {
		return values[0]
	}
	return ""
}

// sha256Hex is the new_identity_hash formula, written out independently here.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// NIP-CASH §Redeeming a Slice: the proof binds the slice (d) and this invoice
// (bolt11_hash), so a captured proof cannot redeem to another invoice.
func TestCashRedeemParams_Request_ProofBindsWalletAndInvoice(t *testing.T) {
	priv, _ := generateTestKeypair(t)
	wallet := randomKeyHex(t)
	req, err := CashRedeemParams{Invoice: testInvoice, Credential: BySigning(priv)}.Request(wallet)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := nip57.DecodeBolt11(testInvoice)
	if err != nil {
		t.Fatal(err)
	}
	if got := proofTag(t, req.IdentityEvent, "d"); got != wallet {
		t.Errorf("d = %q, want the wallet %s", got, wallet)
	}
	if got := proofTag(t, req.IdentityEvent, "bolt11_hash"); got != inv.PaymentHash || got == "" {
		t.Errorf("bolt11_hash = %q, want the invoice's payment hash %s", got, inv.PaymentHash)
	}
}

// NIP-CASH §Redeeming a Slice: a connection_key slice's redeem carries the IA
// attestation, alongside a proof bound to the connection key.
func TestCashRedeemParams_Request_ConnectionKeyCarriesAttestation(t *testing.T) {
	iaPriv, _ := generateTestKeypair(t)
	userPriv, userPub := generateTestKeypair(t)
	key := testDiscordKey(t)
	att := buildTestAttestation(t, iaPriv, userPub, key, 1)
	req, err := CashRedeemParams{Invoice: testInvoice,
		Credential: mustConnCred(t, userPriv, att)}.Request(randomKeyHex(t))
	if err != nil {
		t.Fatal(err)
	}
	if req.AttestationEvent == "" {
		t.Fatal("attestation_event dropped from a connection_key redeem")
	}
	var ev nip01.Event
	if err := json.Unmarshal([]byte(req.AttestationEvent), &ev); err != nil || ev.ID != att.ID {
		t.Fatalf("attestation_event = %q, want the attestation %s", req.AttestationEvent, att.ID)
	}
	if req.IdentityType != "connection_key" || req.IdentityValue != key.String() {
		t.Errorf("identity = %s/%s, want connection_key/%s", req.IdentityType, req.IdentityValue, key)
	}
}

// NIP-CASH §Transferring and Splitting a Slice: on a split the proof binds the
// new_identity (sha256 of type:value:ia_pubkey, ia_pubkey included) and the
// amount being split off, not the slice's current amount.
func TestCashTransferParams_Request_SplitBindsNewIdentityAndAmount(t *testing.T) {
	priv, _ := generateTestKeypair(t)
	wallet := randomKeyHex(t)
	ia := randomKeyHex(t)
	to := attestedKey(t, "discord", "2003", ia)
	split := uint64(4000)
	req, err := CashTransferParams{RequestID: testRID, To: to, Credential: BySigning(priv), CurrentAmount: 15000, SplitAmount: &split}.Request(wallet)
	if err != nil {
		t.Fatal(err)
	}
	bob, _ := nipIC.ConnectionKeyFromAttested("discord", "2003")
	key := bob.String()
	if got, want := proofTag(t, req.IdentityEvent, "new_identity_hash"), sha256Hex("connection_key:"+key+":"+ia); got != want {
		t.Errorf("new_identity_hash = %q, want sha256(type:value:ia) = %s", got, want)
	}
	if got := proofTag(t, req.IdentityEvent, "amount_millis"); got != "4000" {
		t.Errorf("amount_millis = %q, want the split amount 4000", got)
	}
	if got := proofTag(t, req.IdentityEvent, "d"); got != wallet {
		t.Errorf("d = %q, want %s", got, wallet)
	}
	if req.NewIdentity.IAPubkey != ia {
		t.Errorf("new_identity.ia_pubkey = %q, want %s", req.NewIdentity.IAPubkey, ia)
	}

	// A different Identity Authority must change the hash, or a proof for one IA
	// could be replayed under another.
	other := CashTransferParams{RequestID: testRID, To: attestedKey(t, "discord", "2003", randomKeyHex(t)), Credential: BySigning(priv), CurrentAmount: 15000, SplitAmount: &split}
	otherReq, err := other.Request(wallet)
	if err != nil {
		t.Fatal(err)
	}
	if proofTag(t, otherReq.IdentityEvent, "new_identity_hash") == proofTag(t, req.IdentityEvent, "new_identity_hash") {
		t.Error("new_identity_hash ignores ia_pubkey")
	}
}

// NIP-CASH §Transferring and Splitting a Slice: a cash-mode slice sends its
// cash_secret in place of a proof (the cashctl protect path).
func TestCashTransferParams_Request_CashSlicePresentsSecret(t *testing.T) {
	req, err := CashTransferParams{RequestID: testRID, To: Pubkey(randomKeyHex(t)), Credential: BySecret("the-secret"), CurrentAmount: 1000}.Request(randomKeyHex(t))
	if err != nil {
		t.Fatal(err)
	}
	if req.CashSecret != "the-secret" || req.IdentityEvent != "" {
		t.Fatalf("cash_secret = %q, identity_event = %q; want the secret and no proof", req.CashSecret, req.IdentityEvent)
	}
}
