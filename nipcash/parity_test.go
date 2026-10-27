package nipcash

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip57/nip57test"
)

// amount MUST NOT alter an invoice that carries one; it may set an amountless
// invoice's amount (NIP-CASH §Redeeming a Slice).
func TestCashRedeem_AmountOnlyWithAnAmountlessInvoice(t *testing.T) {
	priv, _ := generateTestKeypair(t)
	wallet := randomKeyHex(t)
	amount := uint64(500000)
	if _, err := (CashRedeemParams{Invoice: testInvoice, Credential: BySigning(priv), Amount: &amount}).Request(wallet); !errors.Is(err, ErrRedeemAmountOnAmountInvoice) {
		t.Fatalf("amount invoice + amount: %v", err)
	}
	ph := sha256.Sum256([]byte("p"))
	amountless, err := nip57test.SignedBolt11(nip57test.Invoice{Currency: "fc", PaymentHash: ph[:], Timestamp: 1720000000, NodePriv: nip57test.NewKey(1).Priv})
	if err != nil {
		t.Fatal(err)
	}
	req, err := (CashRedeemParams{Invoice: amountless, Credential: BySigning(priv), Amount: &amount}).Request(wallet)
	if err != nil || req.Amount == nil || *req.Amount != amount {
		t.Fatalf("amountless + amount: %+v %v", req, err)
	}
}

// A pubkey target or ia_pubkey is 64 lowercase hex: uppercase is refused,
// never lowercased (XQ-43).
func TestPubkeyTarget_LowercaseHexOnly(t *testing.T) {
	priv, _ := generateTestKeypair(t)
	up := strings.ToUpper(strings.Repeat("ab", 32))
	_, err := CashTransferParams{RequestID: testRID, Credential: BySigning(priv), To: Pubkey(up), CurrentAmount: 1000}.Request(randomKeyHex(t))
	if !errors.Is(err, ErrPubkeyNotLowerHex) {
		t.Errorf("uppercase transfer target: %v", err)
	}
	if _, err := (MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(Pubkey(up), 1000)}}).Request(); !errors.Is(err, ErrPubkeyNotLowerHex) {
		t.Errorf("uppercase mint recipient: %v", err)
	}
	if _, err := (CashTransferParams{RequestID: testRID, Credential: BySigning(priv), To: Pubkey(strings.ToLower(up)), CurrentAmount: 1000}).Request(randomKeyHex(t)); err != nil {
		t.Errorf("lowercase: %v", err)
	}
}
