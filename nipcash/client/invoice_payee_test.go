package client

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
)

// signedInvoice builds a BOLT11 invoice under hrp (e.g. "lnfc50n", or "lnfc"
// for an amountless one) with a payment hash, signed by privHex.
func signedInvoice(t *testing.T, hrp, privHex string) string {
	t.Helper()
	words := make([]byte, bolt11TimestampWords) // timestamp 0
	words[bolt11TimestampWords-1] = 1
	hash, err := bech32.ConvertBits([]byte(strings.Repeat("\x12", 32)), 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	words = append(words, 1, byte(len(hash)/32), byte(len(hash)%32))
	words = append(words, hash...)
	msg, err := bech32.ConvertBits(words, 5, 8, true)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte(hrp), msg...))
	kb, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatal(err)
	}
	compact := ecdsa.SignCompact(secp256k1.PrivKeyFromBytes(kb), h[:], true)
	sig := append(append([]byte{}, compact[1:]...), compact[0]-27-4)
	sigWords, err := bech32.ConvertBits(sig, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := bech32.Encode(hrp, append(words, sigWords...))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestInvoicePayee(t *testing.T) {
	priv, xonly := sessionKeypair(t)
	got, err := invoicePayee(signedInvoice(t, "lnfc50n", priv))
	if err != nil || got != xonly {
		t.Fatalf("invoicePayee = (%q, %v), want %q", got, err, xonly)
	}
	if _, err := invoicePayee(redeemInvoice); err != nil {
		t.Fatalf("real invoice: %v", err)
	}
	if got, err := invoicePayee(cashtest.FakeBolt11(make([]byte, 32), 1000)); err != nil || got != cashtest.FakePayeeXOnly() {
		t.Fatalf("the fake payee's invoice: (%q, %v)", got, err)
	}
	if _, err := invoicePayee("lnfc1qqqq"); err == nil {
		t.Fatal("a truncated invoice gave a payee")
	}
}

// With AutoAmount and no Payee, the payee is read from the invoice: the Hub's
// own node is paid the full amount, not refused as another node's.
func TestCashRedeemWith_AutoAmountReadsThePayee(t *testing.T) {
	ctx, cancel := e2eContext(t)
	defer cancel()
	t.Run("the Hub's node, full amount", func(t *testing.T) {
		c, hub, priv := redeemClient(t)
		inv := signedInvoice(t, "lnfc50n", hub.hubPriv)
		if _, err := c.CashRedeemWith(ctx, nipcash.CashRedeemParams{Invoice: inv, Credential: nipcash.BySigning(priv)},
			RedeemOptions{AutoAmount: true}); err != nil {
			t.Fatal(err)
		}
		if got := hub.sent(); len(got) != 1 || got[0].Amount != nil {
			t.Fatalf("sent %+v, want one redeem without an amount param", got)
		}
	})
	t.Run("the Hub's node, amountless", func(t *testing.T) {
		c, hub, priv := redeemClient(t)
		inv := signedInvoice(t, "lnfc", hub.hubPriv)
		if _, err := c.CashRedeemWith(ctx, nipcash.CashRedeemParams{Invoice: inv, Credential: nipcash.BySigning(priv)},
			RedeemOptions{AutoAmount: true}); err != nil {
			t.Fatal(err)
		}
		if got := hub.sent(); len(got) != 1 || got[0].Amount == nil || *got[0].Amount != 5000 {
			t.Fatalf("sent %+v, want amount 5000", got)
		}
	})
}
