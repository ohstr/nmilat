package nip57test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"

	"github.com/ohstr/nmilat/nip57"
)

func TestSignedBolt11_Decodes(t *testing.T) {
	ph := sha256.Sum256([]byte("preimage"))
	for _, millis := range []uint64{21022000, 1, 150, 100_000_000, 0} {
		s, err := SignedBolt11(Invoice{Currency: "bc", AmountMillis: millis, PaymentHash: ph[:], Description: "order",
			Timestamp: 1720000000, Expiry: 3600, NodePriv: NewKey(1).Priv})
		if err != nil {
			t.Fatal(err)
		}
		inv, err := nip57.DecodeBolt11(s)
		if err != nil {
			t.Fatalf("%d: %v", millis, err)
		}
		if uint64(inv.AmountMloki) != millis || inv.PaymentHash != hex.EncodeToString(ph[:]) || inv.Description != "order" || inv.Currency != "bc" {
			t.Errorf("%d: decoded %+v", millis, inv)
		}
	}
}

// The signature recovers the node key over sha256(hrp ‖ data), as BOLT11
// defines it.
func TestSignedBolt11_SignatureRecoversNode(t *testing.T) {
	ph := sha256.Sum256([]byte("p"))
	k := NewKey(1)
	s, err := SignedBolt11(Invoice{Currency: "bc", AmountMillis: 21022000, PaymentHash: ph[:], Timestamp: 1720000000, Expiry: 3600, NodePriv: k.Priv})
	if err != nil {
		t.Fatal(err)
	}
	hrp, words, err := bech32.DecodeNoLimit(s)
	if err != nil {
		t.Fatal(err)
	}
	data, sigWords := words[:len(words)-104], words[len(words)-104:]
	dataBytes, _ := bech32.ConvertBits(data, 5, 8, true)
	sig, _ := bech32.ConvertBits(sigWords, 5, 8, false)
	digest := sha256.Sum256(append([]byte(hrp), dataBytes...))
	compact := append([]byte{27 + 4 + sig[64]}, sig[:64]...)
	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pub.SerializeCompressed()[1:]); got != k.Pub {
		t.Fatalf("recovered %s, want %s", got, k.Pub)
	}
}
