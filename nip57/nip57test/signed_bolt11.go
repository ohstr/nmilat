package nip57test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// Invoice describes a BOLT11 invoice to build and sign.
type Invoice struct {
	// Currency is the BOLT11 prefix after "ln": "bc", "tb", "bcrt", "fc", ...
	Currency string
	// AmountMillis is the amount in milli-units; 0 builds an amountless invoice.
	AmountMillis uint64
	// PaymentHash is 32 bytes.
	PaymentHash []byte
	// Description is the d field ("" omits it).
	Description string
	// Timestamp is the creation time; Expiry the x field in seconds (0 omits
	// it, which BOLT11 reads as 3600).
	Timestamp, Expiry int64
	// NodePriv signs the invoice (hex); the payee node id is its key.
	NodePriv string
}

// SignedBolt11 encodes and signs inv as BOLT11 requires: the signature is a
// recoverable secp256k1 signature over sha256(hrp ‖ data), so a strict
// decoder recovers the payee from it. The amount uses the largest multiplier
// that writes it exactly.
func SignedBolt11(inv Invoice) (string, error) {
	if len(inv.PaymentHash) != 32 {
		return "", errors.New("nip57test: payment hash must be 32 bytes")
	}
	priv, err := hex.DecodeString(inv.NodePriv)
	if err != nil || len(priv) != 32 {
		return "", errors.New("nip57test: node key must be 32 bytes of hex")
	}
	hrp := "ln" + inv.Currency + bolt11Amount(inv.AmountMillis)

	words := make([]byte, 0, 256)
	for i := 6; i >= 0; i-- { // 35-bit timestamp
		words = append(words, byte(inv.Timestamp>>(5*uint(i)))&31)
	}
	field := func(typ byte, data []byte) {
		words = append(words, typ, byte(len(data)/32), byte(len(data)%32))
		words = append(words, data...)
	}
	bytesField := func(typ byte, payload []byte) error {
		data, err := bech32.ConvertBits(payload, 8, 5, true)
		if err != nil {
			return err
		}
		field(typ, data)
		return nil
	}
	if err := bytesField(1, inv.PaymentHash); err != nil {
		return "", err
	}
	if inv.Description != "" {
		if err := bytesField(13, []byte(inv.Description)); err != nil {
			return "", err
		}
	}
	if inv.Expiry > 0 {
		var x []byte
		for v := inv.Expiry; v > 0; v >>= 5 {
			x = append([]byte{byte(v & 31)}, x...)
		}
		field(6, x)
	}

	data, err := bech32.ConvertBits(words, 5, 8, true)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(hrp), data...))
	compact := ecdsa.SignCompact(secp256k1.PrivKeyFromBytes(priv), digest[:], true)
	recid := (compact[0] - 27) & 3
	sig := append(append([]byte{}, compact[1:]...), recid)
	sigWords, err := bech32.ConvertBits(sig, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(hrp, append(words, sigWords...))
}

// bolt11Amount writes millis with the largest exact multiplier, "" for 0.
func bolt11Amount(millis uint64) string {
	switch {
	case millis == 0:
		return ""
	case millis%100_000_000 == 0:
		return fmt.Sprintf("%dm", millis/100_000_000)
	case millis%100_000 == 0:
		return fmt.Sprintf("%du", millis/100_000)
	case millis%100 == 0:
		return fmt.Sprintf("%dn", millis/100)
	default:
		return fmt.Sprintf("%dp", millis*10)
	}
}
