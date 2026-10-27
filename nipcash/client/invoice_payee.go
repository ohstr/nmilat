package client

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

const (
	bolt11TimestampWords = 7
	bolt11SignatureWords = 104
)

var errInvoicePayee = errors.New("nipcash/client: cannot read the invoice's payee")

// invoicePayee recovers a BOLT11 invoice's payee node (x-only hex) from its
// signature: the recoverable signature over sha256(hrp || data). A recovered
// key is the payee BOLT11 defines; it is checked against an "n" field by the
// Hub, which pays it.
func invoicePayee(invoice string) (string, error) {
	hrp, words, err := bech32.DecodeNoLimit(invoice)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errInvoicePayee, err)
	}
	if len(words) < bolt11TimestampWords+bolt11SignatureWords {
		return "", fmt.Errorf("%w: data part too short", errInvoicePayee)
	}
	data, sigWords := words[:len(words)-bolt11SignatureWords], words[len(words)-bolt11SignatureWords:]
	sig, err := bech32.ConvertBits(sigWords, 5, 8, false)
	if err != nil || len(sig) != 65 || sig[64] > 3 {
		return "", fmt.Errorf("%w: bad signature field", errInvoicePayee)
	}
	msg, err := bech32.ConvertBits(data, 5, 8, true)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errInvoicePayee, err)
	}
	h := sha256.Sum256(append([]byte(hrp), msg...))
	compact := make([]byte, 65)
	compact[0] = 27 + 4 + sig[64]
	copy(compact[1:], sig[:64])
	pub, _, err := ecdsa.RecoverCompact(compact, h[:])
	if err != nil {
		return "", fmt.Errorf("%w: %v", errInvoicePayee, err)
	}
	return hex.EncodeToString(pub.SerializeCompressed()[1:]), nil
}
