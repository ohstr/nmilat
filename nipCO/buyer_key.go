package nipCO

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/utils"
)

// buyerKeyLabel prefixes the cash secret in the buyer-key derivation.
const buyerKeyLabel = "cash-order-key:v1"

// randReader is where buyer keys and notify values come from; tests swap it.
var randReader io.Reader = rand.Reader

// maxTargetDraws bounds NewCashOrderTarget's draws. An unusable digest has a
// probability near 2^-128, so a second draw already never happens.
const maxTargetDraws = 8

// BuyerKeyFromSecret derives a cash order's buyer key from its cash secret
// (NIP-CO §The Buyer Key): SHA256("cash-order-key:v1" ‖ the secret's 32 raw
// bytes). A digest that is zero or not below the secp256k1 group order is
// ErrBuyerKeyUnusable, and the client generates a new cash secret.
func BuyerKeyFromSecret(secretHex string) (skHex, pkXOnly string, err error) {
	if !nipcash.ValidCashSecret(secretHex) {
		return "", "", errors.New("nipCO: a cash secret is 64 lowercase hex characters")
	}
	raw, _ := hex.DecodeString(secretHex)
	digest := sha256.Sum256(append([]byte(buyerKeyLabel), raw...))
	return buyerKeyFromDigest(digest)
}

// buyerKeyFromDigest turns a 32-byte digest into a key, refusing 0 and ≥ n.
func buyerKeyFromDigest(d [32]byte) (skHex, pkXOnly string, err error) {
	var s secp256k1.ModNScalar
	if overflow := s.SetBytes(&d); overflow != 0 || s.IsZero() {
		return "", "", ErrBuyerKeyUnusable
	}
	skHex = hex.EncodeToString(d[:])
	pkXOnly, err = utils.GetPublicKey(skHex)
	if err != nil {
		return "", "", fmt.Errorf("nipCO: buyer key: %w", err)
	}
	return skHex, pkXOnly, nil
}

// NewCashOrderTarget is a fresh cash recipient whose buyer key is usable: it
// draws nipcash.NewCashTarget until BuyerKeyFromSecret accepts the secret (at
// most 8 draws).
func NewCashOrderTarget() (*nipcash.CashTarget, error) {
	for i := 0; i < maxTargetDraws; i++ {
		t, err := nipcash.NewCashTarget()
		if err != nil {
			return nil, err
		}
		if _, _, err := BuyerKeyFromSecret(t.Secret()); err == nil {
			return t, nil
		} else if !errors.Is(err, ErrBuyerKeyUnusable) {
			return nil, err
		}
	}
	return nil, ErrBuyerKeyUnusable
}

// NewBuyerKey is a fresh random buyer key, for a pubkey or connection_key
// recipient. It is made for the order alone: never the buyer's or the
// recipient's Nostr key.
func NewBuyerKey() (skHex, pkXOnly string, err error) {
	for i := 0; i < maxTargetDraws; i++ {
		var d [32]byte
		if _, err := io.ReadFull(randReader, d[:]); err != nil {
			return "", "", fmt.Errorf("nipCO: buyer key: %w", err)
		}
		skHex, pkXOnly, err = buyerKeyFromDigest(d)
		if err == nil {
			return skHex, pkXOnly, nil
		}
	}
	return "", "", ErrBuyerKeyUnusable
}

// NewNotify is a fresh notify value: 32 CSPRNG bytes as 64 lowercase hex, new
// for every order.
func NewNotify() (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(randReader, b[:]); err != nil {
		return "", fmt.Errorf("nipCO: notify: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
