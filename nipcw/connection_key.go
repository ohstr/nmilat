package nipcw

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/utils"
)

// ErrNoConnectionKey is returned by Prepare when no ConnectionKey was set.
// NIP-CW has no Hub-generated alternative: the member generates the key.
var ErrNoConnectionKey = errors.New("nipcw: create_circle_wallet requires a member-generated connection key")

// ConnectionKey is the keypair a member generates for a Circle Wallet's
// connection (NIP-CW §Pairing Connection). Only its public half is ever sent;
// the Hub authorizes that pubkey and never sees the secret, so the member
// builds the connection string itself from the Hub's reply and this secret.
//
// Build one with NewConnectionKey, or ConnectionKeyFromSecret to reuse a secret
// the caller saved before sending, so a lost reply does not lose it.
type ConnectionKey struct {
	secret string
	pubkey string
}

// NewConnectionKey generates a fresh connection keypair. NIP-CW asks for a fresh
// one per request, so the key links to nothing else the member uses.
func NewConnectionKey() (ConnectionKey, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ConnectionKey{}, fmt.Errorf("nipcw: generate connection key: %w", err)
	}
	return ConnectionKeyFromSecret(hex.EncodeToString(raw[:]))
}

// ConnectionKeyFromSecret rebuilds a connection key from its secret, 64
// lowercase hex, as journalled before a join was sent.
func ConnectionKeyFromSecret(secretHex string) (ConnectionKey, error) {
	if !isLowerHex64(secretHex) {
		return ConnectionKey{}, fmt.Errorf("nipcw: connection secret must be 64 lowercase hex")
	}
	pubkey, err := utils.GetPublicKey(secretHex)
	if err != nil {
		return ConnectionKey{}, fmt.Errorf("nipcw: connection secret: %w", err)
	}
	return ConnectionKey{secret: secretHex, pubkey: pubkey}, nil
}

// Secret is the connection secret, for the member's connection string only.
func (k ConnectionKey) Secret() string { return k.secret }

// Pubkey is the x-only connection pubkey sent as connection_pubkey.
func (k ConnectionKey) Pubkey() string { return k.pubkey }

// IsZero reports whether k was never set.
func (k ConnectionKey) IsZero() bool { return k.secret == "" }
