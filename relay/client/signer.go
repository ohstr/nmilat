package client

import (
	"context"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Signer answers NIP-42 AUTH challenges. It has nip46.Signer's shape, so a
// key in memory (*nip46.LocalKey), a remote signer (bunker.Client) or a
// unix-socket one (nipLS.Client) all fit.
type Signer interface {
	// PubKey is the signing pubkey, lowercase hex.
	PubKey() string
	// Sign sets ev's PubKey, ID and Sig.
	Sign(ctx context.Context, ev *nip01.Event) error
}

// authSignTimeout bounds signing one AUTH event, which may wait on a remote
// signer.
const authSignTimeout = 30 * time.Second

// KeySigner wraps a hex private key as a Signer.
func KeySigner(privKeyHex string) Signer { return keySigner(privKeyHex) }

type keySigner string

func (k keySigner) PubKey() string {
	pub, _ := utils.GetPublicKey(string(k))
	return pub
}

func (k keySigner) Sign(_ context.Context, ev *nip01.Event) error { return ev.Sign(string(k)) }

// configSigner is cfg's Signer, or its SigningKeyHex wrapped as one.
func configSigner(cfg *ConnectionConfig) Signer {
	if cfg.Signer != nil {
		return cfg.Signer
	}
	if cfg.SigningKeyHex != "" {
		return KeySigner(cfg.SigningKeyHex)
	}
	return nil
}
