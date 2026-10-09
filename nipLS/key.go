package nipLS

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip04"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/utils"
)

var (
	_ Key = (*LocalKey)(nil)
	_ Key = (*Client)(nil)
)

// LocalKey is a Key held in this process's memory.
type LocalKey struct {
	priv, pub string
}

// NewLocalKey wraps a private key given as hex or nsec.
func NewLocalKey(privKey string) (*LocalKey, error) {
	priv := strings.TrimSpace(privKey)
	if strings.HasPrefix(priv, "nsec1") {
		h, err := nip19.DecodePrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("nipLS: invalid nsec: %w", err)
		}
		priv = h
	}
	priv = strings.ToLower(priv)
	if err := utils.Validate32Key(priv); err != nil {
		return nil, fmt.Errorf("nipLS: invalid private key: %w", err)
	}
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		return nil, fmt.Errorf("nipLS: invalid private key: %w", err)
	}
	return &LocalKey{priv: priv, pub: pub}, nil
}

// PubKey is the key's pubkey, lowercase hex.
func (k *LocalKey) PubKey() string { return k.pub }

// Sign sets ev's PubKey, ID and Sig.
func (k *LocalKey) Sign(_ context.Context, ev *nip01.Event) error {
	if ev.Tags == nil {
		ev.Tags = [][]string{}
	}
	return ev.Sign(k.priv)
}

// Encrypt encrypts plaintext to peerPubKey with scheme.
func (k *LocalKey) Encrypt(_ context.Context, scheme, peerPubKey, plaintext string) (string, error) {
	switch scheme {
	case nip46.EncryptionNIP04:
		return nip04.Encrypt(plaintext, k.priv, peerPubKey)
	case nip46.EncryptionNIP44V2:
		ck, err := k.conversationKey(peerPubKey)
		if err != nil {
			return "", err
		}
		return nip44.Encrypt(plaintext, ck)
	}
	return "", fmt.Errorf("%w: %q", nip46.ErrUnsupportedEncryption, scheme)
}

// Decrypt decrypts ciphertext from peerPubKey with scheme.
func (k *LocalKey) Decrypt(_ context.Context, scheme, peerPubKey, ciphertext string) (string, error) {
	switch scheme {
	case nip46.EncryptionNIP04:
		return nip04.Decrypt(ciphertext, peerPubKey, k.priv)
	case nip46.EncryptionNIP44V2:
		ck, err := k.conversationKey(peerPubKey)
		if err != nil {
			return "", err
		}
		return nip44.Decrypt(ciphertext, ck)
	}
	return "", fmt.Errorf("%w: %q", nip46.ErrUnsupportedEncryption, scheme)
}

func (k *LocalKey) conversationKey(peerPubKey string) ([]byte, error) {
	privBytes, err := hex.DecodeString(k.priv)
	if err != nil {
		return nil, err
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer pubkey: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid peer pubkey: %w", err)
	}
	return nip44.GenerateConversationKey(priv, pub)
}

// secrets are the encodings of the key the server's guard refuses to emit.
func (k *LocalKey) secrets() []string {
	out := []string{k.priv}
	if nsec, err := nip19.EncodePrivateKey(k.priv); err == nil {
		out = append(out, nsec)
	}
	return out
}
