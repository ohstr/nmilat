// Package nip59 implements NIP-59 gift wrapping: a payload sealed to a
// recipient (kind 13, signed by the real sender) and then wrapped again
// (kind 1059, signed by a throwaway key) so the relay learns nothing about
// who sent it.
//
// Wrap seals any event with a throwaway wrap key. WrapWithKey wraps a rumor (an
// unsigned event) under a wrap key the caller generated first, for a caller
// that records that key to delete the wrap later (NIP-CP). Unwrap opens a wrap
// addressed to the caller and returns the rumor with the seal's signer.
package nip59

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/utils"
)

const (
	KindGiftWrap = 1059
	KindSeal     = 13
)

// maxCreatedAtBackdate is NIP-59's randomisation window: a wrapped event's
// created_at is moved up to two days into the past so an observer cannot use it
// to correlate sender and recipient by timing.
const maxCreatedAtBackdate = 2 * 24 * time.Hour

// RandomizedCreatedAt returns a unix timestamp uniformly distributed over
// [now-maxCreatedAtBackdate, now], as NIP-59 requires for both the seal and the
// gift wrap.
//
// Two consequences worth knowing before you filter on it:
//
//   - a `since` filter WILL drop legitimate wrapped events, silently and
//     partially, because a valid wrap's stated time can be two days old;
//   - the stated time is no longer evidence of freshness, so replay protection
//     has to live inside the encrypted payload (its own expiry plus a nonce the
//     receiver dedupes), never in created_at.
func RandomizedCreatedAt() uint64 {
	now := time.Now()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// A failure here would mean the process has no entropy at all. Falling
		// back to the true timestamp is the safe direction: it leaks timing,
		// which is a privacy loss, rather than producing a predictable offset,
		// which would look random while being trivially reversible.
		return uint64(now.Unix())
	}
	offset := time.Duration(binary.BigEndian.Uint64(buf[:]) % uint64(maxCreatedAtBackdate))
	return uint64(now.Add(-offset).Unix())
}

// WrapOption tunes WrapWithKey.
type WrapOption func(*wrapConfig)

type wrapConfig struct {
	expiration int64
}

// WithWrapExpiration sets a NIP-40 expiration tag on the gift wrap (never on the
// seal or the rumor). A value of 0 or less sets none.
func WithWrapExpiration(unix int64) WrapOption {
	return func(c *wrapConfig) { c.expiration = unix }
}

// Errors of WrapWithKey and Unwrap.
var (
	// ErrSignedRumor is a rumor given to WrapWithKey with a signature: a rumor
	// travels unsigned, so a leaked copy proves nothing.
	ErrSignedRumor = errors.New("nip59: a rumor is never signed")
	// ErrRumorAuthor is a rumor whose pubkey is not the seal signer's.
	ErrRumorAuthor = errors.New("nip59: the rumor's pubkey is not the sender's")
	// ErrNotWrap is an event that is not a well-formed gift wrap for the key.
	ErrNotWrap = errors.New("nip59: not a gift wrap this key can open")
)

// Wrap seals payload to the recipient and wraps the seal for publication.
//
// The seal (kind 13) is signed by senderPrivKeyHex, so the recipient — and only
// the recipient — learns who really sent it. The gift wrap (kind 1059) is signed
// by a fresh key generated here and discarded, and carries the recipient in a
// "p" tag because the relay needs it to route. Note what that means: gift wrap
// hides the SENDER, not the receiver.
//
// recipientPubKeyHex is a 32-byte x-only Nostr pubkey.
func Wrap(payload *nip01.Event, senderPrivKeyHex, recipientPubKeyHex string) (*nip01.Event, error) {
	ephemeralPriv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("nip59: ephemeral key: %w", err)
	}
	return wrap(payload, senderPrivKeyHex, recipientPubKeyHex, hex.EncodeToString(ephemeralPriv.Serialize()), wrapConfig{})
}

// WrapWithKey wraps a rumor under wrapPrivHex, a key the caller generated for
// this one wrap and keeps (to sign the wrap's later deletion). The rumor MUST
// be unsigned (ErrSignedRumor); its pubkey is set to the sender's when empty and
// must be the sender's otherwise (ErrRumorAuthor), and its id is computed.
func WrapWithKey(rumor *nip01.Event, senderPriv, recipientPub, wrapPrivHex string, opts ...WrapOption) (*nip01.Event, error) {
	if rumor == nil {
		return nil, errors.New("nip59: no rumor")
	}
	if rumor.Sig != "" {
		return nil, ErrSignedRumor
	}
	senderPub, err := utils.GetPublicKey(senderPriv)
	if err != nil {
		return nil, fmt.Errorf("nip59: invalid sender private key: %w", err)
	}
	r := *rumor
	switch r.PubKey {
	case "":
		r.PubKey = senderPub
	case senderPub:
	default:
		return nil, ErrRumorAuthor
	}
	id, err := r.HashID()
	if err != nil {
		return nil, fmt.Errorf("nip59: rumor id: %w", err)
	}
	r.ID = hex.EncodeToString(id)
	if _, err := utils.ParsePrivateKeyHex(wrapPrivHex); err != nil {
		return nil, fmt.Errorf("nip59: invalid wrap key: %w", err)
	}
	var cfg wrapConfig
	for _, o := range opts {
		o(&cfg)
	}
	return wrap(&r, senderPriv, recipientPub, wrapPrivHex, cfg)
}

func wrap(payload *nip01.Event, senderPrivKeyHex, recipientPubKeyHex, ephemeralPrivHex string, cfg wrapConfig) (*nip01.Event, error) {
	senderPriv, err := utils.ParsePrivateKeyHex(senderPrivKeyHex)
	if err != nil {
		return nil, fmt.Errorf("nip59: invalid sender private key: %w", err)
	}

	recipientPubBytes, err := hex.DecodeString(recipientPubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("nip59: invalid recipient public key: %w", err)
	}
	recipientPub, err := schnorr.ParsePubKey(recipientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("nip59: invalid recipient public key: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("nip59: marshal payload: %w", err)
	}

	// Seal: the payload, NIP-44 encrypted sender -> recipient, signed by the
	// real sender. Never set PubKey by hand here — Sign derives it from the
	// private key. An earlier version assigned the private key hex to PubKey,
	// which Sign happened to overwrite; it was one reordering away from
	// publishing a private key in a public field.
	conversationKey, err := nip44.GenerateConversationKey(senderPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("nip59: seal conversation key: %w", err)
	}
	sealContent, err := nip44.Encrypt(string(payloadJSON), conversationKey)
	if err != nil {
		return nil, fmt.Errorf("nip59: encrypt seal: %w", err)
	}

	seal := nip01.NewEvent(KindSeal, sealContent)
	seal.Tags = [][]string{}
	seal.CreatedAt = RandomizedCreatedAt()
	if err := seal.Sign(senderPrivKeyHex); err != nil {
		return nil, fmt.Errorf("nip59: sign seal: %w", err)
	}

	// Gift wrap: the seal, NIP-44 encrypted ephemeral -> recipient, signed by a
	// key that exists only for this one event.
	ephemeralPriv, err := utils.ParsePrivateKeyHex(ephemeralPrivHex)
	if err != nil {
		return nil, fmt.Errorf("nip59: ephemeral key: %w", err)
	}

	sealJSON, err := json.Marshal(seal)
	if err != nil {
		return nil, fmt.Errorf("nip59: marshal seal: %w", err)
	}

	wrapKey, err := nip44.GenerateConversationKey(ephemeralPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("nip59: wrap conversation key: %w", err)
	}
	wrapContent, err := nip44.Encrypt(string(sealJSON), wrapKey)
	if err != nil {
		return nil, fmt.Errorf("nip59: encrypt wrap: %w", err)
	}

	wrap := nip01.NewEvent(KindGiftWrap, wrapContent)
	wrap.Tags = [][]string{{"p", recipientPubKeyHex}}
	if cfg.expiration > 0 {
		wrap.Tags = append(wrap.Tags, []string{"expiration", strconv.FormatInt(cfg.expiration, 10)})
	}
	wrap.CreatedAt = RandomizedCreatedAt()
	if err := wrap.Sign(ephemeralPrivHex); err != nil {
		return nil, fmt.Errorf("nip59: sign wrap: %w", err)
	}

	return wrap, nil
}

// Unwrap opens a gift wrap addressed to recipientPriv: it verifies the wrap's
// signature, decrypts the seal, verifies the seal's signature, decrypts the
// rumor, and returns it with the seal's signer. The rumor's id is checked
// against its content when present and set when absent. Whether that signer,
// the rumor's pubkey and kind are acceptable is the caller's to decide; a
// rumor whose pubkey differs from the seal signer is ErrRumorAuthor, and a
// signed rumor is returned as it is (Sig set) for the caller to discard.
func Unwrap(w *nip01.Event, recipientPriv string) (rumor *nip01.Event, sealSigner string, err error) {
	if w == nil || w.Kind != KindGiftWrap {
		return nil, "", ErrNotWrap
	}
	if err := w.Verify(nip01.WithoutPowCheck()); err != nil {
		return nil, "", fmt.Errorf("%w: wrap: %v", ErrNotWrap, err)
	}
	priv, err := utils.ParsePrivateKeyHex(recipientPriv)
	if err != nil {
		return nil, "", fmt.Errorf("nip59: invalid recipient private key: %w", err)
	}
	sealJSON, err := open(priv, w.PubKey, w.Content)
	if err != nil {
		return nil, "", fmt.Errorf("%w: wrap: %v", ErrNotWrap, err)
	}
	var seal nip01.Event
	if err := json.Unmarshal([]byte(sealJSON), &seal); err != nil {
		return nil, "", fmt.Errorf("%w: seal: %v", ErrNotWrap, err)
	}
	if seal.Kind != KindSeal {
		return nil, "", fmt.Errorf("%w: inner event is kind %d, not a seal", ErrNotWrap, seal.Kind)
	}
	if err := seal.Verify(nip01.WithoutPowCheck()); err != nil {
		return nil, "", fmt.Errorf("%w: seal: %v", ErrNotWrap, err)
	}
	rumorJSON, err := open(priv, seal.PubKey, seal.Content)
	if err != nil {
		return nil, "", fmt.Errorf("%w: seal: %v", ErrNotWrap, err)
	}
	var r nip01.Event
	if err := json.Unmarshal([]byte(rumorJSON), &r); err != nil {
		return nil, "", fmt.Errorf("%w: rumor: %v", ErrNotWrap, err)
	}
	if r.PubKey != seal.PubKey {
		return nil, seal.PubKey, ErrRumorAuthor
	}
	id, err := r.HashID()
	if err != nil {
		return nil, "", fmt.Errorf("%w: rumor: %v", ErrNotWrap, err)
	}
	want := hex.EncodeToString(id)
	if r.ID == "" {
		r.ID = want
	} else if r.ID != want {
		return nil, "", fmt.Errorf("%w: rumor id does not match its content", ErrNotWrap)
	}
	return &r, seal.PubKey, nil
}

func open(priv *btcec.PrivateKey, senderPubHex, payload string) (string, error) {
	b, err := hex.DecodeString(senderPubHex)
	if err != nil {
		return "", err
	}
	pub, err := schnorr.ParsePubKey(b)
	if err != nil {
		return "", err
	}
	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		return "", err
	}
	return nip44.Decrypt(payload, key)
}
