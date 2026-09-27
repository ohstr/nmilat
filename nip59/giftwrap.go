// Package nip59 implements NIP-59 gift wrapping: a payload sealed to a
// recipient (kind 13, signed by the real sender) and then wrapped again
// (kind 1059, signed by a throwaway key) so the relay learns nothing about
// who sent it.
//
// Only the send path exists here. There is deliberately no Unwrap/Unseal: no
// caller in this module needs one yet, and a receive path written ahead of its
// first user is a receive path nobody has exercised against real ciphertext.
// Add it together with the code that consumes it.
package nip59

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
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
	senderPrivBytes, err := hex.DecodeString(senderPrivKeyHex)
	if err != nil {
		return nil, fmt.Errorf("nip59: invalid sender private key: %w", err)
	}
	senderPriv, _ := btcec.PrivKeyFromBytes(senderPrivBytes)

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
	seal.CreatedAt = RandomizedCreatedAt()
	if err := seal.Sign(senderPrivKeyHex); err != nil {
		return nil, fmt.Errorf("nip59: sign seal: %w", err)
	}

	// Gift wrap: the seal, NIP-44 encrypted ephemeral -> recipient, signed by a
	// key that exists only for this one event.
	ephemeralPriv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("nip59: ephemeral key: %w", err)
	}
	ephemeralPrivHex := hex.EncodeToString(ephemeralPriv.Serialize())

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
	wrap.CreatedAt = RandomizedCreatedAt()
	if err := wrap.Sign(ephemeralPrivHex); err != nil {
		return nil, fmt.Errorf("nip59: sign wrap: %w", err)
	}

	return wrap, nil
}
