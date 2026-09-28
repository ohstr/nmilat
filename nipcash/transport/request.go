package transport

import (
	"encoding/hex"
	"fmt"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip59"
)

// WrapRequest builds the kind-23190 event a hub actually accepts, from an
// already-encoded envelope plaintext (Envelope.Encode).
//
// This exists because the shape is easy to get wrong in a way that produces
// SILENCE rather than an error. A hub subscribes to kind 23190 and ignores
// everything else, so a sender who reaches for a general-purpose NIP-59 gift wrap
// — the obvious guess, and what an earlier draft of NIP-CASH incorrectly
// described — has their event discarded at the kind filter, before any decryption
// is attempted. No error comes back, because there is nobody to send one to.
//
// The construction is deliberately ONE NIP-44 layer, not NIP-59's seal-and-wrap:
//
//	kind        23190
//	pubkey      a fresh ephemeral key, used for this one event and discarded
//	tags        [["p", inboxXOnly]]
//	created_at  randomised into the past, NIP-59's technique
//	content     NIP-44(plaintext) under conversationKey(ephemeral, inbox)
//
// NIP-59's inner seal exists to prove to the recipient who sent the message. Here
// the sender is deliberately anonymous — the ephemeral key identifies nobody by
// design — and authorization travels per item, in each item's own kind-23192
// proof. Those proofs already do the seal's job and do it better, binding to the
// target, method and params rather than merely to an author, so a seal would add a
// layer and an extra ECDH to prove something no hub relies on.
//
// The ephemeral key is generated here and never returned. Nothing needs it again:
// the response comes back under a key derived from this event's own conversation
// key plus the envelope's reply_to (DeriveReplyKey), which the caller already has
// from ConversationKeyFor. Returning it would only invite someone to reuse it,
// which would defeat the unlinkability the ephemeral key exists for.
func WrapRequest(plaintext []byte, inboxXOnly string) (*nip01.Event, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%w: refusing to wrap an empty payload", ErrEnvelopeMalformed)
	}
	if len(inboxXOnly) != keyHexLen || !isLowerHex(inboxXOnly) {
		return nil, fmt.Errorf("%w: inbox pubkey must be %d lowercase hex characters",
			ErrAnnouncementMalformed, keyHexLen)
	}
	inboxBytes, err := hex.DecodeString(inboxXOnly)
	if err != nil {
		return nil, fmt.Errorf("%w: inbox pubkey: %v", ErrAnnouncementMalformed, err)
	}
	inboxPub, err := schnorr.ParsePubKey(inboxBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: inbox pubkey is not a valid point: %v", ErrAnnouncementMalformed, err)
	}

	ephemeralPriv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("transport: ephemeral key: %w", err)
	}
	ephemeralPrivHex := hex.EncodeToString(ephemeralPriv.Serialize())

	conversationKey, err := nip44.GenerateConversationKey(ephemeralPriv, inboxPub)
	if err != nil {
		return nil, fmt.Errorf("transport: conversation key: %w", err)
	}
	content, err := nip44.Encrypt(string(plaintext), conversationKey)
	if err != nil {
		return nil, fmt.Errorf("transport: encrypt request: %w", err)
	}

	ev := nip01.NewEvent(KindPrivateRequest, content)
	// Randomised into the past, so the event's own metadata says nothing about
	// when the request was really made. This is exactly why freshness cannot live
	// in created_at and lives in the envelope's not_after instead.
	ev.CreatedAt = nip59.RandomizedCreatedAt()
	// The p-tag is how a hub's relay filter finds this at all, and how the hub
	// confirms the event was addressed to its inbox rather than merely encrypted
	// to something. A hub checks it before spending an ECDH.
	ev.Tags = [][]string{{"p", inboxXOnly}}
	// Never assign PubKey by hand — Sign derives it from the private key. See
	// nip59.Wrap's own note about the landmine that used to sit here.
	if err := ev.Sign(ephemeralPrivHex); err != nil {
		return nil, fmt.Errorf("transport: sign request: %w", err)
	}
	return ev, nil
}

// ConversationKeyFor returns the NIP-44 conversation key between a request event's
// own (ephemeral) author and the inbox key it was addressed to.
//
// A client needs this to read the reply: the response is encrypted under
// DeriveReplyKey(conversationKey, replyTo), and after WrapRequest the only place
// the conversation key can still be recovered from is the event itself, since the
// ephemeral private key is intentionally not kept. Callers therefore derive it
// from the event they are about to publish, which also means a caller cannot
// accidentally pair a reply key with the wrong request.
//
// inboxPrivKeyHex is the HUB's side of the same ECDH — a hub uses this function
// too, which is the point: both ends compute the identical key from opposite
// halves, so a mismatch is a bug in one implementation rather than a protocol
// ambiguity.
func ConversationKeyFor(eventPubkeyXOnly, counterpartyPrivKeyHex string) ([32]byte, error) {
	var out [32]byte

	if len(eventPubkeyXOnly) != keyHexLen || !isLowerHex(eventPubkeyXOnly) {
		return out, fmt.Errorf("%w: event pubkey must be %d lowercase hex characters",
			ErrEnvelopeMalformed, keyHexLen)
	}
	pubBytes, err := hex.DecodeString(eventPubkeyXOnly)
	if err != nil {
		return out, fmt.Errorf("%w: event pubkey: %v", ErrEnvelopeMalformed, err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return out, fmt.Errorf("%w: event pubkey is not a valid point: %v", ErrEnvelopeMalformed, err)
	}

	privBytes, err := hex.DecodeString(counterpartyPrivKeyHex)
	if err != nil {
		return out, fmt.Errorf("transport: invalid private key: %w", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)

	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		return out, fmt.Errorf("transport: conversation key: %w", err)
	}
	if len(key) != len(out) {
		return out, fmt.Errorf("transport: conversation key is %d bytes, expected %d", len(key), len(out))
	}
	copy(out[:], key)
	return out, nil
}
