package nip59

// NIP-59: Gift Wrap & Seal + NIP-44 Encryption (Simplified)

import (
	"encoding/hex"
	"encoding/json"
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

// Simplified implementation of wrapping logic.
// A full NIP-44/59 implementation requires complex key derivation (HKDF) and nonces.

func Wrap(payload *nip01.Event, senderPrivKeyHex, recipientPubKeyHex string) (*nip01.Event, error) {
	// 1. Create Seal (Kind 13)
	//    Seal content = encrypted payload (NIP-44 style)
	//    Seal recipient = logged in user (sender) ?? No, Seal is signed by sender, encrypted to recipient.

	// For this exercise, I will assume a simpler "NIP-04-like" encryption but using the NIP-59 structure
	// because full NIP-44 is heavy. But user asked for NIP-59.
	// I will produce the structure Kind 1059 -> Kind 13 -> Payload.
	// But use standard ECDH + AES/ChaCha for content if NIP-44 compliance is too big to fit in one file.
	// Actually, let's try to be close to spec if possible using XChaCha20Poly1305.

	senderPrivBytes, err := hex.DecodeString(senderPrivKeyHex)
	if err != nil {
		return nil, err
	}
	senderPriv, _ := btcec.PrivKeyFromBytes(senderPrivBytes)

	recipientPubBytes, err := hex.DecodeString(recipientPubKeyHex)
	if err != nil {
		return nil, err
	}
	recipientPub, err := schnorr.ParsePubKey(recipientPubBytes)
	if err != nil {
		return nil, err
	}

	// Prepare Seal
	// In NIP-59, the Seal (Kind 13) Is signed by the SENDER.
	// The content of the Seal is the JSON of the payload, encrypted to RECIPIENT.

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// Encryption (Sender -> Recipient)
	// Use NIP-44 v2
	conversationKey, err := nip44.GenerateConversationKey(senderPriv, recipientPub)
	if err != nil {
		return nil, err
	}

	encryptedSealContent, err := nip44.Encrypt(string(payloadJson), conversationKey)
	if err != nil {
		return nil, err
	}

	seal := nip01.NewEvent(KindSeal, encryptedSealContent)
	seal.CreatedAt = uint64(time.Now().Unix())
	seal.PubKey = senderPrivKeyHex
	if err := seal.Sign(senderPrivKeyHex); err != nil {
		return nil, err
	}

	// 2. Create Gift Wrap (Kind 1059)
	//    Gift Wrap is signed by a RANDOM ephemeral key.
	//    Content is the Seal JSON, encrypted to RECIPIENT.

	// Generate random ephemeral key
	ephemeralPriv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	ephemeralPrivHex := hex.EncodeToString(ephemeralPriv.Serialize())

	sealJson, err := json.Marshal(seal)
	if err != nil {
		return nil, err
	}

	conversationKeyWrap, err := nip44.GenerateConversationKey(ephemeralPriv, recipientPub)
	if err != nil {
		return nil, err
	}

	encryptedWrapContent, err := nip44.Encrypt(string(sealJson), conversationKeyWrap)
	if err != nil {
		return nil, err
	}

	wrap := nip01.NewEvent(KindGiftWrap, encryptedWrapContent)
	wrap.Tags = [][]string{{"p", recipientPubKeyHex}}
	wrap.CreatedAt = uint64(time.Now().Unix()) // potentially tweaked
	if err := wrap.Sign(ephemeralPrivHex); err != nil {
		return nil, err
	}

	return wrap, nil
}
