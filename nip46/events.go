package nip46

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip04"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/utils"
)

// deriveKeys parses a hex private key and hex public key into the types
// nip44's conversation-key derivation needs. Nostr public keys are 32-byte
// x-only schnorr keys, the same shape nip04's shared-secret derivation
// already parses via schnorr.ParsePubKey.
func deriveKeys(privKeyHex, pubKeyHex string) (*btcec.PrivateKey, *btcec.PublicKey, error) {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid private key: %w", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)

	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}

	return priv, pub, nil
}

// encryptContent encrypts plaintext from the holder of privKeyHex to
// pubKeyHex using the named encryption scheme.
func encryptContent(plaintext, encryption, privKeyHex, pubKeyHex string) (string, error) {
	switch encryption {
	case EncryptionNIP44V2:
		priv, pub, err := deriveKeys(privKeyHex, pubKeyHex)
		if err != nil {
			return "", err
		}
		key, err := nip44.GenerateConversationKey(priv, pub)
		if err != nil {
			return "", fmt.Errorf("derive nip44 conversation key: %w", err)
		}
		return nip44.Encrypt(plaintext, key)
	case EncryptionNIP04:
		return nip04.Encrypt(plaintext, privKeyHex, pubKeyHex)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedEncryption, encryption)
	}
}

// decryptContent decrypts ciphertext addressed to the holder of privKeyHex
// from pubKeyHex using the named encryption scheme.
func decryptContent(ciphertext, encryption, privKeyHex, pubKeyHex string) (string, error) {
	switch encryption {
	case EncryptionNIP44V2:
		priv, pub, err := deriveKeys(privKeyHex, pubKeyHex)
		if err != nil {
			return "", err
		}
		key, err := nip44.GenerateConversationKey(priv, pub)
		if err != nil {
			return "", fmt.Errorf("derive nip44 conversation key: %w", err)
		}
		return nip44.Decrypt(ciphertext, key)
	case EncryptionNIP04:
		return nip04.Decrypt(ciphertext, pubKeyHex, privKeyHex)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedEncryption, encryption)
	}
}

// RequestEvent is a parsed kind:24133 request event.
type RequestEvent struct {
	*nip01.Event
	Request
}

// NewRequestEvent builds and encrypts a kind:24133 request event from the
// holder of senderPrivKey to recipientPubkey — the client sending a
// command to a remote signer, or a signer sending "connect" to a client
// during the nostrconnect:// flow. A random request ID is generated and
// returned alongside the event; the caller matches it against the
// eventual response's ID. params may be empty (e.g. for ping,
// get_public_key) but not nil. encryption must be EncryptionNIP04 or
// EncryptionNIP44V2. Caller must sign the returned event with
// senderPrivKey.
func NewRequestEvent(senderPrivKey, recipientPubkey, method string, params []string, encryption string) (event *nip01.Event, requestID string, err error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, "", fmt.Errorf("generate request id: %w", err)
	}
	requestID = id.String()

	if params == nil {
		params = []string{}
	}
	req := Request{RequestID: requestID, Method: method, Params: params}

	plaintext, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("marshal request: %w", err)
	}

	content, err := encryptContent(string(plaintext), encryption, senderPrivKey, recipientPubkey)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt request: %w", err)
	}

	senderPubkey, err := utils.GetPublicKey(senderPrivKey)
	if err != nil {
		return nil, "", fmt.Errorf("derive sender pubkey: %w", err)
	}

	tags := [][]string{{"p", recipientPubkey}}
	if encryption == EncryptionNIP44V2 {
		tags = append(tags, []string{"encryption", encryption})
	}

	return nip01.NewUnsignedEvent(KindRequest, senderPubkey, content, tags...), requestID, nil
}

// ParseRequestEvent decrypts and parses a kind:24133 request event. The
// encryption scheme is determined by the presence/absence of the
// request's "encryption" tag, per spec.
func ParseRequestEvent(event *nip01.Event, recipientPrivKey string) (*RequestEvent, error) {
	if event.Kind != KindRequest {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindRequest)
	}

	encryption := EncryptionNIP04
	if enc, err := utils.FindUniqueEventTagValue(event.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}

	plaintext, err := decryptContent(event.Content, encryption, recipientPrivKey, event.PubKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt request: %w", err)
	}

	var req Request
	if err := json.Unmarshal([]byte(plaintext), &req); err != nil {
		return nil, fmt.Errorf("unmarshal request: %w", err)
	}

	return &RequestEvent{Event: event, Request: req}, nil
}

// ResponseEvent is a parsed kind:24133 response event.
type ResponseEvent struct {
	*nip01.Event
	Response
}

// buildResponseEvent is the shared implementation behind
// NewResponseEvent/NewErrorResponseEvent.
func buildResponseEvent(senderPrivKey, recipientPubkey string, resp Response, encryption string) (*nip01.Event, error) {
	plaintext, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	content, err := encryptContent(string(plaintext), encryption, senderPrivKey, recipientPubkey)
	if err != nil {
		return nil, fmt.Errorf("encrypt response: %w", err)
	}

	senderPubkey, err := utils.GetPublicKey(senderPrivKey)
	if err != nil {
		return nil, fmt.Errorf("derive sender pubkey: %w", err)
	}

	tags := [][]string{{"p", recipientPubkey}}
	if encryption == EncryptionNIP44V2 {
		tags = append(tags, []string{"encryption", encryption})
	}

	return nip01.NewUnsignedEvent(KindRequest, senderPubkey, content, tags...), nil
}

// NewResponseEvent builds and encrypts a successful kind:24133 response
// event answering the request identified by requestID. For an error
// response, use NewErrorResponseEvent instead. encryption must be
// EncryptionNIP04 or EncryptionNIP44V2 (typically the scheme the request
// itself used). Caller must sign it with senderPrivKey.
func NewResponseEvent(senderPrivKey, recipientPubkey, requestID, result, encryption string) (*nip01.Event, error) {
	return buildResponseEvent(senderPrivKey, recipientPubkey, Response{RequestID: requestID, Result: result}, encryption)
}

// NewErrorResponseEvent builds and encrypts an error kind:24133 response
// event answering the request identified by requestID. Caller must sign
// it with senderPrivKey.
func NewErrorResponseEvent(senderPrivKey, recipientPubkey, requestID, errMsg, encryption string) (*nip01.Event, error) {
	return buildResponseEvent(senderPrivKey, recipientPubkey, Response{RequestID: requestID, Error: errMsg}, encryption)
}

// ParseResponseEvent decrypts and parses a kind:24133 response event. The
// encryption scheme is determined by the presence/absence of the
// response's "encryption" tag.
func ParseResponseEvent(event *nip01.Event, recipientPrivKey string) (*ResponseEvent, error) {
	if event.Kind != KindRequest {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindRequest)
	}

	encryption := EncryptionNIP04
	if enc, err := utils.FindUniqueEventTagValue(event.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}

	plaintext, err := decryptContent(event.Content, encryption, recipientPrivKey, event.PubKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal([]byte(plaintext), &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &ResponseEvent{Event: event, Response: resp}, nil
}
