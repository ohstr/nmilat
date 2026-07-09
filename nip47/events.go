package nip47

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
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
		return "", fmt.Errorf("unsupported encryption %q, must be %q or %q", encryption, EncryptionNIP04, EncryptionNIP44V2)
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
		return "", fmt.Errorf("unsupported encryption %q, must be %q or %q", encryption, EncryptionNIP04, EncryptionNIP44V2)
	}
}

// InfoEvent is the parsed kind:13194 wallet capability advertisement.
type InfoEvent struct {
	*nip01.Event
	Methods              []string
	NotificationTypes    []string
	SupportedEncryptions []string
}

// NewInfoEvent builds an unsigned kind:13194 info event advertising the
// wallet service's capabilities. Caller must sign it with the wallet
// service identity key matching walletPubkey.
func NewInfoEvent(walletPubkey string, methods, notificationTypes, supportedEncryptions []string) *nip01.Event {
	var tags [][]string
	if len(supportedEncryptions) > 0 {
		tags = append(tags, []string{"encryption", strings.Join(supportedEncryptions, " ")})
	}
	if len(notificationTypes) > 0 {
		tags = append(tags, []string{"notifications", strings.Join(notificationTypes, " ")})
	}

	return &nip01.Event{
		PubKey:    walletPubkey,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindNWCInfo,
		Tags:      tags,
		Content:   strings.Join(methods, " "),
	}
}

// ParseInfoEvent parses a kind:13194 info event. Absence of the encryption
// tag implies the wallet only supports legacy NIP-04, per spec.
func ParseInfoEvent(event *nip01.Event) (*InfoEvent, error) {
	if event.Kind != KindNWCInfo {
		return nil, fmt.Errorf("invalid kind %d, expected %d", event.Kind, KindNWCInfo)
	}

	info := &InfoEvent{
		Event:                event,
		SupportedEncryptions: []string{EncryptionNIP04},
	}
	if event.Content != "" {
		info.Methods = strings.Fields(event.Content)
	}
	if enc, err := utils.FindUniqueEventTagValue(event.Tags, "encryption"); err == nil && enc != "" {
		info.SupportedEncryptions = strings.Fields(enc)
	}
	if notif, err := utils.FindUniqueEventTagValue(event.Tags, "notifications"); err == nil && notif != "" {
		info.NotificationTypes = strings.Fields(notif)
	}

	return info, nil
}

// NewRequestEvent builds and encrypts a kind:23194 request event from the
// client's connection key to the wallet service. params is marshaled to
// JSON internally — pass a typed params struct (e.g. PayInvoiceParams), or
// nil for methods that take none (e.g. get_balance, get_info). encryption
// must be EncryptionNIP04 or EncryptionNIP44V2. Caller must sign it with
// appPrivKey.
func NewRequestEvent(appPrivKey, walletPubkey, method string, params any, encryption string) (*nip01.Event, error) {
	req := Request{Method: method}
	if params != nil {
		paramsJSON, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
		req.Params = paramsJSON
	}

	plaintext, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	content, err := encryptContent(string(plaintext), encryption, appPrivKey, walletPubkey)
	if err != nil {
		return nil, fmt.Errorf("encrypt request: %w", err)
	}

	appPubkey, err := utils.GetPublicKey(appPrivKey)
	if err != nil {
		return nil, fmt.Errorf("derive app pubkey: %w", err)
	}

	tags := [][]string{{"p", walletPubkey}}
	if encryption == EncryptionNIP44V2 {
		tags = append(tags, []string{"encryption", encryption})
	}

	return &nip01.Event{
		PubKey:    appPubkey,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindNWCRequest,
		Tags:      tags,
		Content:   content,
	}, nil
}

// ParseRequestEvent decrypts and parses a kind:23194 request event received
// by the wallet service. The encryption scheme is determined by the
// presence/absence of the request's "encryption" tag, per spec.
func ParseRequestEvent(event *nip01.Event, walletPrivKey string) (*Request, error) {
	if event.Kind != KindNWCRequest {
		return nil, fmt.Errorf("invalid kind %d, expected %d", event.Kind, KindNWCRequest)
	}

	encryption := EncryptionNIP04
	if enc, err := utils.FindUniqueEventTagValue(event.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}

	plaintext, err := decryptContent(event.Content, encryption, walletPrivKey, event.PubKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt request: %w", err)
	}

	var req Request
	if err := json.Unmarshal([]byte(plaintext), &req); err != nil {
		return nil, fmt.Errorf("unmarshal request: %w", err)
	}
	return &req, nil
}

// NewResponseEvent builds and encrypts a successful kind:23195 response
// event answering requestEvent. result is marshaled to JSON internally —
// pass a typed result struct (e.g. PayInvoiceResult), or nil if the method
// has no result payload. For an error response, use NewErrorResponseEvent
// instead. encryption must be EncryptionNIP04 or EncryptionNIP44V2
// (typically the scheme requestEvent itself used). extraTags is appended
// after the standard p/e/(encryption) tags — used to attach a
// ["d", subPaymentID] tag when building one of the per-sub-payment fanout
// response events multi_pay_invoice/multi_pay_keysend require (one call per
// sub-payment, not a single batched response). Caller must sign it with
// walletPrivKey.
func NewResponseEvent(walletPrivKey, appPubkey, resultType string, result any, requestEvent *nip01.Event, encryption string, extraTags ...[]string) (*nip01.Event, error) {
	resp := Response{ResultType: resultType}
	if result != nil {
		resultJSON, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("marshal result: %w", err)
		}
		resp.Result = resultJSON
	}
	return buildResponseEvent(walletPrivKey, appPubkey, resp, requestEvent, encryption, extraTags...)
}

// NewErrorResponseEvent builds and encrypts an error kind:23195 response
// event answering requestEvent. Caller must sign it with walletPrivKey.
func NewErrorResponseEvent(walletPrivKey, appPubkey, resultType string, respErr Error, requestEvent *nip01.Event, encryption string, extraTags ...[]string) (*nip01.Event, error) {
	resp := Response{ResultType: resultType, Error: &respErr}
	return buildResponseEvent(walletPrivKey, appPubkey, resp, requestEvent, encryption, extraTags...)
}

func buildResponseEvent(walletPrivKey, appPubkey string, resp Response, requestEvent *nip01.Event, encryption string, extraTags ...[]string) (*nip01.Event, error) {
	plaintext, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	content, err := encryptContent(string(plaintext), encryption, walletPrivKey, appPubkey)
	if err != nil {
		return nil, fmt.Errorf("encrypt response: %w", err)
	}

	walletPubkey, err := utils.GetPublicKey(walletPrivKey)
	if err != nil {
		return nil, fmt.Errorf("derive wallet pubkey: %w", err)
	}

	tags := [][]string{{"p", appPubkey}, {"e", requestEvent.ID}}
	if encryption == EncryptionNIP44V2 {
		tags = append(tags, []string{"encryption", encryption})
	}
	tags = append(tags, extraTags...)

	return &nip01.Event{
		PubKey:    walletPubkey,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindNWCResponse,
		Tags:      tags,
		Content:   content,
	}, nil
}

// ResponseEvent is a parsed kind:23195 response event.
type ResponseEvent struct {
	*nip01.Event
	Response
	RequestEventID string // from the "e" tag
	SubPaymentID   string // from the "d" tag; empty for single-payment methods
}

// ParseResponseEvent decrypts and parses a kind:23195 response event
// received by the client. The encryption scheme is determined by the
// presence/absence of the response's "encryption" tag.
func ParseResponseEvent(event *nip01.Event, appPrivKey string) (*ResponseEvent, error) {
	if event.Kind != KindNWCResponse {
		return nil, fmt.Errorf("invalid kind %d, expected %d", event.Kind, KindNWCResponse)
	}

	requestEventID, err := utils.FindUniqueEventTagValue(event.Tags, "e")
	if err != nil {
		return nil, fmt.Errorf("response e tag: %w", err)
	}

	var subPaymentID string
	if d, err := utils.FindUniqueEventTagValue(event.Tags, "d"); err == nil {
		subPaymentID = d
	} else if !errors.Is(err, utils.ErrTagNotFound) {
		return nil, fmt.Errorf("response d tag: %w", err)
	}

	encryption := EncryptionNIP04
	if enc, err := utils.FindUniqueEventTagValue(event.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}

	plaintext, err := decryptContent(event.Content, encryption, appPrivKey, event.PubKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal([]byte(plaintext), &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &ResponseEvent{
		Event:          event,
		Response:       resp,
		RequestEventID: requestEventID,
		SubPaymentID:   subPaymentID,
	}, nil
}

// NewNotificationEvent builds and encrypts a notification event from the
// wallet service to the client: kind:23197 (NIP-44) if useNIP44 is true,
// otherwise the legacy kind:23196 (NIP-04). Caller must sign it with
// walletPrivKey.
func NewNotificationEvent(walletPrivKey, appPubkey string, notif Notification, useNIP44 bool) (*nip01.Event, error) {
	plaintext, err := json.Marshal(notif)
	if err != nil {
		return nil, fmt.Errorf("marshal notification: %w", err)
	}

	encryption := EncryptionNIP04
	kind := KindNWCLegacyNotification
	if useNIP44 {
		encryption = EncryptionNIP44V2
		kind = KindNWCNotification
	}

	content, err := encryptContent(string(plaintext), encryption, walletPrivKey, appPubkey)
	if err != nil {
		return nil, fmt.Errorf("encrypt notification: %w", err)
	}

	walletPubkey, err := utils.GetPublicKey(walletPrivKey)
	if err != nil {
		return nil, fmt.Errorf("derive wallet pubkey: %w", err)
	}

	return &nip01.Event{
		PubKey:    walletPubkey,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      kind,
		Tags:      [][]string{{"p", appPubkey}},
		Content:   content,
	}, nil
}

// ParseNotificationEvent decrypts and parses a notification event (kind
// 23197 or legacy 23196) received by the client.
func ParseNotificationEvent(event *nip01.Event, appPrivKey string) (*Notification, error) {
	var encryption string
	switch event.Kind {
	case KindNWCNotification:
		encryption = EncryptionNIP44V2
	case KindNWCLegacyNotification:
		encryption = EncryptionNIP04
	default:
		return nil, fmt.Errorf("invalid kind %d, expected %d or %d", event.Kind, KindNWCNotification, KindNWCLegacyNotification)
	}

	plaintext, err := decryptContent(event.Content, encryption, appPrivKey, event.PubKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt notification: %w", err)
	}

	var notif Notification
	if err := json.Unmarshal([]byte(plaintext), &notif); err != nil {
		return nil, fmt.Errorf("unmarshal notification: %w", err)
	}
	return &notif, nil
}
