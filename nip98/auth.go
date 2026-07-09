// Package nip98 implements NIP-98: HTTP Auth, a signed kind-27235 event
// carried in an HTTP Authorization header to prove control of a pubkey to
// an HTTP server (e.g. a file upload endpoint).
package nip98

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

var (
	ErrMissingAuthHeader = errors.New("missing or malformed Authorization header")
	ErrInvalidNIP98Event = errors.New("invalid NIP-98 event payload")
	ErrEventExpired      = errors.New("NIP-98 event is expired (created_at too old or in future)")
	ErrMethodMismatch    = errors.New("NIP-98 event method does not match HTTP request")
	ErrURLMismatch       = errors.New("NIP-98 event URL does not match HTTP request")
	ErrWrongPubkey       = errors.New("NIP-98 signature not from allowed pubkey")
)

// VerifyAuthHeader validates an incoming HTTP request against the NIP-98 spec,
// ensuring the auth event is 1) Signed correctly, 2) Signed by requiredPubkey,
// 3) Within 60 seconds age, 4) Matches HTTP Method, 5) Matches HTTP URL exactly.
func VerifyAuthHeader(r *http.Request, requiredPubkey string) error {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:6] != "Nostr " {
		return ErrMissingAuthHeader
	}

	b64Payload := authHeader[6:]
	payloadJSON, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		return ErrMissingAuthHeader
	}

	var event nip01.Event
	if err := json.Unmarshal(payloadJSON, &event); err != nil {
		return ErrInvalidNIP98Event
	}

	// 1. Must be kind 27235
	if event.Kind != 27235 {
		return ErrInvalidNIP98Event
	}

	// 2. Must be from the required authorized static pubkey
	if event.PubKey != requiredPubkey {
		return ErrWrongPubkey
	}

	// 3. Verify Nostr Signature
	if err := event.Verify(); err != nil {
		return ErrInvalidNIP98Event
	}

	// 4. Timestamp check (Must be within 60 seconds of now)
	now := uint64(time.Now().Unix())
	if event.CreatedAt < now-60 || event.CreatedAt > now+60 {
		return ErrEventExpired
	}

	// 5. Verify tags
	var hasURL, hasMethod bool
	reqURL := utils.GetFullHTTPURL(r) // We will implement an absolute URL formatter

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		if tag[0] == "u" {
			hasURL = true
			if tag[1] != reqURL {
				return ErrURLMismatch
			}
		}
		if tag[0] == "method" {
			hasMethod = true
			if tag[1] != r.Method {
				return ErrMethodMismatch
			}
		}
	}

	if !hasURL || !hasMethod {
		return ErrInvalidNIP98Event
	}

	return nil
}
