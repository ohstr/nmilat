// Package nip98 implements NIP-98: HTTP Auth, a signed kind-27235 event
// carried in an HTTP Authorization header to prove control of a pubkey to
// an HTTP server (e.g. a file upload endpoint).
package nip98

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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
	ErrMissingPayloadTag = errors.New("NIP-98 event is missing the required payload tag")
	ErrPayloadMismatch   = errors.New("NIP-98 payload tag does not match the request body")
	ErrNoAllowedPubkeys  = errors.New("no pubkey is authorized for this endpoint")
)

// Options tunes Verify for callers needing more than VerifyAuthHeader's
// defaults -- NIP-86 in particular, which requires the payload tag NIP-98
// itself only recommends.
type Options struct {
	// AllowedPubkeys may authenticate. Empty allows nobody: a caller with
	// nothing configured fails closed rather than open.
	AllowedPubkeys []string

	// Body is the request body already read by the caller. When non-nil the
	// event's payload tag must be its SHA-256. A caller that passes the body
	// gets payload verification whether or not RequirePayload is set.
	Body []byte

	// RequirePayload rejects an event with no payload tag even when Body is
	// empty, so an empty-bodied request still has to commit to that emptiness.
	RequirePayload bool

	// NormalizeRootPath compares the u tag ignoring a trailing slash, so a
	// client that signs "https://relay.example" reaches a handler mounted at
	// "/". Without it the comparison is byte-exact and that client gets a 401
	// it cannot diagnose.
	NormalizeRootPath bool
}

// VerifyAuthHeader validates an incoming HTTP request against the NIP-98 spec,
// ensuring the auth event is 1) Signed correctly, 2) Signed by requiredPubkey,
// 3) Within 60 seconds age, 4) Matches HTTP Method, 5) Matches HTTP URL exactly.
//
// It does not verify a payload tag. Use Verify for that.
func VerifyAuthHeader(r *http.Request, requiredPubkey string) error {
	_, err := Verify(r, Options{AllowedPubkeys: []string{requiredPubkey}})
	return err
}

// Verify validates r's Authorization header per NIP-98 and opts, returning the
// pubkey that authenticated. Callers use that pubkey to scope what the request
// may do -- NIP-86's supportedmethods, for one, answers per caller.
func Verify(r *http.Request, opts Options) (string, error) {
	if len(opts.AllowedPubkeys) == 0 {
		return "", ErrNoAllowedPubkeys
	}

	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:6] != "Nostr " {
		return "", ErrMissingAuthHeader
	}

	payloadJSON, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", ErrMissingAuthHeader
	}

	var event nip01.Event
	if err := json.Unmarshal(payloadJSON, &event); err != nil {
		return "", ErrInvalidNIP98Event
	}

	// 1. Must be kind 27235
	if event.Kind != 27235 {
		return "", ErrInvalidNIP98Event
	}

	// 2. Must be from an authorized pubkey
	if !allowed(opts.AllowedPubkeys, event.PubKey) {
		return "", ErrWrongPubkey
	}

	// 3. Verify Nostr Signature
	if err := event.Verify(); err != nil {
		return "", ErrInvalidNIP98Event
	}

	// 4. Timestamp check (Must be within 60 seconds of now)
	now := uint64(time.Now().Unix())
	if event.CreatedAt < now-60 || event.CreatedAt > now+60 {
		return "", ErrEventExpired
	}

	// 5. Verify tags
	var hasURL, hasMethod bool
	var payloadTag string
	reqURL := utils.GetFullHTTPURL(r)

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "u":
			hasURL = true
			if !urlMatches(tag[1], reqURL, opts.NormalizeRootPath) {
				return "", ErrURLMismatch
			}
		case "method":
			hasMethod = true
			if tag[1] != r.Method {
				return "", ErrMethodMismatch
			}
		case "payload":
			payloadTag = tag[1]
		}
	}

	if !hasURL || !hasMethod {
		return "", ErrInvalidNIP98Event
	}

	// 6. Bind the body to the signature, so a captured header cannot be
	// replayed with different contents inside the freshness window.
	if opts.Body != nil || opts.RequirePayload {
		if payloadTag == "" {
			return "", ErrMissingPayloadTag
		}
		sum := sha256.Sum256(opts.Body)
		if !strings.EqualFold(payloadTag, hex.EncodeToString(sum[:])) {
			return "", ErrPayloadMismatch
		}
	}

	return event.PubKey, nil
}

func allowed(pubkeys []string, pubkey string) bool {
	for _, p := range pubkeys {
		if p == pubkey {
			return true
		}
	}
	return false
}

// urlMatches compares the event's u tag against the request URL. normalizeRoot
// relaxes only a trailing slash; everything else stays byte-exact.
func urlMatches(tagURL, reqURL string, normalizeRoot bool) bool {
	if tagURL == reqURL {
		return true
	}
	if !normalizeRoot {
		return false
	}
	return strings.TrimSuffix(tagURL, "/") == strings.TrimSuffix(reqURL, "/")
}
