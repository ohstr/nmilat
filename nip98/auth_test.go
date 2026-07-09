package nip98

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

const testPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

func newAuthRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, url, nil)
}

func buildAuthHeader(t *testing.T, kind int, pubkeyOverride string, createdAtOffset int64, tags [][]string) string {
	t.Helper()

	event := &nip01.Event{
		Kind:      kind,
		CreatedAt: uint64(time.Now().Unix() + createdAtOffset),
		Tags:      tags,
	}
	if err := event.Sign(testPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	if pubkeyOverride != "" {
		event.PubKey = pubkeyOverride
	}

	eventBytes, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	return "Nostr " + base64.StdEncoding.EncodeToString(eventBytes)
}

func signedRequiredPubkey(t *testing.T) string {
	t.Helper()
	ev := &nip01.Event{}
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("failed to derive pubkey: %v", err)
	}
	return ev.PubKey
}

func TestVerifyAuthHeader_Success(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "GET", "http://example.com/path")

	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/path"},
		{"method", "GET"},
	}))

	if err := VerifyAuthHeader(req, pubkey); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestVerifyAuthHeader_MissingHeader(t *testing.T) {
	req := newAuthRequest(t, "GET", "http://example.com/path")
	err := VerifyAuthHeader(req, "anypubkey")
	if !errors.Is(err, ErrMissingAuthHeader) {
		t.Fatalf("expected ErrMissingAuthHeader, got %v", err)
	}
}

func TestVerifyAuthHeader_MalformedHeaderPrefix(t *testing.T) {
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", "Bearer sometoken")
	err := VerifyAuthHeader(req, "anypubkey")
	if !errors.Is(err, ErrMissingAuthHeader) {
		t.Fatalf("expected ErrMissingAuthHeader, got %v", err)
	}
}

func TestVerifyAuthHeader_BadBase64(t *testing.T) {
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", "Nostr not-valid-base64!!")
	err := VerifyAuthHeader(req, "anypubkey")
	if !errors.Is(err, ErrMissingAuthHeader) {
		t.Fatalf("expected ErrMissingAuthHeader, got %v", err)
	}
}

func TestVerifyAuthHeader_InvalidJSON(t *testing.T) {
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString([]byte("not json")))
	err := VerifyAuthHeader(req, "anypubkey")
	if !errors.Is(err, ErrInvalidNIP98Event) {
		t.Fatalf("expected ErrInvalidNIP98Event, got %v", err)
	}
}

func TestVerifyAuthHeader_WrongKind(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 1, "", 0, [][]string{
		{"u", "http://example.com/path"},
		{"method", "GET"},
	}))

	err := VerifyAuthHeader(req, pubkey)
	if !errors.Is(err, ErrInvalidNIP98Event) {
		t.Fatalf("expected ErrInvalidNIP98Event, got %v", err)
	}
}

func TestVerifyAuthHeader_WrongPubkey(t *testing.T) {
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/path"},
		{"method", "GET"},
	}))

	err := VerifyAuthHeader(req, "0000000000000000000000000000000000000000000000000000000000000000")
	if !errors.Is(err, ErrWrongPubkey) {
		t.Fatalf("expected ErrWrongPubkey, got %v", err)
	}
}

func TestVerifyAuthHeader_InvalidSignature(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "GET", "http://example.com/path")

	event := &nip01.Event{
		Kind:      27235,
		CreatedAt: uint64(time.Now().Unix()),
		Tags: [][]string{
			{"u", "http://example.com/path"},
			{"method", "GET"},
		},
	}
	if err := event.Sign(testPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	// Tamper with the content after signing so the signature no longer matches.
	event.Content = "tampered"

	eventBytes, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}
	req.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString(eventBytes))

	err = VerifyAuthHeader(req, pubkey)
	if !errors.Is(err, ErrInvalidNIP98Event) {
		t.Fatalf("expected ErrInvalidNIP98Event, got %v", err)
	}
}

func TestVerifyAuthHeader_Expired(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", -120, [][]string{
		{"u", "http://example.com/path"},
		{"method", "GET"},
	}))

	err := VerifyAuthHeader(req, pubkey)
	if !errors.Is(err, ErrEventExpired) {
		t.Fatalf("expected ErrEventExpired, got %v", err)
	}
}

func TestVerifyAuthHeader_MethodMismatch(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "POST", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/path"},
		{"method", "GET"},
	}))

	err := VerifyAuthHeader(req, pubkey)
	if !errors.Is(err, ErrMethodMismatch) {
		t.Fatalf("expected ErrMethodMismatch, got %v", err)
	}
}

func TestVerifyAuthHeader_URLMismatch(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/other-path"},
		{"method", "GET"},
	}))

	err := VerifyAuthHeader(req, pubkey)
	if !errors.Is(err, ErrURLMismatch) {
		t.Fatalf("expected ErrURLMismatch, got %v", err)
	}
}

func TestVerifyAuthHeader_MissingTags(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, nil))

	err := VerifyAuthHeader(req, pubkey)
	if !errors.Is(err, ErrInvalidNIP98Event) {
		t.Fatalf("expected ErrInvalidNIP98Event, got %v", err)
	}
}
