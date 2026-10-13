package nip98

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/ohstr/nmilat/utils"
)

func TestNewAuthHeaderVerifies(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	const url = "http://example.com/api/zap?x=1"
	body := []byte(`{"amount":1000}`)

	header, err := NewAuthHeader(testPrivKey, url, "POST", body)
	if err != nil {
		t.Fatalf("NewAuthHeader: %v", err)
	}

	r := httptest.NewRequest("POST", url, nil)
	r.Header.Set("Authorization", header)

	got, err := Verify(r, Options{AllowedPubkeys: []string{pubkey}, Body: body, RequirePayload: true})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != pubkey {
		t.Errorf("pubkey = %s, want %s", got, pubkey)
	}

	// A different body must not verify against the signed payload tag.
	if _, err := Verify(r, Options{AllowedPubkeys: []string{pubkey}, Body: []byte(`{"amount":9}`)}); !errors.Is(err, ErrPayloadMismatch) {
		t.Errorf("tampered body: got %v, want ErrPayloadMismatch", err)
	}
}

func TestNewAuthHeaderWithoutBody(t *testing.T) {
	const url = "http://example.com/api/me"
	header, err := NewAuthHeader(testPrivKey, url, "GET", nil)
	if err != nil {
		t.Fatalf("NewAuthHeader: %v", err)
	}

	r := httptest.NewRequest("GET", url, nil)
	r.Header.Set("Authorization", header)
	if _, err := VerifyAnyPubkey(r, Options{}); err != nil {
		t.Fatalf("VerifyAnyPubkey: %v", err)
	}
	if _, err := VerifyAnyPubkey(r, Options{RequirePayload: true}); !errors.Is(err, ErrMissingPayloadTag) {
		t.Errorf("RequirePayload without a body: got %v, want ErrMissingPayloadTag", err)
	}
}

func TestNewAuthHeaderInvalidKey(t *testing.T) {
	if _, err := NewAuthHeader("not-hex", "http://example.com/", "GET", nil); err == nil {
		t.Error("expected an error for an invalid private key")
	}
}
