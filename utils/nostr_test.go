package utils

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetNip05URL(t *testing.T) {
	if got := GetNip05URL("bob@example.com"); got != "https://example.com/.well-known/nostr.json?name=bob" {
		t.Errorf("unexpected URL: %s", got)
	}
	if got := GetNip05URL("not-a-valid-identifier"); got != "" {
		t.Errorf("expected empty string for malformed identifier, got %q", got)
	}
}

func TestGetLud16URL(t *testing.T) {
	if got := GetLud16URL("bob@example.com"); got != "https://example.com/.well-known/lnurlp/bob" {
		t.Errorf("unexpected URL: %s", got)
	}
	if got := GetLud16URL("malformed"); got != "" {
		t.Errorf("expected empty string for malformed identifier, got %q", got)
	}
}

func TestGetDomainOnly(t *testing.T) {
	if got := GetDomainOnly("bob@example.com"); got != "example.com" {
		t.Errorf("expected example.com, got %q", got)
	}
	if got := GetDomainOnly("malformed"); got != "" {
		t.Errorf("expected empty string for malformed identifier, got %q", got)
	}
}

func TestGetFullHTTPURL(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/path?x=1", nil)
	if got := GetFullHTTPURL(req); got != "http://example.com/path?x=1" {
		t.Errorf("unexpected URL: %s", got)
	}

	reqXFP := httptest.NewRequest("GET", "http://example.com/path", nil)
	reqXFP.Header.Set("X-Forwarded-Proto", "https")
	if got := GetFullHTTPURL(reqXFP); got != "https://example.com/path" {
		t.Errorf("expected https scheme via X-Forwarded-Proto, got %s", got)
	}
}

func TestVerifyNip05(t *testing.T) {
	body := `{"names":{"bob":"pubkeyABC"}}`

	if !VerifyNip05(strings.NewReader(body), "pubkeyabc", "bob@example.com") {
		t.Error("expected case-insensitive pubkey match to succeed")
	}
	if VerifyNip05(strings.NewReader(body), "wrongpubkey", "bob@example.com") {
		t.Error("expected mismatched pubkey to fail")
	}
	if VerifyNip05(strings.NewReader(body), "pubkeyABC", "unknown@example.com") {
		t.Error("expected unknown name to fail")
	}
	if VerifyNip05(strings.NewReader(body), "pubkeyABC", "malformed") {
		t.Error("expected malformed nip05 identifier to fail")
	}
	if VerifyNip05(strings.NewReader("not json"), "pubkeyABC", "bob@example.com") {
		t.Error("expected malformed JSON body to fail")
	}
}

func TestUnmarshalJSON(t *testing.T) {
	var v struct {
		Name string `json:"name"`
	}
	if err := UnmarshalJSON([]byte(`{"name":"bob"}`), &v); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "bob" {
		t.Errorf("expected name=bob, got %q", v.Name)
	}
}

func TestIsValidPictureURL(t *testing.T) {
	if !IsValidPictureURL("https://example.com/pic.png") {
		t.Error("expected https URL to be valid")
	}
	if !IsValidPictureURL("http://example.com/pic.png") {
		t.Error("expected http URL to be valid")
	}
	if IsValidPictureURL("") {
		t.Error("expected empty string to be invalid")
	}
	if IsValidPictureURL("ftp://example.com/pic.png") {
		t.Error("expected non-http(s) scheme to be invalid")
	}
}
