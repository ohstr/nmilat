package nip98

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// A key is accepted in its one spelling only, and a header past MaxHeader is not read.
func TestVerifyKeySpellingAndHeaderSize(t *testing.T) {
	priv := strings.Repeat("1", 64)
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	url := "https://api.example.org/login"
	h, err := NewAuthHeader(priv, url, "POST", nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", h)
	got, err := VerifyAnyPubkey(req, Options{ExpectURL: url, ExpectMethod: "POST"})
	if err != nil || got != pub {
		t.Fatalf("a lower-case key: %q %v", got, err)
	}
	// the same event with its key in upper case: refused before its signature is read
	ev := decodeHeader(t, h)
	ev.PubKey = strings.ToUpper(ev.PubKey)
	req = httptest.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", encodeHeader(t, *ev))
	if _, err := VerifyAnyPubkey(req, Options{ExpectURL: url, ExpectMethod: "POST"}); err != ErrInvalidNIP98Event {
		t.Fatalf("an upper-case key: %v", err)
	}
	// a header past MaxHeader
	req = httptest.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", "Nostr "+strings.Repeat("A", MaxHeader))
	if _, err := VerifyAnyPubkey(req, Options{ExpectURL: url, ExpectMethod: "POST"}); err != ErrMissingAuthHeader {
		t.Fatalf("a header past MaxHeader: %v", err)
	}
}

func encodeHeader(t *testing.T, ev nip01.Event) string {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return "Nostr " + base64.StdEncoding.EncodeToString(raw)
}
