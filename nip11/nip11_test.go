package nip11

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestNewHandler(t *testing.T) {
	md := &Metadata{
		Name:        "Test Relay",
		PubKey:      "test-pubkey",
		Contact:     "test-contact",
		Description: "A test relay",
		Software:    "nmilat",
		Version:     "1.0.0",
		Limitation: Limitation{
			MaxLimit:         500,
			MaxMessageLength: 1000,
			AuthRequired:     true,
		},
	}
	nips := NewNIPSet(NIP(1), NIP(2), NIP(9), NIP(11))

	handler := NewHandler(md, nips)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("NewHandler() status code = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	// Check content type header
	if contentType := resp.Header.Get("content-type"); contentType != ContentTypeHeader {
		t.Errorf("NewHandler() content-type = %v, want %v", contentType, ContentTypeHeader)
	}

	// Check CORS header
	if cors := resp.Header.Get("Access-Control-Allow-Origin"); cors != "*" {
		t.Errorf("NewHandler() CORS header = %v, want *", cors)
	}

	// Decode body and compare
	var decodedMD Metadata
	if err := json.Unmarshal(body, &decodedMD); err != nil {
		t.Fatalf("Failed to unmarshal response body: %v", err)
	}

	want := *md
	want.SupportedNips = nips.Slice()
	if !reflect.DeepEqual(want, decodedMD) {
		t.Errorf("NewHandler() body mismatch.\nWant: %+v\nGot: %+v", want, decodedMD)
	}
}

func TestNewHandler_NeverLeaksPrivateFields(t *testing.T) {
	md := &Metadata{
		Name:    "Test Relay",
		PubKey:  "test-pubkey",
		PrivKey: "super-secret-private-key",
		Delegation: &DelegationConfig{
			Issuer:     "issuer-pubkey",
			Conditions: "kind=1",
			Token:      "secret-delegation-token",
		},
	}

	handler := NewHandler(md, NewNIPSet(NIP(1), NIP(11)))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	bodyStr := string(body)

	for _, secret := range []string{md.PrivKey, md.Delegation.Token} {
		if contains(bodyStr, secret) {
			t.Errorf("NewHandler() response leaked a private field.\nBody: %s", bodyStr)
		}
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal response body: %v", err)
	}
	if _, ok := decoded["privkey"]; ok {
		t.Error("NewHandler() response contains a \"privkey\" key")
	}
	if _, ok := decoded["delegation"]; ok {
		t.Error("NewHandler() response contains a \"delegation\" key")
	}
}

func TestNewNIPSet(t *testing.T) {
	got := NewNIPSet(NIP(9), NIP(1), NIP(1), NIP(11), NIP(9)).Slice()
	want := []NIPID{NIP(1), NIP(9), NIP(11)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NewNIPSet() = %v, want %v", got, want)
	}
}

func TestNewNIPSetLetteredSortsAfterNumbered(t *testing.T) {
	got := NewNIPSet(NIPLetter("B7"), NIP(11), NIPLetter("B0"), NIP(1)).Slice()
	want := []NIPID{NIP(1), NIP(11), NIPLetter("B0"), NIPLetter("B7")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NewNIPSet() = %v, want %v", got, want)
	}
}

func TestNIPIDMarshalJSON(t *testing.T) {
	numBytes, err := json.Marshal(NIP(42))
	if err != nil {
		t.Fatalf("json.Marshal(NIP(42)) error = %v", err)
	}
	if string(numBytes) != "42" {
		t.Errorf("json.Marshal(NIP(42)) = %s, want 42", numBytes)
	}

	strBytes, err := json.Marshal(NIPLetter("B7"))
	if err != nil {
		t.Fatalf("json.Marshal(NIPLetter(\"B7\")) error = %v", err)
	}
	if string(strBytes) != `"B7"` {
		t.Errorf("json.Marshal(NIPLetter(\"B7\")) = %s, want \"B7\"", strBytes)
	}

	var roundTripped NIPID
	if err := json.Unmarshal(strBytes, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", strBytes, err)
	}
	if roundTripped != NIPLetter("B7") {
		t.Errorf("round-tripped = %v, want %v", roundTripped, NIPLetter("B7"))
	}
}

func TestMetadataTags(t *testing.T) {
	// Verify that struct tags are working as expected (especially mapstructure if used elsewhere, but here we test json)
	md := Metadata{
		Name: "Test",
	}
	bytes, err := json.Marshal(md)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	jsonStr := string(bytes)
	// Simple string check to ensure "name" field is present in JSON
	if !contains(jsonStr, "\"name\":\"Test\"") {
		t.Errorf("JSON output invalid, expected name field. Got: %s", jsonStr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s[0:len(substr)] == substr || contains(s[1:], substr))
}
