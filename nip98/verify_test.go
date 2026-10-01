package nip98

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func TestVerify_ReturnsAuthenticatedPubkey(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/path"},
		{"method", "GET"},
	}))

	got, err := Verify(req, Options{AllowedPubkeys: []string{pubkey}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != pubkey {
		t.Fatalf("pubkey = %q, want %q", got, pubkey)
	}
}

// No configured admin must mean nobody gets in, not everybody.
func TestVerify_NoAllowedPubkeysFailsClosed(t *testing.T) {
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/path"},
		{"method", "GET"},
	}))

	if _, err := Verify(req, Options{}); !errors.Is(err, ErrNoAllowedPubkeys) {
		t.Fatalf("err = %v, want ErrNoAllowedPubkeys", err)
	}
}

func TestVerify_SecondAllowedPubkeyAccepted(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "GET", "http://example.com/path")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/path"},
		{"method", "GET"},
	}))

	other := strings.Repeat("a", 64)
	if _, err := Verify(req, Options{AllowedPubkeys: []string{other, pubkey}}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_PayloadMatches(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	body := []byte(`{"method":"listallowedpubkeys","params":[]}`)
	req := newAuthRequest(t, "POST", "http://example.com/")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/"},
		{"method", "POST"},
		{"payload", bodyHash(body)},
	}))

	if _, err := Verify(req, Options{AllowedPubkeys: []string{pubkey}, Body: body}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// Uppercase hex is still the same hash.
func TestVerify_PayloadCaseInsensitive(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	body := []byte("x")
	req := newAuthRequest(t, "POST", "http://example.com/")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/"},
		{"method", "POST"},
		{"payload", strings.ToUpper(bodyHash(body))},
	}))

	if _, err := Verify(req, Options{AllowedPubkeys: []string{pubkey}, Body: body}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// The point of binding the body: a captured header must not carry a different
// one inside the freshness window.
func TestVerify_SwappedBodyRejected(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	signed := []byte(`{"method":"allowpubkey","params":["alice"]}`)
	swapped := []byte(`{"method":"allowpubkey","params":["attacker"]}`)
	req := newAuthRequest(t, "POST", "http://example.com/")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/"},
		{"method", "POST"},
		{"payload", bodyHash(signed)},
	}))

	_, err := Verify(req, Options{AllowedPubkeys: []string{pubkey}, Body: swapped})
	if !errors.Is(err, ErrPayloadMismatch) {
		t.Fatalf("err = %v, want ErrPayloadMismatch", err)
	}
}

func TestVerify_MissingPayloadTagRejectedWhenRequired(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	body := []byte(`{}`)
	req := newAuthRequest(t, "POST", "http://example.com/")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/"},
		{"method", "POST"},
	}))

	opts := Options{AllowedPubkeys: []string{pubkey}, Body: body, RequirePayload: true}
	if _, err := Verify(req, opts); !errors.Is(err, ErrMissingPayloadTag) {
		t.Fatalf("err = %v, want ErrMissingPayloadTag", err)
	}
}

// An endpoint can gain body binding without turning away a client that predates
// the tag: present is checked, absent is tolerated unless required.
func TestVerify_MissingPayloadTagToleratedWhenNotRequired(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "POST", "http://example.com/")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/"},
		{"method", "POST"},
	}))

	if _, err := Verify(req, Options{AllowedPubkeys: []string{pubkey}, Body: []byte(`{}`)}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// An empty body still has to commit to being empty.
func TestVerify_RequirePayloadWithEmptyBody(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "POST", "http://example.com/")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/"},
		{"method", "POST"},
	}))

	_, err := Verify(req, Options{AllowedPubkeys: []string{pubkey}, RequirePayload: true})
	if !errors.Is(err, ErrMissingPayloadTag) {
		t.Fatalf("err = %v, want ErrMissingPayloadTag", err)
	}

	req2 := newAuthRequest(t, "POST", "http://example.com/")
	req2.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/"},
		{"method", "POST"},
		{"payload", bodyHash(nil)},
	}))
	if _, err := Verify(req2, Options{AllowedPubkeys: []string{pubkey}, RequirePayload: true}); err != nil {
		t.Fatalf("Verify with empty-body hash: %v", err)
	}
}

// A client that signs the bare relay URL reaches a handler mounted at "/".
func TestVerify_NormalizeRootPath(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	header := buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com"},
		{"method", "POST"},
	})

	req := newAuthRequest(t, "POST", "http://example.com/")
	req.Header.Set("Authorization", header)
	if _, err := Verify(req, Options{AllowedPubkeys: []string{pubkey}, NormalizeRootPath: true}); err != nil {
		t.Fatalf("Verify with NormalizeRootPath: %v", err)
	}

	strict := newAuthRequest(t, "POST", "http://example.com/")
	strict.Header.Set("Authorization", header)
	_, err := Verify(strict, Options{AllowedPubkeys: []string{pubkey}})
	if !errors.Is(err, ErrURLMismatch) {
		t.Fatalf("err = %v, want ErrURLMismatch without NormalizeRootPath", err)
	}
}

// Normalizing a trailing slash must not collapse genuinely different paths.
func TestVerify_NormalizeRootPathStillRejectsOtherPaths(t *testing.T) {
	pubkey := signedRequiredPubkey(t)
	req := newAuthRequest(t, "POST", "http://example.com/admin")
	req.Header.Set("Authorization", buildAuthHeader(t, 27235, "", 0, [][]string{
		{"u", "http://example.com/other"},
		{"method", "POST"},
	}))

	_, err := Verify(req, Options{AllowedPubkeys: []string{pubkey}, NormalizeRootPath: true})
	if !errors.Is(err, ErrURLMismatch) {
		t.Fatalf("err = %v, want ErrURLMismatch", err)
	}
}
