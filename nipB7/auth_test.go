package nipB7

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

func newSignedAuth(t *testing.T, p AuthorizationParams) *nip01.Event {
	t.Helper()
	ev := NewAuthorization(p)
	return signed(t, ev)
}

func TestNewAuthorizationAndParse(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	ev := newSignedAuth(t, AuthorizationParams{
		Verb:       VerbUpload,
		Content:    "Upload blob",
		Expiration: exp,
		Servers:    []string{"https://blossom.example"},
		Hashes:     []string{testHash},
	})

	auth, err := ParseAuthorization(ev)
	if err != nil {
		t.Fatalf("ParseAuthorization() error = %v", err)
	}
	if auth.Verb != VerbUpload {
		t.Errorf("Verb = %q, want %q", auth.Verb, VerbUpload)
	}
	if auth.Expiration != uint64(exp.Unix()) {
		t.Errorf("Expiration = %d, want %d", auth.Expiration, exp.Unix())
	}
	if !auth.HasServer("blossom.example") {
		t.Error("HasServer(blossom.example) = false, want true")
	}
	if !auth.HasServer("https://blossom.example/") {
		t.Error("HasServer with scheme/trailing slash = false, want true")
	}
	if auth.HasServer("other.example") {
		t.Error("HasServer(other.example) = true, want false")
	}
	if !auth.HasHash(testHash) {
		t.Error("HasHash(testHash) = false, want true")
	}
	if auth.HasHash("00" + testHash[2:]) {
		t.Error("HasHash with wrong hash = true, want false")
	}

	if err := ValidateAuthorization(ev); err != nil {
		t.Errorf("ValidateAuthorization() error = %v", err)
	}
}

func TestAuthorizationNoServerTagsMeansAnyServer(t *testing.T) {
	ev := newSignedAuth(t, AuthorizationParams{
		Verb:       VerbGet,
		Content:    "Get blob",
		Expiration: time.Now().Add(time.Hour),
	})
	auth, err := ParseAuthorization(ev)
	if err != nil {
		t.Fatalf("ParseAuthorization() error = %v", err)
	}
	if !auth.HasServer("anything.example") {
		t.Error("HasServer with no server tags = false, want true (unscoped)")
	}
}

func TestParseAuthorizationErrors(t *testing.T) {
	tests := []struct {
		name    string
		kind    int
		tags    [][]string
		wantErr error
	}{
		{
			name:    "wrong kind",
			kind:    1,
			tags:    nil,
			wantErr: ErrWrongAuthKind,
		},
		{
			name:    "missing t tag",
			kind:    KindAuthorization,
			tags:    [][]string{{"expiration", "123"}},
			wantErr: ErrMissingVerbTag,
		},
		{
			name:    "empty t tag value",
			kind:    KindAuthorization,
			tags:    [][]string{{"t", ""}, {"expiration", "123"}},
			wantErr: ErrMissingVerbTag,
		},
		{
			name:    "missing expiration tag",
			kind:    KindAuthorization,
			tags:    [][]string{{"t", "upload"}},
			wantErr: ErrMissingExpiration,
		},
		{
			name:    "non-numeric expiration",
			kind:    KindAuthorization,
			tags:    [][]string{{"t", "upload"}, {"expiration", "not-a-number"}},
			wantErr: ErrMissingExpiration,
		},
		{
			name:    "zero expiration",
			kind:    KindAuthorization,
			tags:    [][]string{{"t", "upload"}, {"expiration", "0"}},
			wantErr: ErrMissingExpiration,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			_, err := ParseAuthorization(ev)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseAuthorizationIgnoresShortTags(t *testing.T) {
	ev := &nip01.Event{
		Kind: KindAuthorization,
		Tags: [][]string{{"t", VerbGet}, {"expiration", "9999999999"}, {"malformed"}},
	}
	auth, err := ParseAuthorization(ev)
	if err != nil {
		t.Fatalf("ParseAuthorization() error = %v", err)
	}
	if auth.Verb != VerbGet {
		t.Errorf("Verb = %q, want %q", auth.Verb, VerbGet)
	}
}

func TestValidateAuthorizationBadSignature(t *testing.T) {
	ev := NewAuthorization(AuthorizationParams{
		Verb:       VerbUpload,
		Expiration: time.Now().Add(time.Hour),
	})
	ev.PubKey = "0000000000000000000000000000000000000000000000000000000000000000"
	ev.ID = "0000000000000000000000000000000000000000000000000000000000000000"
	ev.Sig = "00"
	if err := ValidateAuthorization(ev); err == nil {
		t.Error("expected error for unsigned/invalid event")
	}
}

func TestEncodeDecodeAuthHeaderRoundTrip(t *testing.T) {
	ev := newSignedAuth(t, AuthorizationParams{
		Verb:       VerbList,
		Expiration: time.Now().Add(time.Hour),
	})

	header, err := EncodeAuthHeader(ev)
	if err != nil {
		t.Fatalf("EncodeAuthHeader() error = %v", err)
	}
	if header[:6] != "Nostr " {
		t.Fatalf("header = %q, want Nostr prefix", header)
	}

	decoded, err := DecodeAuthHeader(header)
	if err != nil {
		t.Fatalf("DecodeAuthHeader() error = %v", err)
	}
	if decoded.ID != ev.ID || decoded.Sig != ev.Sig {
		t.Errorf("decoded event = %+v, want ID/Sig matching %+v", decoded, ev)
	}
}

func TestDecodeAuthHeaderErrors(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "empty", header: ""},
		{name: "missing scheme", header: "Bearer abc"},
		{name: "bad base64", header: "Nostr !!!not-base64!!!"},
		{name: "valid base64 bad json", header: "Nostr " + "bm90LWpzb24"}, // "not-json" base64url
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeAuthHeader(tt.header); !errors.Is(err, ErrMissingAuthHeader) {
				t.Errorf("err = %v, want ErrMissingAuthHeader", err)
			}
		})
	}
}

func TestVerifyAuthorizationSuccess(t *testing.T) {
	now := time.Now()
	ev := newSignedAuth(t, AuthorizationParams{
		Verb:       VerbUpload,
		Content:    "Upload blob",
		Expiration: now.Add(time.Hour),
		Servers:    []string{"blossom.example"},
		Hashes:     []string{testHash},
	})
	header, err := EncodeAuthHeader(ev)
	if err != nil {
		t.Fatalf("EncodeAuthHeader() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodPut, "https://blossom.example/upload", nil)
	req.Header.Set("Authorization", header)

	auth, err := VerifyAuthorization(req, VerifyParams{
		Verb:        VerbUpload,
		ServerHost:  "blossom.example",
		Hash:        testHash,
		RequireHash: true,
		Now:         now,
	})
	if err != nil {
		t.Fatalf("VerifyAuthorization() error = %v", err)
	}
	if auth.Verb != VerbUpload {
		t.Errorf("Verb = %q, want %q", auth.Verb, VerbUpload)
	}
}

func TestVerifyAuthorizationErrors(t *testing.T) {
	now := time.Now()

	build := func(p AuthorizationParams) string {
		ev := NewAuthorization(p)
		ev = signed(t, ev)
		header, err := EncodeAuthHeader(ev)
		if err != nil {
			t.Fatalf("EncodeAuthHeader() error = %v", err)
		}
		return header
	}

	tests := []struct {
		name    string
		header  string
		params  VerifyParams
		wantErr error
	}{
		{
			name:    "missing header",
			header:  "",
			params:  VerifyParams{Verb: VerbGet, Now: now},
			wantErr: ErrMissingAuthHeader,
		},
		{
			name: "verb mismatch",
			header: build(AuthorizationParams{
				Verb: VerbGet, Expiration: now.Add(time.Hour),
			}),
			params:  VerifyParams{Verb: VerbUpload, Now: now},
			wantErr: ErrVerbMismatch,
		},
		{
			name: "expired",
			header: build(AuthorizationParams{
				Verb: VerbGet, Expiration: now.Add(-time.Minute),
			}),
			params:  VerifyParams{Verb: VerbGet, Now: now},
			wantErr: ErrAuthExpired,
		},
		{
			name: "not yet valid",
			header: func() string {
				ev := NewAuthorization(AuthorizationParams{Verb: VerbGet, Expiration: now.Add(time.Hour)})
				ev.CreatedAt = uint64(now.Add(time.Hour).Unix())
				return build2(t, ev)
			}(),
			params:  VerifyParams{Verb: VerbGet, Now: now},
			wantErr: ErrAuthNotYetValid,
		},
		{
			name: "server mismatch",
			header: build(AuthorizationParams{
				Verb: VerbGet, Expiration: now.Add(time.Hour), Servers: []string{"other.example"},
			}),
			params:  VerifyParams{Verb: VerbGet, ServerHost: "blossom.example", Now: now},
			wantErr: ErrServerMismatch,
		},
		{
			name: "hash not authorized, required",
			header: build(AuthorizationParams{
				Verb: VerbDelete, Expiration: now.Add(time.Hour),
			}),
			params:  VerifyParams{Verb: VerbDelete, Hash: testHash, RequireHash: true, Now: now},
			wantErr: ErrHashNotAuthorized,
		},
		{
			name: "hash mismatch when scoped",
			header: build(AuthorizationParams{
				Verb: VerbDelete, Expiration: now.Add(time.Hour), Hashes: []string{"b" + testHash[1:]},
			}),
			params:  VerifyParams{Verb: VerbDelete, Hash: testHash, Now: now},
			wantErr: ErrHashNotAuthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "https://blossom.example/x", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			_, err := VerifyAuthorization(req, tt.params)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyAuthorizationBadSignature(t *testing.T) {
	ev := NewAuthorization(AuthorizationParams{Verb: VerbGet, Expiration: time.Now().Add(time.Hour)})
	ev.PubKey = "0000000000000000000000000000000000000000000000000000000000000000"
	ev.ID = "0000000000000000000000000000000000000000000000000000000000000000"
	ev.Sig = "00"

	header, err := EncodeAuthHeader(ev)
	if err != nil {
		t.Fatalf("EncodeAuthHeader() error = %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://blossom.example/x", nil)
	req.Header.Set("Authorization", header)

	if _, err := VerifyAuthorization(req, VerifyParams{Verb: VerbGet}); !errors.Is(err, ErrAuthInvalidSignature) {
		t.Errorf("err = %v, want ErrAuthInvalidSignature", err)
	}
}

func TestVerifyAuthorizationStructurallyInvalid(t *testing.T) {
	// Signed, so it clears event.Verify(), but missing the expiration tag
	// ParseAuthorization requires — exercises VerifyAuthorization's own
	// ParseAuthorization error path, distinct from Verify()'s.
	ev := signed(t, &nip01.Event{Kind: KindAuthorization, Tags: [][]string{{"t", VerbGet}}})

	header, err := EncodeAuthHeader(ev)
	if err != nil {
		t.Fatalf("EncodeAuthHeader() error = %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://blossom.example/x", nil)
	req.Header.Set("Authorization", header)

	if _, err := VerifyAuthorization(req, VerifyParams{Verb: VerbGet}); !errors.Is(err, ErrMissingExpiration) {
		t.Errorf("err = %v, want ErrMissingExpiration", err)
	}
}

func TestVerifyAuthorizationDefaultsNowWhenZero(t *testing.T) {
	ev := newSignedAuth(t, AuthorizationParams{Verb: VerbGet, Expiration: time.Now().Add(time.Hour)})
	header, err := EncodeAuthHeader(ev)
	if err != nil {
		t.Fatalf("EncodeAuthHeader() error = %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://blossom.example/x", nil)
	req.Header.Set("Authorization", header)

	if _, err := VerifyAuthorization(req, VerifyParams{Verb: VerbGet}); err != nil {
		t.Errorf("VerifyAuthorization() error = %v, want nil with zero-value Now", err)
	}
}

func TestVerifyAuthorizationHashUnscopedTokenAllowed(t *testing.T) {
	now := time.Now()
	ev := signed(t, NewAuthorization(AuthorizationParams{Verb: VerbGet, Expiration: now.Add(time.Hour)}))
	header, err := EncodeAuthHeader(ev)
	if err != nil {
		t.Fatalf("EncodeAuthHeader() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://blossom.example/x", nil)
	req.Header.Set("Authorization", header)

	// Hash set but not required, and token carries no x tags at all: this
	// must be treated as "unscoped", not rejected.
	if _, err := VerifyAuthorization(req, VerifyParams{Verb: VerbGet, Hash: testHash, Now: now}); err != nil {
		t.Errorf("VerifyAuthorization() error = %v, want nil for unscoped token", err)
	}
}

// build2 signs ev (whose CreatedAt has already been overridden) and encodes
// it into an Authorization header, bypassing NewAuthorization's own
// CreatedAt assignment.
func build2(t *testing.T, ev *nip01.Event) string {
	t.Helper()
	ev = signed(t, ev)
	header, err := EncodeAuthHeader(ev)
	if err != nil {
		t.Fatalf("EncodeAuthHeader() error = %v", err)
	}
	return header
}
