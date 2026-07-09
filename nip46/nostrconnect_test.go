package nip46

import (
	"net/url"
	"testing"
)

const testClientPubkey = "abcdef0123456789012345678901234567890123456789012345678901234a"

func buildNostrconnectURI(t *testing.T, overrides map[string]string) string {
	t.Helper()

	q := url.Values{}
	q.Set("relay", "wss://relay.example.com")
	q.Set("secret", "sekret")
	q.Set("metadata", `{"name":"MyApp","url":"https://myapp.example","description":"desc"}`)

	for k, v := range overrides {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}

	u := url.URL{
		Scheme:   "nostrconnect",
		Host:     testClientPubkey,
		RawQuery: q.Encode(),
	}
	return u.String()
}

func TestParseNostrconnect_Success(t *testing.T) {
	uri := buildNostrconnectURI(t, nil)

	schema, err := ParseNostrconnect(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schema.ClientPublickey != testClientPubkey {
		t.Errorf("expected pubkey %q, got %q", testClientPubkey, schema.ClientPublickey)
	}
	if schema.Secret != "sekret" {
		t.Errorf("expected secret %q, got %q", "sekret", schema.Secret)
	}
	if schema.Relay.String() != "wss://relay.example.com" {
		t.Errorf("expected relay URL, got %q", schema.Relay.String())
	}
	if schema.Metadata.Name != "MyApp" {
		t.Errorf("expected metadata name %q, got %q", "MyApp", schema.Metadata.Name)
	}
}

func TestParseNostrconnect_InvalidURI(t *testing.T) {
	if _, err := ParseNostrconnect("://not-a-uri"); err == nil {
		t.Error("expected error for malformed URI")
	}
}

func TestParseNostrconnect_WrongScheme(t *testing.T) {
	if _, err := ParseNostrconnect("https://" + testClientPubkey + "?relay=wss://x&secret=s&metadata=%7B%7D"); err == nil {
		t.Error("expected error for wrong scheme")
	}
}

func TestParseNostrconnect_MissingSecret(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"secret": ""})
	if _, err := ParseNostrconnect(uri); err == nil {
		t.Error("expected error for missing secret query param")
	}
}

func TestParseNostrconnect_MissingRelay(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"relay": ""})
	if _, err := ParseNostrconnect(uri); err == nil {
		t.Error("expected error for missing relay query param")
	}
}

func TestParseNostrconnect_InvalidRelay(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"relay": "://bad"})
	if _, err := ParseNostrconnect(uri); err == nil {
		t.Error("expected error for malformed relay URL")
	}
}

func TestParseNostrconnect_MissingMetadata(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"metadata": ""})
	if _, err := ParseNostrconnect(uri); err == nil {
		t.Error("expected error for missing metadata query param")
	}
}

func TestParseNostrconnect_InvalidMetadata(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"metadata": "not-json"})
	if _, err := ParseNostrconnect(uri); err == nil {
		t.Error("expected error for malformed metadata JSON")
	}
}

func TestParseNostrconnect_InvalidClientPubkey(t *testing.T) {
	q := url.Values{}
	q.Set("relay", "wss://relay.example.com")
	q.Set("secret", "sekret")
	q.Set("metadata", `{}`)
	u := url.URL{Scheme: "nostrconnect", Host: "not-hex-!!", RawQuery: q.Encode()}

	if _, err := ParseNostrconnect(u.String()); err == nil {
		t.Error("expected error for non-hex client pubkey")
	}
}
