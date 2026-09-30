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

// Metadata is optional in NIP-46 -- no spec-compliant client sends a
// "metadata" param at all, so requiring one rejected every real URI.
func TestParseNostrconnect_MissingMetadata(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"metadata": ""})

	schema, err := ParseNostrconnect(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schema.Metadata == nil {
		t.Fatal("Metadata is nil; want a zero-valued one so callers need no nil check")
	}
	if schema.Metadata.Name != "" {
		t.Errorf("Name = %q, want empty", schema.Metadata.Name)
	}
}

// A display hint is not worth refusing a connection over.
func TestParseNostrconnect_InvalidMetadata(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"metadata": "not-json"})

	schema, err := ParseNostrconnect(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schema.Metadata.Name != "" {
		t.Errorf("Name = %q, want empty", schema.Metadata.Name)
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

// realWorldURI is a URI produced by a shipping Nostr client, kept verbatim:
// four relays, no metadata param, and a secret that is not hex. Parsing it
// is the whole point of this file -- the previous parser rejected it with
// "metadata query not found".
const realWorldURI = "nostrconnect://6109a3efcd74054f2335e3c1626c32f2d50d8b4241137b697e85d7d2e68e364a" +
	"?relay=wss%3A%2F%2Frelay.bullishbounty.com" +
	"&relay=wss%3A%2F%2Frelay.damus.io" +
	"&relay=wss%3A%2F%2Frelay.primal.net" +
	"&relay=wss%3A%2F%2Fbucket.coracle.social" +
	"&secret=sec-232306d55d240b50e0201b449980c58f"

func TestParseNostrconnect_RealWorldURI(t *testing.T) {
	schema, err := ParseNostrconnect(realWorldURI)
	if err != nil {
		t.Fatalf("ParseNostrconnect() error = %v", err)
	}

	want := []string{
		"wss://relay.bullishbounty.com",
		"wss://relay.damus.io",
		"wss://relay.primal.net",
		"wss://bucket.coracle.social",
	}
	got := relayStrings(schema)
	if len(got) != len(want) {
		t.Fatalf("got %d relays (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("relay %d = %q, want %q (URI order must be preserved)", i, got[i], want[i])
		}
	}
	if schema.Secret != "sec-232306d55d240b50e0201b449980c58f" {
		t.Errorf("Secret = %q", schema.Secret)
	}
	if schema.Metadata == nil {
		t.Error("Metadata is nil; want a zero-valued one")
	}
}

// The example printed in NIP-46 itself: two relays, perms and a name, with
// the params in an order no builder would pick.
func TestParseNostrconnect_SpecExample(t *testing.T) {
	const uri = "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5" +
		"?relay=wss%3A%2F%2Frelay1.example.com" +
		"&perms=nip44_encrypt%2Cnip44_decrypt%2Csign_event%3A13%2Csign_event%3A14%2Csign_event%3A1059" +
		"&name=My+Client" +
		"&secret=0s8j2djs" +
		"&relay=wss%3A%2F%2Frelay2.example2.com"

	schema, err := ParseNostrconnect(uri)
	if err != nil {
		t.Fatalf("ParseNostrconnect() error = %v", err)
	}
	if got := relayStrings(schema); len(got) != 2 {
		t.Errorf("relays = %v, want 2", got)
	}
	if schema.Metadata.Name != "My Client" {
		t.Errorf("Name = %q, want %q", schema.Metadata.Name, "My Client")
	}
	if want := "nip44_encrypt,nip44_decrypt,sign_event:13,sign_event:14,sign_event:1059"; schema.Perms != want {
		t.Errorf("Perms = %q, want %q", schema.Perms, want)
	}
}

func TestParseNostrconnect_DiscreteMetadataParams(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{
		"metadata": "",
		"name":     "Discrete App",
		"url":      "https://discrete.example",
		"image":    "https://discrete.example/icon.png",
	})

	schema, err := ParseNostrconnect(uri)
	if err != nil {
		t.Fatalf("ParseNostrconnect() error = %v", err)
	}
	if schema.Metadata.Name != "Discrete App" {
		t.Errorf("Name = %q", schema.Metadata.Name)
	}
	if schema.Metadata.Url != "https://discrete.example" {
		t.Errorf("Url = %q", schema.Metadata.Url)
	}
	if schema.Metadata.Image != "https://discrete.example/icon.png" {
		t.Errorf("Image = %q", schema.Metadata.Image)
	}
}

// The legacy blob fills only the gaps: a spec param naming the same field
// always wins.
func TestParseNostrconnect_DiscreteParamsOutrankLegacyBlob(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{
		"metadata": `{"name":"Legacy","url":"https://legacy.example","description":"from the blob"}`,
		"name":     "Discrete",
	})

	schema, err := ParseNostrconnect(uri)
	if err != nil {
		t.Fatalf("ParseNostrconnect() error = %v", err)
	}
	if schema.Metadata.Name != "Discrete" {
		t.Errorf("Name = %q, want the discrete param to win", schema.Metadata.Name)
	}
	if schema.Metadata.Url != "https://legacy.example" {
		t.Errorf("Url = %q, want the blob to fill the gap", schema.Metadata.Url)
	}
	if schema.Metadata.Description != "from the blob" {
		t.Errorf("Description = %q", schema.Metadata.Description)
	}
}

func TestParseNostrconnect_SchemelessRelayHost(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"relay": "relay.example.com"})

	schema, err := ParseNostrconnect(uri)
	if err != nil {
		t.Fatalf("ParseNostrconnect() error = %v", err)
	}
	if got := schema.Relays[0].String(); got != "wss://relay.example.com" {
		t.Errorf("relay = %q, want wss:// to be assumed", got)
	}
}

func TestParseNostrconnect_NonWebsocketRelayRejected(t *testing.T) {
	uri := buildNostrconnectURI(t, map[string]string{"relay": "https://relay.example.com"})
	if _, err := ParseNostrconnect(uri); err == nil {
		t.Error("expected error: https is not a relay transport")
	}
}

// One bad relay must not cost the client the good ones.
func TestParseNostrconnect_DropsUnusableRelaysKeepsRest(t *testing.T) {
	uri := "nostrconnect://" + testClientPubkey +
		"?relay=" + url.QueryEscape("://bad") +
		"&relay=" + url.QueryEscape("wss://good.one") +
		"&relay=" + url.QueryEscape("wss://good.two") +
		"&secret=sekret"

	schema, err := ParseNostrconnect(uri)
	if err != nil {
		t.Fatalf("ParseNostrconnect() error = %v", err)
	}
	want := []string{"wss://good.one", "wss://good.two"}
	got := relayStrings(schema)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("relays = %v, want %v", got, want)
	}
}

// Relay is retained only as an alias for the first entry.
func TestParseNostrconnect_RelayAliasIsFirstRelay(t *testing.T) {
	schema, err := ParseNostrconnect(realWorldURI)
	if err != nil {
		t.Fatal(err)
	}
	if schema.Relay != schema.Relays[0] {
		t.Errorf("Relay = %v, want it to alias Relays[0] = %v", schema.Relay, schema.Relays[0])
	}
}

func TestParseNostrconnect_PermsAbsent(t *testing.T) {
	schema, err := ParseNostrconnect(realWorldURI)
	if err != nil {
		t.Fatal(err)
	}
	if schema.Perms != "" {
		t.Errorf("Perms = %q, want empty", schema.Perms)
	}
}

func relayStrings(schema *NostrconnectSchema) []string {
	out := make([]string, 0, len(schema.Relays))
	for _, r := range schema.Relays {
		out = append(out, r.String())
	}
	return out
}
