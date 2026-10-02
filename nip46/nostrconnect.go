package nip46

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ohstr/nmilat/nip19"
)

const (
	nostrconnectScheme = "nostrconnect"
	paramRelay         = "relay"
	paramSecret        = "secret"
	paramPerms         = "perms"
	paramName          = "name"
	paramURL           = "url"
	paramImage         = "image"

	// paramMetadata is not a NIP-46 parameter. Some older signers (this
	// package's own callers included) packed name/url/description into one
	// JSON blob under this key before the spec settled on the discrete
	// params above. Still read, never required, and always outranked by a
	// discrete param that carries the same field.
	paramMetadata = "metadata"
)

// ParseNostrconnect parses a nostrconnect://<client-pubkey>?relay=...&secret=...
// URI — the client-initiated counterpart to BuildConnect, used when the
// client (rather than the signer) generates the connection secret.
//
// Only `relay` (repeatable) and `secret` are required, per NIP-46. Every
// other parameter is a display hint or a request, never a precondition: a
// URI carrying nothing but a pubkey, one relay and a secret is valid and
// must parse.
func ParseNostrconnect(nostrconnect string) (*NostrconnectSchema, error) {

	// schema
	nostrconnectURI, err := url.ParseRequestURI(nostrconnect)
	if err != nil {
		return nil, fmt.Errorf("failed parsing nostrconnect string: %w", err)
	}
	if strings.ToLower(nostrconnectURI.Scheme) != nostrconnectScheme {
		return nil, errors.New("invalid protocol")
	}

	// queries
	queries := nostrconnectURI.Query()

	// secret param
	if !queries.Has(paramSecret) {
		return nil, errors.New("secret query not found")
	}
	secret := queries.Get(paramSecret)

	// relay param — repeatable, and a client that lists several means all
	// of them: the signer reaches it on whichever ones it can, so one dead
	// relay in the list is not a dead connection. Individually malformed
	// entries are dropped rather than failing the URI; only an empty
	// result is an error.
	if !queries.Has(paramRelay) {
		return nil, errors.New("relay query not found")
	}
	var relays []*url.URL
	for _, raw := range queries[paramRelay] {
		relayURI, err := parseRelayParam(raw)
		if err != nil {
			continue
		}
		relays = append(relays, relayURI)
	}
	if len(relays) == 0 {
		return nil, errors.New("no usable relay in the relay query")
	}

	// host = client public key

	err = nip19.CheckPublicKey(nostrconnectURI.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to check public key: %w", err)
	}

	return &NostrconnectSchema{
		ClientPublickey: nostrconnectURI.Host,
		Metadata:        parseNostrconnectMetadata(queries),
		Relay:           relays[0],
		Relays:          relays,
		Secret:          secret,
		Perms:           queries.Get(paramPerms),
	}, nil
}

// parseRelayParam turns one relay query value into a URL. A value with no
// scheme is read as wss://, the convention every Nostr relay list follows;
// anything that isn't websocket after that is rejected, since a signer
// cannot speak NIP-46 over it.
func parseRelayParam(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("empty relay")
	}
	if !strings.Contains(raw, "://") {
		raw = "wss://" + raw
	}

	relayURI, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, fmt.Errorf("failed parsing relay query: %w", err)
	}
	switch strings.ToLower(relayURI.Scheme) {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("unsupported relay scheme %q", relayURI.Scheme)
	}
	if relayURI.Host == "" {
		return nil, errors.New("relay has no host")
	}
	return relayURI, nil
}

// parseNostrconnectMetadata reads the client's self-reported identity. The
// result is never nil — a URI carrying no app information at all yields a
// zero-valued Metadata, so a caller can read .Name without a nil check.
//
// Metadata is client-supplied and unauthenticated. Per NIP-46 it is a
// display hint only and MUST NOT feed an authorization decision.
func parseNostrconnectMetadata(queries url.Values) *Metadata {
	metadata := &Metadata{
		Name:  queries.Get(paramName),
		Url:   queries.Get(paramURL),
		Image: queries.Get(paramImage),
	}

	// Legacy blob: fills only what the discrete params left empty. A
	// malformed one is ignored rather than fatal — losing a display name
	// is not worth refusing a connection over.
	if blob := queries.Get(paramMetadata); blob != "" {
		var legacy Metadata
		if err := json.Unmarshal([]byte(blob), &legacy); err == nil {
			if metadata.Name == "" {
				metadata.Name = legacy.Name
			}
			if metadata.Url == "" {
				metadata.Url = legacy.Url
			}
			if metadata.Image == "" {
				metadata.Image = legacy.Image
			}
			metadata.Description = legacy.Description
		}
	}

	return metadata
}
