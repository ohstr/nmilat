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
	paramMetadata      = "metadata"
	paramSecret        = "secret"
)

// ParseNostrconnect parses a nostrconnect://<client-pubkey>?relay=...&secret=...&metadata=...
// URI — the client-initiated counterpart to BuildConnect, used when the
// client (rather than the signer) generates the connection secret.
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

	// relay param
	if !queries.Has(paramRelay) {
		return nil, errors.New("relay query not found")
	}
	relay := queries.Get(paramRelay)
	relayURI, err := url.ParseRequestURI(relay)
	if err != nil {
		return nil, fmt.Errorf("failed parsing relay query: %w", err)
	}

	// metadata param
	if !queries.Has(paramMetadata) {
		return nil, errors.New("metadata query not found")
	}
	metadata := &Metadata{}
	err = json.Unmarshal([]byte(queries.Get(paramMetadata)), metadata)
	if err != nil {
		return nil, fmt.Errorf("failed deserializing metadata query: %w", err)
	}

	// host = client public key

	err = nip19.CheckPublicKey(nostrconnectURI.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to check public key: %w", err)
	}

	return &NostrconnectSchema{
		ClientPublickey: nostrconnectURI.Host,
		Metadata:        metadata,
		Relay:           relayURI,
		Secret:          secret,
	}, nil
}
