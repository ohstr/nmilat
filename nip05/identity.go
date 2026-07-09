// Package nip05 implements NIP-05: Mapping Nostr Keys to DNS-based
// Internet Identifiers, letting a pubkey advertise a human-readable
// "name@domain" identifier that resolves via a domain's
// /.well-known/nostr.json document.
package nip05

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	Kind = 35_555
)

// IdentityResponse is the /.well-known/nostr.json document shape (NIP-05).
type IdentityResponse struct {
	Names  map[string]string   `json:"names"`
	Relays map[string][]string `json:"relays,omitempty"`
}

type Identity struct {
	name, pubkey, domain string
	relays               []string
}

func NewIdentity(domain, name, pubkey string, relays []string) *Identity {
	return &Identity{
		name:   name,
		pubkey: pubkey,
		domain: domain,
		relays: relays,
	}
}

func BuildNIP05Event(relayPubKey string, iden *Identity) *nip01.Event {
	return &nip01.Event{
		Kind:      Kind,
		PubKey:    relayPubKey,
		CreatedAt: uint64(time.Now().Unix()),
		Tags: [][]string{
			{"d", iden.name},
			append([]string{"p", iden.pubkey}, iden.relays...),
			{"domain", iden.domain},
		},
	}
}

func parseIdentityTags(tags [][]string) (*Identity, error) {
	iden := &Identity{}
	var fields int
	for _, tag := range tags {
		if len(tag) == 0 {
			continue
		}

		switch strings.ToLower(tag[0]) {
		case "d":
			if err := iden.parseNameTag(tag); err != nil {
				return nil, err
			}
		case "p":
			if err := iden.parsePubkeyTag(tag); err != nil {
				return nil, err
			}
		case "domain":
			if err := iden.parseDomainTag(tag); err != nil {
				return nil, err
			}
		}

		if fields++; fields == 3 {
			return iden, nil
		}
	}

	return nil, errors.New("invalid tags")
}

func (i *Identity) parseDomainTag(tag []string) error {
	if len(tag) != 2 {
		return fmt.Errorf("domain tag: bad size %d", len(tag))
	}
	if !IsValidDomain(tag[1]) {
		return fmt.Errorf("invalid domain: %s", tag[1])
	}

	i.domain = tag[1]
	return nil
}

func (i *Identity) parseNameTag(tag []string) error {
	if len(tag) != 2 {
		return fmt.Errorf("name tag: bad size %d", len(tag))
	}

	if err := ValidateName(tag[1]); err != nil {
		return err
	}

	i.name = tag[1]
	return nil
}

func (i *Identity) parsePubkeyTag(tag []string) error {
	if len(tag) < 2 {
		return errors.New("pubkey tag contains fewer values than expected")
	}

	if err := utils.Validate32Key(tag[1]); err != nil {
		return err
	}

	for v := 2; v < len(tag); v++ {
		if err := ValidateWebSocketURL(tag[v]); err != nil {
			continue
		}
		i.relays = append(i.relays, tag[v])
	}

	i.pubkey = tag[1]
	return nil
}

func ValidateWebSocketURL(u string) error {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return err
	}

	if !((parsedURL.Scheme == "ws" || parsedURL.Scheme == "wss") && parsedURL.Host != "") {
		return errors.New("invalid url")
	}

	return nil
}

func ValidateName(name string) error {
	validNamePattern := regexp.MustCompile(`^[A-Za-z0-9\-_.]+$`)
	if !validNamePattern.MatchString(name) {
		return errors.New("name must contain only a-z, 0-9, -, _, or .")
	}
	return nil
}

func IsValidDomain(domain string) bool {
	var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

func appendToMap(relays map[string][]string, key string, values []string) {
	if existingValues, found := relays[key]; found {
		relays[key] = append(existingValues, values...)
	} else {
		relays[key] = values
	}
}

// BuildIdentityResponse aggregates kind:35555 identity events (as built by
// BuildNIP05Event) into the names/relays JSON shape a NIP-05 identity
// endpoint serves. Events that don't parse as valid identity tags are
// skipped. This is pure protocol logic — how those events get fetched (a
// live relay query, a static export, a different relay's index entirely)
// is the caller's concern, not nip05's.
func BuildIdentityResponse(events []*nip01.Event) *IdentityResponse {
	res := &IdentityResponse{
		Names:  make(map[string]string),
		Relays: make(map[string][]string),
	}

	for _, event := range events {
		identity, err := parseIdentityTags(event.Tags)
		if err != nil {
			continue
		}
		res.Names[identity.name] = identity.pubkey
		appendToMap(res.Relays, identity.name, identity.relays)
	}

	return res
}
