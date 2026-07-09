// Package nip65 implements NIP-65: Relay List Metadata, letting a user
// publish which relays they read from and write to (the "outbox model"),
// so other clients know where to find their events and send them replies.
package nip65

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nip01"
)

const (
	KindRelayListMetadata = 10002
)

// Failure modes for ParseRelayList/ValidateRelayList, for callers that need
// to distinguish them (e.g. via errors.Is) rather than match on message
// text.
var (
	ErrWrongKind          = errors.New("nip65: wrong kind")
	ErrInvalidRelayURL    = errors.New("nip65: invalid relay url")
	ErrInvalidRelayScheme = errors.New("nip65: relay url must use ws or wss scheme")
	ErrInvalidSignature   = errors.New("nip65: invalid signature")
)

// RelayEntry is one relay in a NIP-65 relay list, from an
// ["r", <url>] or ["r", <url>, "read"|"write"] tag. Read and Write are
// both true when the tag carries no marker (per spec, no marker means the
// relay is used for both).
type RelayEntry struct {
	URL   string
	Read  bool
	Write bool
}

// RelayList is a parsed kind:10002 relay list event.
type RelayList struct {
	*nip01.Event
	Relays []RelayEntry
}

// NewRelayList builds an unsigned kind:10002 relay list event. Caller must
// sign it.
func NewRelayList(pubkey string, relays []RelayEntry) *nip01.Event {
	tags := make([][]string, 0, len(relays))
	for _, r := range relays {
		tag := []string{"r", r.URL}
		switch {
		case r.Read && !r.Write:
			tag = append(tag, "read")
		case r.Write && !r.Read:
			tag = append(tag, "write")
		}
		tags = append(tags, tag)
	}
	return nip01.NewUnsignedEvent(KindRelayListMetadata, pubkey, "", tags...)
}

// ParseRelayList parses and structurally validates a kind:10002 relay list
// event.
func ParseRelayList(event *nip01.Event) (*RelayList, error) {
	if event.Kind != KindRelayListMetadata {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindRelayListMetadata)
	}

	rl := &RelayList{Event: event}
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != "r" {
			continue
		}

		u, err := url.ParseRequestURI(tag[1])
		if err != nil {
			return nil, fmt.Errorf("%w %q: %w", ErrInvalidRelayURL, tag[1], err)
		}
		if u.Scheme != "wss" && u.Scheme != "ws" {
			return nil, fmt.Errorf("%w: %q has scheme %q", ErrInvalidRelayScheme, tag[1], u.Scheme)
		}

		entry := RelayEntry{URL: tag[1]}
		if len(tag) > 2 {
			switch tag[2] {
			case "read":
				entry.Read = true
			case "write":
				entry.Write = true
			default:
				entry.Read, entry.Write = true, true
			}
		} else {
			entry.Read, entry.Write = true, true
		}
		rl.Relays = append(rl.Relays, entry)
	}

	return rl, nil
}

// ValidateRelayList checks the signature and structure of a relay list
// event.
func ValidateRelayList(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseRelayList(event)
	return err
}
