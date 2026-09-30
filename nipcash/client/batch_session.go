package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// ErrNoAnnouncement means no kind-11190 announcement could be found for a hub, so
// its private transport cannot be used.
//
// A distinct error because it is the expected answer for a hub that simply does not
// offer the transport — it is OPTIONAL in both directions — rather than a fault. A
// caller seeing this should fall back to the standard transport, not retry.
var ErrNoAnnouncement = errors.New("nipcash/client: hub publishes no private-transport announcement")

// BatchSession is what a client needs to talk to one hub's private transport: its
// announced inbox, the limits it will actually accept, and where to reach it.
//
// Held rather than re-fetched per call, because every batch needs it and a relay
// round trip per batch would be paid by a CLI doing several operations in a row.
// Refreshed on demand instead — see Refresh.
type BatchSession struct {
	// hubXOnly is the hub's IDENTITY key, which item proofs bind to and which the
	// announcement's signature is checked against. Distinct from the inbox key
	// below, which is what envelopes are encrypted to. Conflating the two is the
	// exact mistake the announcement exists to prevent: a hub whose identity key
	// lives in a signing device cannot decrypt with it.
	hubXOnly string
	// relays to try, in order. Announcement relays if it named any, otherwise
	// whatever the caller supplied from the bill's own token hints.
	fallbackRelays []string

	mu           sync.Mutex
	announcement *transport.Announcement
	relays       []string
}

// NewBatchSession fetches and verifies a hub's announcement.
//
// hubXOnly is the identity the caller ALREADY trusts for this hub — typically
// recovered from a bill's mint signature, or configured. It is required rather than
// discovered: an announcement is only meaningful if its signature is checked against
// an identity known in advance, otherwise an attacker publishing their own
// announcement would simply be believed, and envelopes would be encrypted to them.
//
// relays are where to look. A bill's own token hints are the normal source; if the
// announcement names its own relays those take over afterwards, since the token's
// hints were fixed when the bill was minted and a hub may have moved since.
func (c *Client) NewBatchSession(ctx context.Context, hubXOnly string, relays []string) (*BatchSession, error) {
	if len(relays) == 0 {
		return nil, fmt.Errorf("nipcash/client: no relays to look for %s's announcement on", hubXOnly)
	}
	// Normalized because the documented source of this value — the identity
	// recovered from a bill's mint signature — produces a 33-byte COMPRESSED
	// pubkey, while a Nostr event's author is always the 32-byte x-only form.
	// Without this the announcement is published under one spelling and looked up
	// under another, and the lookup returns nothing: indistinguishable from a hub
	// that simply does not offer the transport.
	xonly, err := transport.NormalizeNodeIdentity(hubXOnly)
	if err != nil {
		return nil, err
	}
	s := &BatchSession{hubXOnly: xonly, fallbackRelays: relays, relays: relays}
	if err := s.Refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Refresh re-fetches the announcement.
//
// Called once at construction, and again when a hub rejects an envelope in a way that
// implies the cached policy is stale — over-limit, or addressed to an inbox the hub no
// longer reads. That is the whole refresh strategy: no TTL, because any interval would
// be a number invented without measurement, and polling costs a round trip to learn
// nothing in the overwhelming majority of cases. A rejection is the only evidence that
// the cache is actually wrong, so it is the only thing that triggers a refetch.
func (s *BatchSession) Refresh(ctx context.Context) error {
	// Addressed by author, which is why no "d" tag is needed: a replaceable kind
	// plus one author returns exactly one event.
	filter := nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{
		Kinds:   []int{transport.KindHubAnnouncement},
		Authors: []string{s.hubXOnly},
		Limit:   1,
	})

	s.mu.Lock()
	candidates := append([]string(nil), s.relays...)
	s.mu.Unlock()
	// Always retry the caller's own hints too. If a previous announcement moved the
	// hub to relays that have since gone away, the hints are the only way back.
	candidates = appendMissing(candidates, s.fallbackRelays)

	var lastErr error
	var newest *transport.Announcement
	for _, raw := range candidates {
		relayURL, err := url.Parse(raw)
		if err != nil {
			lastErr = fmt.Errorf("relay %q: %w", raw, err)
			continue
		}
		events, err := relayclient.ReadEventsFromRelay(ctx, relayURL, filter)
		if err != nil {
			lastErr = fmt.Errorf("relay %q: %w", raw, err)
			continue
		}
		for _, ev := range events {
			// ParseAnnouncement verifies the signature against the expected identity
			// and refuses one signed by anyone else. Doing it here rather than
			// trusting the relay is the point: a relay can serve any bytes it likes.
			announcement, err := transport.ParseAnnouncement(ev, s.hubXOnly)
			if err != nil {
				lastErr = fmt.Errorf("relay %q: %w", raw, err)
				continue
			}
			// Keep the NEWEST candidate rather than adopting the first that parses,
			// and never move backwards from one already held.
			//
			// Every announcement the hub has ever published stays individually valid
			// forever — kind 11190 is replaceable at the relay, but an old event is
			// still genuinely signed by the node identity. So a relay serving a stale
			// one forges nothing; it CHOOSES which of the hub's own past policies the
			// client obeys, and one cooperating relay in the candidate list is enough
			// because the bill's token relay hints are re-appended on every Refresh.
			//
			// Measured consequence with no further precondition: replaying the hub's
			// own pre-change announcement reinstates the 4 KiB padding bucket, which
			// takes 1-8 items from three distinguishable wire sizes back to four —
			// exactly the leak that change was made to close. And once inbox rotation
			// ships, a retired inbox key is the remedy for a leaked one, so being able
			// to pin a client to the old inbox would defeat rotation entirely.
			if newest == nil || announcement.CreatedAt > newest.CreatedAt {
				newest = announcement
			}
		}
	}

	if newest != nil {
		s.mu.Lock()
		if s.announcement == nil || newest.CreatedAt >= s.announcement.CreatedAt {
			s.announcement = newest
			if len(newest.Relays) > 0 {
				s.relays = append([]string(nil), newest.Relays...)
			}
		}
		s.mu.Unlock()
		return nil
	}

	if lastErr != nil {
		return fmt.Errorf("%w: %v", ErrNoAnnouncement, lastErr)
	}
	return ErrNoAnnouncement
}

// Limits are the envelope limits this hub announced.
//
// A client MUST size envelopes against these rather than against DefaultLimits: a hub
// that lowered its limits would reject every envelope built to a default, and a hub
// that raised them would see batches split more than necessary.
func (s *BatchSession) Limits() transport.Limits {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.announcement == nil {
		return transport.Limits{}
	}
	return s.announcement.Limits.Limits()
}

// Inbox is the key envelopes are encrypted and p-tagged to. NOT the hub identity.
func (s *BatchSession) Inbox() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.announcement == nil {
		return ""
	}
	return s.announcement.Inbox
}

// HubIdentity is the key item proofs bind to, and the one the announcement was
// verified against.
func (s *BatchSession) HubIdentity() string { return s.hubXOnly }

// Relays returns where to publish, announcement relays preferred over the caller's
// original hints.
func (s *BatchSession) Relays() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.relays...)
}

func appendMissing(dst, extra []string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[v] = struct{}{}
	}
	for _, v := range extra {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		dst = append(dst, v)
	}
	return dst
}
