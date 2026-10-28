package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
)

// WithRecipientOnlyKinds sets SessionConfig.RecipientOnlyKinds: an event of
// one of kinds is served only to a connection that has authenticated
// (NIP-42) as a pubkey named in one of the event's "p" tags. Off by default.
// The usual use is WithRecipientOnlyKinds(1059), so a gift wrap reaches only
// its recipient (NIP-CP §Kind 9525 asks this of the relays holding a user's
// wraps). An embedder reading its own config file maps its
// recipient_only_kinds key to this option.
func WithRecipientOnlyKinds(kinds ...int) SessionOption {
	return func(cfg *SessionConfig) {
		cfg.RecipientOnlyKinds = append([]int(nil), kinds...)
	}
}

// recipientOnly reports whether kind is served only to its recipient.
func (c *SessionConfig) recipientOnly(kind int) bool {
	return c != nil && slices.Contains(c.RecipientOnlyKinds, kind)
}

// namesRecipientOnlyKind reports whether a filter in filters lists a
// recipient-only kind by number. An unauthenticated REQ, COUNT or NEG-OPEN
// doing so is refused "auth-required:", so the client knows to AUTH.
func (c *SessionConfig) namesRecipientOnlyKind(filters ...*nip01.SubscriptionFilter) bool {
	if c == nil || len(c.RecipientOnlyKinds) == 0 {
		return false
	}
	for _, f := range filters {
		if f == nil {
			continue
		}
		for _, k := range f.Kinds {
			if c.recipientOnly(k) {
				return true
			}
		}
	}
	return false
}

// mayMatchRecipientOnlyKind reports whether a filter in filters could
// match a recipient-only kind: it lists one, or lists no kinds at all. Only
// then are candidate events checked one by one.
func (c *SessionConfig) mayMatchRecipientOnlyKind(filters ...*nip01.SubscriptionFilter) bool {
	if c == nil || len(c.RecipientOnlyKinds) == 0 {
		return false
	}
	for _, f := range filters {
		if f == nil {
			continue
		}
		if len(f.Kinds) == 0 {
			return true
		}
		for _, k := range f.Kinds {
			if c.recipientOnly(k) {
				return true
			}
		}
	}
	return false
}

// recipientOnlyRefusal is the reason an unauthenticated read naming a
// recipient-only kind is refused.
func recipientOnlyRefusal(kinds []int) string {
	return fmt.Sprintf("auth-required: kinds %v are served only to their recipient", kinds)
}

// deniedRecipientOnlyEvent reports whether ev is of a recipient-only kind
// and none of reader's authenticated pubkeys is named in its "p" tags.
func (c *SessionConfig) deniedRecipientOnlyEvent(reader groupReader, ev *nip01.Event) bool {
	if ev == nil || !c.recipientOnly(ev.Kind) {
		return false
	}
	return !namesReader(reader, ev.Tags)
}

// deniedRecipientOnlyPotentialEvent is deniedRecipientOnlyEvent for a
// stored event's raw bytes. A payload that will not parse is withheld: the
// store holds only what it accepted, so this is a bug, and withholding is
// the side that leaks nothing.
func (c *SessionConfig) deniedRecipientOnlyPotentialEvent(reader groupReader, pe *PotentialEvent) bool {
	if c == nil || len(c.RecipientOnlyKinds) == 0 || pe == nil {
		return false
	}
	var ev struct {
		Kind int        `json:"kind"`
		Tags [][]string `json:"tags"`
	}
	if err := json.Unmarshal(pe.Bytes, &ev); err != nil {
		return true
	}
	if !c.recipientOnly(ev.Kind) {
		return false
	}
	return !namesReader(reader, ev.Tags)
}

func namesReader(reader groupReader, tags [][]string) bool {
	if reader == nil {
		return false
	}
	pubkeys := reader.readerPubkeys()
	if len(pubkeys) == 0 {
		return false
	}
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "p" && slices.Contains(pubkeys, tag[1]) {
			return true
		}
	}
	return false
}

// QueryHandler returns NewQueryHandler wired to this handler's store,
// limitation, NIP-43 membership and NIP-29 groups, and also applying its
// RecipientOnlyKinds for the NIP-98 signer. NewQueryHandler alone knows
// nothing of RecipientOnlyKinds, so a relay that sets them serves POST
// /query through this.
func (sh *SessionHandler) QueryHandler() http.Handler {
	var limitation *nip11.Limitation
	if sh.relayMetadata != nil {
		limitation = &sh.relayMetadata.Limitation
	}
	return &queryHandler{store: sh.store, limitation: limitation, membership: sh.membership, groups: sh.groups, recipientOnly: sh.config}
}

// allFilters is fg's filters, nil-safe.
func allFilters(fg *nip01.SubscriptionFilterGroup) []*nip01.SubscriptionFilter {
	if fg == nil {
		return nil
	}
	return fg.GetAll()
}

// refuseRecipientOnlyRead refuses subID when the connection has not
// authenticated and filters name a recipient-only kind, reporting whether
// it did.
func (s *Session) refuseRecipientOnlyRead(subID string, filters ...*nip01.SubscriptionFilter) bool {
	if s.AuthedPubkey() != "" || !s.config.namesRecipientOnlyKind(filters...) {
		return false
	}
	s.refuse(subID, recipientOnlyRefusal(s.config.RecipientOnlyKinds))
	return true
}
