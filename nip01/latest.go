package nip01

import (
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip16"
	"github.com/ohstr/nmilat/nip33"
)

// Supersedes reports whether a replaces b under NIP-01's rule for replaceable
// and addressable events: the higher created_at wins, and on a tie the
// lower id (lexicographic hex) wins. It is the rule the relay store applies.
func Supersedes(a, b *Event) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt > b.CreatedAt
	}
	return strings.ToLower(a.ID) < strings.ToLower(b.ID)
}

// LatestVersion returns the version that wins among events, which must all be
// versions of one replaceable or addressable event (same ReplaceableAddress). An event
// dated more than maxSkew after now is ignored, so a future-dated version
// can't win and then pin the slot. Nil events are skipped. Latest does not
// check signatures: verify events before trusting them. It returns nil
// when no event qualifies.
func LatestVersion(events []*Event, now time.Time, maxSkew time.Duration) *Event {
	limit := uint64(max(now.Add(maxSkew).Unix(), 0))
	var best *Event
	for _, ev := range events {
		if ev == nil || ev.CreatedAt > limit {
			continue
		}
		if best == nil || Supersedes(ev, best) {
			best = ev
		}
	}
	return best
}

// LatestVersions groups events by ReplaceableAddress and applies LatestVersion to each
// group. Events that are neither replaceable nor addressable are skipped.
func LatestVersions(events []*Event, now time.Time, maxSkew time.Duration) map[string]*Event {
	groups := map[string][]*Event{}
	for _, ev := range events {
		if ev == nil {
			continue
		}
		addr, ok := ReplaceableAddress(ev)
		if !ok {
			continue
		}
		groups[addr] = append(groups[addr], ev)
	}
	out := make(map[string]*Event, len(groups))
	for addr, evs := range groups {
		if latest := LatestVersion(evs, now, maxSkew); latest != nil {
			out[addr] = latest
		}
	}
	return out
}

// ReplaceableAddress is the slot an event replaces within: "kind:pubkey:d" for an
// addressable event (d is the first "d" tag's value, "" when absent),
// "kind:pubkey:" for a replaceable one. ok is false for any other kind.
func ReplaceableAddress(ev *Event) (addr string, ok bool) {
	switch {
	case nip33.IsParamReplaceableKind(ev.Kind):
		return strconv.Itoa(ev.Kind) + ":" + strings.ToLower(ev.PubKey) + ":" + dTag(ev), true
	case nip16.IsReplaceableKind(ev.Kind):
		return strconv.Itoa(ev.Kind) + ":" + strings.ToLower(ev.PubKey) + ":", true
	}
	return "", false
}

func dTag(ev *Event) string {
	for _, t := range ev.Tags {
		if len(t) > 0 && t[0] == "d" {
			if len(t) > 1 {
				return t[1]
			}
			return ""
		}
	}
	return ""
}
