package relay

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// MemberNoticeKinds are the kinds of the events GroupsService signs when a
// pubkey gains or loses a seat in a hosted group (SetMemberNotices). No NIP
// fixes them; 44100 and 44101 are what existing clients read.
type MemberNoticeKinds struct {
	Added   int
	Removed int
}

// DefaultMemberNoticeKinds are the kinds existing clients subscribe to.
var DefaultMemberNoticeKinds = MemberNoticeKinds{Added: 44100, Removed: 44101}

// SetMemberNotices turns seat notices on with kinds, or off with the zero
// value. While on, every change to a group's member list -- create,
// put-user, remove-user, join, leave, delete -- stores one relay-signed
// event per pubkey whose seat changed:
//
//	tags:    ["p", member], ["h", group], ["e", cause] (the event behind it)
//	content: {"type":"member_added"|"member_removed","channel_id":group,"actor":pubkey}
//
// Only the member it names and relay admins (SetRelayAdmins) may read one.
// List both kinds in SessionConfig.RelayAuthoredKinds (and the /events
// handler's WithEventsRelayAuthoredKinds) so no client can forge one.
func (g *GroupsService) SetMemberNotices(kinds MemberNoticeKinds) {
	if g == nil {
		return
	}
	if kinds == (MemberNoticeKinds{}) {
		g.memberNotices.Store(nil)
		return
	}
	g.memberNotices.Store(&kinds)
}

// MemberNotices returns the notice kinds and whether notices are on.
func (g *GroupsService) MemberNotices() (MemberNoticeKinds, bool) {
	if g == nil {
		return MemberNoticeKinds{}, false
	}
	k := g.memberNotices.Load()
	if k == nil {
		return MemberNoticeKinds{}, false
	}
	return *k, true
}

func (g *GroupsService) isMemberNoticeKind(kind int) bool {
	k, ok := g.MemberNotices()
	return ok && (kind == k.Added || kind == k.Removed)
}

// mayDeliverMemberNotice reports whether a filter in filters could match a
// member notice: it names a notice kind, or no kinds at all.
func (g *GroupsService) mayDeliverMemberNotice(filters *nip01.SubscriptionFilterGroup) bool {
	if _, ok := g.MemberNotices(); !ok || filters == nil {
		return false
	}
	for _, f := range filters.GetAll() {
		if len(f.Kinds) == 0 || slices.ContainsFunc(f.Kinds, g.isMemberNoticeKind) {
			return true
		}
	}
	return false
}

// deniedMemberNotice reports whether s may not read the member notice ev:
// only the member its "p" names and relay admins may.
func (g *GroupsService) deniedMemberNotice(s groupReader, ev *nip01.Event) bool {
	if namesReader(s, ev.Tags) {
		return false
	}
	if s != nil {
		for _, pk := range s.readerPubkeys() {
			if g.isRelayAdmin(pk) {
				return false
			}
		}
	}
	return true
}

// memberNoticeContent is a notice's content.
type memberNoticeContent struct {
	Type  string `json:"type"`
	Group string `json:"channel_id"`
	Actor string `json:"actor"`
}

// publishMemberNotice stores a relay-signed notice that member gained
// (added) or lost a seat in groupID, because of cause (an event id, or ""),
// sent by actor. A no-op while notices are off.
func (g *GroupsService) publishMemberNotice(ctx context.Context, s *Session, groupID, member, actor, cause string, added bool) {
	kinds, ok := g.MemberNotices()
	if !ok {
		return
	}
	kind, typ := kinds.Removed, "member_removed"
	if added {
		kind, typ = kinds.Added, "member_added"
	}
	content, _ := json.Marshal(memberNoticeContent{Type: typ, Group: groupID, Actor: actor})
	tags := [][]string{{"p", member}, {"h", groupID}}
	if cause != "" {
		tags = append(tags, []string{"e", cause})
	}
	publishSelfSigned(ctx, s, &nip01.Event{
		PubKey:    s.selfPubkey,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      kind,
		Tags:      tags,
		Content:   string(content),
	})
}
