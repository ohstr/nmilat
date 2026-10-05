package relay

import (
	"context"
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/wire"
)

// HandleEvent processes a NIP-29 kind:9007 (create group) or kind:9008
// (delete group) request -- Phase 1's two group-lifecycle actions --
// replying via s and mutating group state as a side effect. Callers
// (processEvent) should invoke this only for those two kinds; it always
// replies (never falls through silently), since a client sending one of
// these kinds is unambiguously attempting to use this feature -- including
// when g is nil (NIP-29 group hosting isn't configured on this relay at
// all), which gets an explicit "restricted" reply rather than being
// silently accepted as an ordinary event.
func (g *GroupsService) HandleEvent(ctx context.Context, s *Session, ev *nip01.Event) {
	if g == nil {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: false,
			Message:  "restricted: NIP-29 group hosting is not enabled on this relay",
		})
		return
	}
	switch ev.Kind {
	case nip29.KindCreateGroup:
		g.handleCreate(ctx, s, ev)
	case nip29.KindDeleteGroup:
		g.handleDelete(s, ev)
	}
}

// handleCreate implements kind:9007. Decision 1 (docs/specs/nip29-groups-plan.md):
// group creation requires no prior NIP-43 relay membership -- anyone may
// create a group, so there is deliberately no membership/role check here.
func (g *GroupsService) handleCreate(ctx context.Context, s *Session, ev *nip01.Event) {
	// Structural validation (h tag present) already ran via
	// nip29/relayreg's RegisterEventValidator hook before processEvent ever
	// reached this point, when that package is blank-imported -- this
	// re-parse is defensive either way, not expected to fail in practice.
	groupID, err := nip29.GroupIDFromTags(ev.Tags)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}

	if g.Exists(groupID) {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: true,
			Message:  "duplicate: a group with that id already exists.",
		})
		return
	}

	rec := newGroupRecord(groupID, ev.PubKey)
	if err := g.Create(rec); err != nil {
		s.config.Logger.Error().Err(err).Str("group", groupID).Msg("failed to persist new group")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not store group"})
		return
	}

	// Relay-authored mirror events, so clients can discover the group's
	// metadata/admin/member roster -- the same publishSelfSigned pattern
	// membership.go uses for kind:8000/8001. Private+closed per decision 2.
	publishSelfSigned(ctx, s, nip29.NewGroupMetadata(nip29.GroupMetadataParams{
		SelfPubkey: s.selfPubkey,
		ID:         groupID,
		Private:    true,
		Closed:     true,
	}))
	publishSelfSigned(ctx, s, nip29.NewGroupAdmins(nip29.GroupAdminsParams{
		SelfPubkey: s.selfPubkey,
		ID:         groupID,
		Admins:     []nip29.Admin{{Pubkey: ev.PubKey}},
	}))
	publishSelfSigned(ctx, s, nip29.NewGroupMembers(nip29.GroupMembersParams{
		SelfPubkey: s.selfPubkey,
		ID:         groupID,
		Members:    []string{ev.PubKey},
	}))

	s.reply(&wire.OkSubscriptionResponse{
		EventID:  ev.ID,
		Accepted: true,
		Message:  fmt.Sprintf("info: group %s created.", groupID),
	})
}

// handleDelete implements kind:9008: admin-gated teardown, checked against
// the group's own 39001 roster (not relay-wide NIP-43 role) -- a relay-wide
// admin with no role in this specific group may not delete it.
func (g *GroupsService) handleDelete(s *Session, ev *nip01.Event) {
	groupID, err := nip29.GroupIDFromTags(ev.Tags)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}

	if !g.Exists(groupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}

	if !g.IsAdmin(groupID, ev.PubKey) {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: false,
			Message:  "restricted: only a group admin may delete this group.",
		})
		return
	}

	if err := g.Delete(groupID); err != nil {
		s.config.Logger.Error().Err(err).Str("group", groupID).Msg("failed to delete group")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not delete group"})
		return
	}

	s.reply(&wire.OkSubscriptionResponse{
		EventID:  ev.ID,
		Accepted: true,
		Message:  fmt.Sprintf("info: group %s deleted.", groupID),
	})
}

/////////////////////////////////////////////////////////////////////
// Visibility gating (REQ/COUNT)
/////////////////////////////////////////////////////////////////////

// deniedPrivateGroupFilter scans filters for a "d" or "h" tag naming a
// private group (the two tags group-related events carry a group id in --
// see nip29.GroupIDFromTags/GroupIDFromDTag) that none of s's authenticated
// identities is a member of. It returns the offending group id and true on
// the first such filter found; ("", false) if every private group
// referenced has a member among s's authenticated identities, including
// when none are referenced at all, filters is nil, or g is nil.
//
// Without this, decision 2's private+closed default (see
// docs/specs/nip29-groups-plan.md's "Visibility gating" section) is a
// no-op: a group's own kind:39000/39001/39002 events would be
// world-readable by REQ the moment handleCreate publishes them, regardless
// of the "private" flag they carry.
func (g *GroupsService) deniedPrivateGroupFilter(s *Session, filters *nip01.SubscriptionFilterGroup) (string, bool) {
	if g == nil || filters == nil {
		return "", false
	}
	for _, filter := range filters.GetAll() {
		for _, groupID := range groupIDsInFilter(filter) {
			if !g.IsPrivate(groupID) {
				continue
			}
			if !g.anyIdentityIsMember(s, groupID) {
				return groupID, true
			}
		}
	}
	return "", false
}

// anyIdentityIsMember reports whether any identity authenticated on s is a
// member of groupID -- the connection-level "at least one identity passes"
// semantics NIP-43's own Session.HasMembership uses, applied per-group.
func (g *GroupsService) anyIdentityIsMember(s *Session, groupID string) bool {
	for _, id := range s.Identities() {
		if g.IsMember(groupID, id.Pubkey) {
			return true
		}
	}
	return false
}

// groupIDsInFilter collects the group ids a filter's "d" and "h" tag
// filters name.
func groupIDsInFilter(filter *nip01.SubscriptionFilter) []string {
	if filter == nil {
		return nil
	}
	var ids []string
	ids = append(ids, filter.Tags["d"]...)
	ids = append(ids, filter.Tags["h"]...)
	return ids
}
