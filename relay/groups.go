package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/wire"
)

// HandleEvent processes any NIP-29 moderation event (kind:9000-9020) or
// group-scoped user request (kind:9021/9022), replying via s and mutating
// group state as a side effect. Callers (processEvent) should invoke this
// only for those kinds; it always replies (never falls through silently),
// since a client sending one of these kinds is unambiguously attempting to
// use this feature -- including when g is nil (NIP-29 group hosting isn't
// configured on this relay at all), which gets an explicit "restricted"
// reply rather than being silently accepted as an ordinary event.
func (g *GroupsService) HandleEvent(ctx context.Context, s *Session, ev *nip01.Event) {
	if g == nil {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: false,
			Message:  "restricted: NIP-29 group hosting is not enabled on this relay",
		})
		return
	}
	s.reply(g.handle(ctx, s, ev))
}

// handle runs ev's handler holding g.mu, so the checks an event passes and
// the change they allow are one step against every other group write: a
// role or roster read for a check can't be stale by the time it's acted
// on, and a group deleted meanwhile is "no such group", never recreated.
// The OK goes out after the lock is released, so a slow client never
// holds up other groups' writes.
func (g *GroupsService) handle(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch ev.Kind {
	case nip29.KindCreateGroup:
		return g.handleCreate(ctx, s, ev)
	case nip29.KindDeleteGroup:
		return g.handleDeleteGroup(ctx, s, ev)
	case nip29.KindPutUser:
		return g.handlePutUser(ctx, s, ev)
	case nip29.KindRemoveUser:
		return g.handleRemoveUser(ctx, s, ev)
	case nip29.KindEditMetadata:
		return g.handleEditMetadata(ctx, s, ev)
	case nip29.KindDeleteEvent:
		return g.handleDeleteEvent(ctx, s, ev)
	case nip29.KindCreateInvite:
		return g.handleCreateInvite(ctx, s, ev)
	case nip29.KindUpdatePinList:
		return g.handleUpdatePinList(ctx, s, ev)
	case nip29.KindJoinRequest:
		return g.handleJoinRequest(ctx, s, ev)
	case nip29.KindLeaveRequest:
		return g.handleLeaveRequest(ctx, s, ev)
	default:
		// A moderation kind inside 9000-9020 this build doesn't give any
		// specific meaning to (see nip29.IsModerationKind's own doc
		// comment: an unrecognized kind in the range still parses, so a
		// relay can forward/store one it predates). Phase 1-3 implement
		// every currently-specified kind, so reaching here means either a
		// future NIP-29 revision or a client mistake -- either way, still
		// answered explicitly rather than silently dropped.
		return &wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: false,
			Message:  "restricted: unsupported NIP-29 event kind",
		}
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9007 create / kind:9008 delete
/////////////////////////////////////////////////////////////////////

// handleCreate implements kind:9007. Decision 1 (docs/specs/nip29-groups-plan.md):
// group creation requires no prior NIP-43 relay membership -- anyone may
// create a group, so there is deliberately no membership/role check here.
func (g *GroupsService) handleCreate(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	// Structural validation (h tag present) already ran via
	// nip29/relayreg's RegisterEventValidator hook before processEvent ever
	// reached this point, when that package is blank-imported -- this
	// re-parse is defensive either way, not expected to fail in practice.
	groupID, err := nip29.GroupIDFromTags(ev.Tags)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}

	if g.Exists(groupID) {
		// Accepted only as its own admin's idempotent retry; anyone else's
		// create changed nothing and must not read as success.
		return &wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: g.IsAdmin(groupID, ev.PubKey),
			Message:  "duplicate: a group with that id already exists.",
		}
	}

	rec := newGroupRecord(groupID, ev.PubKey)
	if err := g.createLocked(rec); err != nil {
		s.config.Logger.Error().Err(err).Str("group", groupID).Msg("failed to persist new group")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not store group"}
	}

	publishGroupMetadataMirror(ctx, s, rec)
	g.publishGroupRosterMirrors(ctx, s, rec)
	g.publishMemberNotice(ctx, s, groupID, ev.PubKey, ev.PubKey, ev.ID, true)
	if s.config.PrivKey != "" {
		g.publishRoles(ctx, s.selfPubkey, s.config.PrivKey, rec.ID)
	}
	g.recordModeration(ctx, s, ev)

	return &wire.OkSubscriptionResponse{
		EventID:  ev.ID,
		Accepted: true,
		Message:  fmt.Sprintf("info: group %s created.", groupID),
	}
}

// handleDeleteGroup implements kind:9008: teardown by whoever CanPerform
// allows it -- a member whose roles in this group carry kind 9008, a relay
// admin (SetRelayAdmins) even with no roster entry here, or a key the
// host's authorizer (SetAuthorizer) allows. A NIP-43 relay role alone
// grants nothing unless the authorizer maps it.
//
// NIP-29 "Subgroups": when a parent is deleted, its remaining children
// automatically become roots. Delete returns the record as it stood
// immediately before removal, so its own Children list -- the parent's
// reverse index, already paid for by the reparent bookkeeping below --
// is exactly what needs detaching; no scan over every other group.
func (g *GroupsService) handleDeleteGroup(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	groupID, err := nip29.GroupIDFromTags(ev.Tags)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}

	if !g.Exists(groupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}

	if !g.CanPerform(groupID, ev.PubKey, nip29.KindDeleteGroup) {
		return &wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: false,
			Message:  "restricted: only a group admin may delete this group.",
		}
	}

	// handle holds g.mu: delete reads this group's own Children before
	// removing it, then this function mutates each of them, a sequence a
	// concurrent reparent elsewhere must not interleave with.
	deleted, err := g.deleteLocked(groupID)
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", groupID).Msg("failed to delete group")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not delete group"}
	}

	purgeGroupEvents(ctx, s, groupID)

	var children []string
	if deleted != nil {
		for _, m := range deleted.Members {
			g.publishMemberNotice(ctx, s, groupID, m.Pubkey, ev.PubKey, ev.ID, false)
		}
		children = deleted.Metadata.Children
		// A deleted subgroup must also leave its parent's child list, or
		// the parent keeps advertising an id every read of it now refuses.
		if parentID := deleted.Metadata.Parent; parentID != "" {
			if parent, err := g.removeChild(parentID, groupID); err != nil {
				s.config.Logger.Error().Err(err).Str("group", parentID).Str("child", groupID).
					Msg("failed to detach deleted subgroup from its parent")
			} else if parent != nil {
				publishGroupMetadataMirror(ctx, s, parent)
			}
		}
	}
	for _, childID := range children {
		child, err := g.setParentLocked(childID, "")
		if err != nil {
			s.config.Logger.Error().Err(err).Str("group", groupID).Str("child", childID).
				Msg("failed to promote child to root after parent deletion")
			continue
		}
		if child != nil {
			publishGroupMetadataMirror(ctx, s, child)
		}
	}

	return &wire.OkSubscriptionResponse{
		EventID:  ev.ID,
		Accepted: true,
		Message:  fmt.Sprintf("info: group %s deleted.", groupID),
	}
}

// purgeGroupEvents removes a deleted group's stored events: the relay's own
// 39000-39005 mirrors and everything tagged into it. Left in the store
// they'd be served to anyone, since the group whose privacy gated them is
// gone.
func purgeGroupEvents(ctx context.Context, s *Session, groupID string) {
	filters := []*nip01.SubscriptionFilter{
		{
			Kinds:   []int{nip29.KindGroupMetadata, nip29.KindGroupAdmins, nip29.KindGroupMembers, nip29.KindGroupRoles, nip29.KindLiveParticipants, nip29.KindGroupPinnedEvents},
			Authors: []string{s.selfPubkey},
			Tags:    map[string][]string{"d": {groupID}},
		},
		{Tags: map[string][]string{"h": {groupID}}},
	}
	for _, f := range filters {
		pes, err := s.store.FindEvents(ctx, f)
		if err == nil && len(pes) > 0 {
			err = s.store.DeleteAll(pes)
		}
		if err != nil {
			s.config.Logger.Error().Err(err).Str("group", groupID).Msg("failed to purge a deleted group's events")
		}
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9000 put-user / kind:9001 remove-user (Phase 2)
/////////////////////////////////////////////////////////////////////

// handlePutUser implements kind:9000: an admin (per ModerationPolicy) adds
// pubkey to the group's roster, optionally with roles.
func (g *GroupsService) handlePutUser(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}
	if !g.Exists(action.GroupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindPutUser) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: you may not add members to this group."}
	}
	if msg := g.grantCeilingPutUser(action.GroupID, ev.PubKey, action.Pubkey, action.Roles); msg != "" {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: msg}
	}

	wasMember := g.IsMember(action.GroupID, action.Pubkey)
	rec, err := g.upsertMemberLocked(action.GroupID, GroupMember{Pubkey: action.Pubkey, Roles: action.Roles})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to add group member")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update group roster"}
	}

	g.publishGroupRosterMirrors(ctx, s, rec)
	if !wasMember {
		g.publishMemberNotice(ctx, s, action.GroupID, action.Pubkey, ev.PubKey, ev.ID, true)
	}
	g.clearPendingJoins(ctx, s, action.GroupID, action.Pubkey)
	g.recordModeration(ctx, s, ev)
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: member added."}
}

// handleRemoveUser implements kind:9001: an admin (per ModerationPolicy)
// removes pubkey from the group's roster.
func (g *GroupsService) handleRemoveUser(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}
	if !g.Exists(action.GroupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindRemoveUser) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: you may not remove members from this group."}
	}
	if msg := g.grantCeilingRemoveUser(action.GroupID, ev.PubKey, action.Pubkey); msg != "" {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: msg}
	}

	wasMember := g.IsMember(action.GroupID, action.Pubkey)
	rec, err := g.removeMemberLocked(action.GroupID, action.Pubkey)
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to remove group member")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update group roster"}
	}

	g.publishGroupRosterMirrors(ctx, s, rec)
	if wasMember {
		g.publishMemberNotice(ctx, s, action.GroupID, action.Pubkey, ev.PubKey, ev.ID, false)
	}
	g.clearPendingJoins(ctx, s, action.GroupID, action.Pubkey)
	g.recordModeration(ctx, s, ev)
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: member removed."}
}

/////////////////////////////////////////////////////////////////////
// kind:9002 edit-metadata (Phase 3)
/////////////////////////////////////////////////////////////////////

// handleEditMetadata implements kind:9002: an admin (per ModerationPolicy)
// replaces the group's metadata wholesale -- the event carries the complete
// desired state, not a patch (every access flag is a presence tag, so a
// flag the submitter omits is cleared, not left alone).
//
// NIP-29 "Subgroups" adds two more concerns on top of that same full-replace
// event, evaluated independently since a group simultaneously has one
// Parent and can itself be the Parent of others (Children) -- the existing
// admin-of-the-edited-group check above already covers "may I set my own
// parent" and "may I reorder my own children" (both fields on the record
// ev's own "h" tag names); only the *new* parent side of a reparent needs
// an extra check, because that group isn't the one ev names.
func (g *GroupsService) handleEditMetadata(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}
	if !g.Exists(action.GroupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindEditMetadata) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: only a group admin may edit this group's metadata."}
	}

	// handle holds g.mu: a reparent reads and mutates up to three records
	// (this group, its old parent, its new parent), and that whole
	// sequence runs as one unit against a concurrent edit elsewhere.
	current := g.cache.Get(action.GroupID)
	var oldParent string
	if current != nil {
		oldParent = current.Metadata.Parent
	}
	newParent := action.Metadata.Parent
	reparenting := newParent != oldParent

	if reparenting && newParent != "" {
		switch {
		case newParent == action.GroupID:
			return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: a group cannot be its own parent."}
		case !g.Exists(newParent):
			return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: the named parent group does not exist."}
		case g.createsCycle(newParent, action.GroupID):
			return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: that parent assignment would create a cycle."}
		case !g.CanPerform(newParent, ev.PubKey, nip29.KindEditMetadata):
			return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: you must also be an admin of the new parent group."}
		case action.Metadata.Private != g.IsPrivate(newParent):
			// A kind:39000 mirror is self-signed once and cached, so its
			// tags can't be redacted per viewer -- a public parent's
			// child tag (or a private parent's public child) would
			// permanently reveal the other group's id to every viewer of
			// the visible side, regardless of their own membership. Both
			// groups must share the same Private setting before they can
			// be linked.
			return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: cannot link groups with different privacy settings."}
		}
	}

	// A privacy flip on a linked group would create the same mismatched
	// pair the link check above refuses: the group's parent or a current
	// subgroup left with the other setting. Refuse it; the admin detaches
	// first, flips, then relinks.
	if current != nil && action.Metadata.Private != current.Metadata.Private && g.linkedAcrossPrivacy(newParent, current.Metadata.Children, action.Metadata.Private) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: cannot change the privacy of a linked group; its parent and subgroups must share the same setting, so detach it first."}
	}

	// Children-list completeness + no-unilateral-annexation. Unconditional
	// on whether this edit meant to touch Children at all: kind:9002 is a
	// full replace, so if the group being edited currently has any
	// children, every edit on it -- even one only renaming it -- must
	// re-list every one of them or they'd be silently detached. The
	// submitted list must also be an exact permutation of the current one
	// (same set, any order): reordering is fine, but adding an id lets a
	// parent unilaterally annex a group that never named it as parent
	// (bypassing the child-initiated model above), and omitting one is the
	// same silent-detach risk the completeness rule exists to prevent.
	//
	// Ids that no longer name a group are ignored on both sides and
	// dropped from the stored list, so a stale entry left by an older
	// relay's subgroup delete can be cleared by any edit.
	fields := groupMetadataFieldsFromAction(action.Metadata)
	fields.Children = g.liveGroups(action.Metadata.Children)
	if current != nil {
		if !isPermutation(g.liveGroups(current.Metadata.Children), fields.Children) {
			return &wire.OkSubscriptionResponse{
				EventID:  ev.ID,
				Accepted: false,
				Message:  "restricted: this edit must re-list every current subgroup; none may be added or omitted here.",
			}
		}
	}

	rec, err := g.setMetadataLocked(action.GroupID, fields)
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to update group metadata")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update group metadata"}
	}
	publishGroupMetadataMirror(ctx, s, rec)

	if reparenting {
		if oldParent != "" {
			if oldRec, err := g.removeChild(oldParent, action.GroupID); err != nil {
				s.config.Logger.Error().Err(err).Str("group", oldParent).Str("child", action.GroupID).
					Msg("failed to detach child from its old parent")
			} else if oldRec != nil {
				publishGroupMetadataMirror(ctx, s, oldRec)
			}
		}
		if newParent != "" {
			if newRec, err := g.addChild(newParent, action.GroupID); err != nil {
				s.config.Logger.Error().Err(err).Str("group", newParent).Str("child", action.GroupID).
					Msg("failed to attach child to its new parent")
			} else if newRec != nil {
				publishGroupMetadataMirror(ctx, s, newRec)
			}
		}
	}

	g.recordModeration(ctx, s, ev)
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: group metadata updated."}
}

// linkedAcrossPrivacy reports whether parent (if any) or any of children
// has a Private setting other than private.
func (g *GroupsService) linkedAcrossPrivacy(parent string, children []string, private bool) bool {
	if parent != "" && g.IsPrivate(parent) != private {
		return true
	}
	for _, c := range children {
		if g.Exists(c) && g.IsPrivate(c) != private {
			return true
		}
	}
	return false
}

// liveGroups returns the ids in ids that still name a hosted group, in
// order.
func (g *GroupsService) liveGroups(ids []string) []string {
	live := make([]string, 0, len(ids))
	for _, id := range ids {
		if g.Exists(id) {
			live = append(live, id)
		}
	}
	return live
}

// isPermutation reports whether b contains exactly the same elements as
// a, in any order -- no additions, no omissions. Used to enforce that a
// parent's own child-list edit may reorder but never add or drop a
// subgroup.
func isPermutation(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, x := range a {
		counts[x]++
	}
	for _, x := range b {
		counts[x]--
		if counts[x] < 0 {
			return false
		}
	}
	return true
}

func groupMetadataFieldsFromAction(m *nip29.GroupMetadata) GroupMetadataFields {
	if m == nil {
		return GroupMetadataFields{}
	}
	return GroupMetadataFields{
		Name:              m.Name,
		Picture:           m.Picture,
		Banner:            m.Banner,
		About:             m.About,
		Parent:            m.Parent,
		Children:          m.Children,
		Private:           m.Private,
		Restricted:        m.Restricted,
		Hidden:            m.Hidden,
		Closed:            m.Closed,
		LiveKit:           m.LiveKit,
		SupportedKinds:    m.SupportedKinds,
		SupportedKindsSet: m.SupportedKindsSet,
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9005 moderator delete-event (Phase 3)
/////////////////////////////////////////////////////////////////////

// handleDeleteEvent implements kind:9005: an admin (per ModerationPolicy)
// deletes a specific event belonging to the group, identified by its "e"
// tag. Unlike NIP-09's own kind:5 deletion (self-delete only --
// relay/store.go's insert() path enforces delEvent.PubKey == event.PubKey),
// this is a moderation action: an admin may delete any member's event, so
// it goes through the store's unrestricted EventStore.DeleteAll rather than
// NIP-09's author-scoped path. The one check that replaces NIP-09's
// authorship gate is scope: the target event must itself carry this
// group's own id in its "h" tag, so an admin can only delete events that
// belong to their own group.
func (g *GroupsService) handleDeleteEvent(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}
	if !g.Exists(action.GroupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindDeleteEvent) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: only a group admin may delete group events."}
	}

	targets, err := s.store.QueryEvents(ctx, &nip01.SubscriptionFilter{IDs: []string{action.EventID}, Limit: 1})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("event", action.EventID).Msg("failed to look up event for group moderator delete")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not look up that event"}
	}
	if len(targets) == 0 {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such event."}
	}
	targetGroupID, err := nip29.GroupIDFromTags(targets[0].Tags)
	if err != nil || targetGroupID != action.GroupID {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: that event does not belong to this group."}
	}

	pes, err := s.store.FindEvents(ctx, &nip01.SubscriptionFilter{IDs: []string{action.EventID}, Limit: 1})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("event", action.EventID).Msg("failed to resolve event for group moderator delete")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not delete that event"}
	}
	if err := s.store.DeleteAll(pes); err != nil {
		s.config.Logger.Error().Err(err).Str("event", action.EventID).Msg("failed to delete group event")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not delete that event"}
	}

	g.recordModeration(ctx, s, ev)
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: event deleted."}
}

/////////////////////////////////////////////////////////////////////
// kind:9009 create-invite / kind:9021 join (Phase 3 + Phase 2)
/////////////////////////////////////////////////////////////////////

// handleCreateInvite implements kind:9009: an admin (per ModerationPolicy)
// creates a group-scoped invite code, stored separately from NIP-43's own
// invite claims (relay/store_groups.go's indexGroupInvites).
func (g *GroupsService) handleCreateInvite(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}
	if !g.Exists(action.GroupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindCreateInvite) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: only a group admin may create invites."}
	}

	if err := g.store.PutGroupInvite(&GroupInvite{GroupID: action.GroupID, Code: action.Code, CreatedAt: time.Now().Unix()}); err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to persist group invite")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not store invite"}
	}

	g.recordModeration(ctx, s, ev)
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: invite created."}
}

// handleJoinRequest implements kind:9021 -- NIP-29's own group-scoped join
// request, distinct from NIP-43's relay-wide kind:28934. An open group
// (Metadata.Closed == false) admits any request outright; a closed one
// requires a valid, unused invite code (kind:9009) in the request's "code"
// tag. Without a code, a closed group refuses the join -- or, with
// SetPendingJoins on, stores it for the group's admins to answer with a
// kind:9000 (accept) or kind:9001 (decline).
func (g *GroupsService) handleJoinRequest(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	jr, err := nip29.ParseJoinRequest(ev)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}
	if !g.Exists(jr.GroupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}
	if g.IsMember(jr.GroupID, ev.PubKey) {
		return &wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: true,
			Message:  nip29.DuplicateErrorPrefix + "you are already a member of this group.",
		}
	}

	if g.IsClosed(jr.GroupID) {
		if jr.Code == "" {
			if g.pendingJoins.Load() {
				return g.storePendingJoin(ctx, s, jr.GroupID, ev)
			}
			return &wire.OkSubscriptionResponse{
				EventID:  ev.ID,
				Accepted: false,
				Message:  "restricted: this group is closed; an invite code or admin approval is required.",
			}
		}
		if _, err := s.store.ConsumeGroupInvite(jr.GroupID, jr.Code); err != nil {
			msg := "restricted: that is an invalid invite code."
			if !isKnownGroupInviteError(err) {
				s.config.Logger.Error().Err(err).Str("group", jr.GroupID).Msg("failed to consume group invite claim")
				msg = "error: could not validate invite code"
			}
			return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: msg}
		}
	}

	rec, err := g.upsertMemberLocked(jr.GroupID, GroupMember{Pubkey: ev.PubKey})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", jr.GroupID).Msg("failed to add joining member")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not store membership"}
	}

	g.publishGroupRosterMirrors(ctx, s, rec)
	g.publishMemberNotice(ctx, s, jr.GroupID, ev.PubKey, ev.PubKey, ev.ID, true)
	g.clearPendingJoins(ctx, s, jr.GroupID, ev.PubKey)
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: welcome to the group!"}
}

// handleLeaveRequest implements kind:9022 -- NIP-29's own group-scoped
// leave request, distinct from NIP-43's relay-wide kind:28936.
func (g *GroupsService) handleLeaveRequest(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	lr, err := nip29.ParseLeaveRequest(ev)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}
	if !g.Exists(lr.GroupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}
	if !g.IsMember(lr.GroupID, ev.PubKey) {
		// Leaving withdraws a pending join request, if any.
		g.clearPendingJoins(ctx, s, lr.GroupID, ev.PubKey)
		return &wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: true,
			Message:  nip29.DuplicateErrorPrefix + "you are not a member of this group.",
		}
	}

	rec, err := g.removeMemberLocked(lr.GroupID, ev.PubKey)
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", lr.GroupID).Msg("failed to remove leaving member")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update membership"}
	}

	g.publishGroupRosterMirrors(ctx, s, rec)
	g.publishMemberNotice(ctx, s, lr.GroupID, ev.PubKey, ev.PubKey, ev.ID, false)
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: you have left the group."}
}

// storePendingJoin keeps a closed group's codeless join request for its
// admins, replacing any earlier one from the same pubkey.
func (g *GroupsService) storePendingJoin(ctx context.Context, s *Session, groupID string, ev *nip01.Event) *wire.OkSubscriptionResponse {
	g.clearPendingJoins(ctx, s, groupID, ev.PubKey)
	if err := s.store.InsertEvents(ctx, []*nip01.Event{ev}); err != nil {
		s.config.Logger.Error().Err(err).Str("group", groupID).Msg("failed to store pending join request")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not store join request"}
	}
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: your join request is pending admin approval."}
}

// clearPendingJoins drops pubkey's stored join requests to groupID: it was
// answered (put-user or remove-user), joined another way, or left.
func (g *GroupsService) clearPendingJoins(ctx context.Context, s *Session, groupID, pubkey string) {
	if pubkey == "" {
		return
	}
	pes, err := s.store.FindEvents(ctx, &nip01.SubscriptionFilter{
		Kinds:   []int{nip29.KindJoinRequest},
		Authors: []string{pubkey},
		Tags:    map[string][]string{"h": {groupID}},
	})
	if err == nil && len(pes) > 0 {
		err = s.store.DeleteAll(pes)
	}
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", groupID).Msg("failed to clear pending join requests")
	}
}

// isKnownGroupInviteError reports whether err is one of the two "normal,
// expected" ConsumeGroupInvite outcomes (as opposed to a real storage
// failure) -- both read identically to the requester as "invalid code".
func isKnownGroupInviteError(err error) bool {
	return errors.Is(err, ErrGroupInviteNotFound) || errors.Is(err, ErrGroupInviteExhausted)
}

/////////////////////////////////////////////////////////////////////
// kind:9010 update-pin-list (Phase 3)
/////////////////////////////////////////////////////////////////////

// handleUpdatePinList implements kind:9010: an admin (per ModerationPolicy)
// replaces the group's pinned list wholesale -- zero references is
// legitimate (nip29.ParseModerationAction's own doc comment: "an empty
// list clears every pin").
func (g *GroupsService) handleUpdatePinList(ctx context.Context, s *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()}
	}
	if !g.Exists(action.GroupID) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."}
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindUpdatePinList) {
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: only a group admin may update this group's pinned list."}
	}

	rec, err := g.setPinsLocked(action.GroupID, GroupPins{Events: action.PinnedEvents, Addresses: action.PinnedAddresses})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to update group pins")
		return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update pinned list"}
	}

	publishGroupPinsMirror(ctx, s, rec)
	g.recordModeration(ctx, s, ev)
	return &wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: pinned list updated."}
}

/////////////////////////////////////////////////////////////////////
// Relay-authored mirror events (kind:39000-39002, 39005)
/////////////////////////////////////////////////////////////////////

// mirrorCreatedAt returns a created_at for a republished kind:3900x mirror
// event that is guaranteed to be newer than any event of the same kind
// already stored for this group's "d" tag. These kinds are NIP-33
// parameterized-replaceable: when two events of the same kind+d-tag share
// the same created_at (entirely possible here -- two admin actions on the
// same group within the same wall-clock second, e.g. kind:9007 immediately
// followed by kind:9002), NIP-01 breaks the tie by keeping whichever has
// the lower event id, which has nothing to do with which one was actually
// published more recently. Left alone, that could silently leave a
// group's publicly-visible metadata/roster/pins stuck on stale content
// even though GroupsService's own authoritative state (relay/store_groups.go)
// updated correctly. Bumping forward past the current latest sidesteps
// the tie entirely, at the cost of one extra point lookup per mirror
// publish -- an infrequent admin action, not the request hot path.
func mirrorCreatedAt(ctx context.Context, s *Session, kind int, groupID string) uint64 {
	now := uint64(time.Now().Unix())
	existing, err := s.store.QueryEvents(ctx, &nip01.SubscriptionFilter{
		Kinds: []int{kind},
		Tags:  map[string][]string{"d": {groupID}},
		Limit: 1,
	})
	if err != nil || len(existing) == 0 || now > existing[0].CreatedAt {
		return now
	}
	return existing[0].CreatedAt + 1
}

// publishGroupMetadataMirror self-signs+stores rec's current metadata as a
// kind:39000 event, via the same publishSelfSigned pattern
// relay/membership.go first used for NIP-43's own relay-authored events.
func publishGroupMetadataMirror(ctx context.Context, s *Session, rec *GroupRecord) {
	ev := nip29.NewGroupMetadata(nip29.GroupMetadataParams{
		SelfPubkey:        s.selfPubkey,
		ID:                rec.ID,
		Name:              rec.Metadata.Name,
		Picture:           rec.Metadata.Picture,
		Banner:            rec.Metadata.Banner,
		About:             rec.Metadata.About,
		Parent:            rec.Metadata.Parent,
		Children:          rec.Metadata.Children,
		Private:           rec.Metadata.Private,
		Restricted:        rec.Metadata.Restricted,
		Hidden:            rec.Metadata.Hidden,
		Closed:            rec.Metadata.Closed,
		LiveKit:           rec.Metadata.LiveKit,
		SupportedKinds:    rec.Metadata.SupportedKinds,
		SupportedKindsSet: rec.Metadata.SupportedKindsSet,
	})
	ev.CreatedAt = mirrorCreatedAt(ctx, s, nip29.KindGroupMetadata, rec.ID)
	publishSelfSigned(ctx, s, ev)
}

// groupAdminsEvent builds rec's unsigned kind:39001: every member holding
// a role with at least one moderation kind in the policy.
func (g *GroupsService) groupAdminsEvent(selfPubkey string, rec *GroupRecord) *nip01.Event {
	var admins []nip29.Admin
	for _, m := range rec.Members {
		if g.hasPrivilege(m.Roles) {
			admins = append(admins, nip29.Admin{Pubkey: m.Pubkey, Roles: m.Roles})
		}
	}
	return nip29.NewGroupAdmins(nip29.GroupAdminsParams{SelfPubkey: selfPubkey, ID: rec.ID, Admins: admins})
}

// publishGroupRosterMirrors self-signs+stores rec's current roster as a
// kind:39001 (every member holding a role with at least one moderation
// kind in the policy -- NIP-29's "any roles that have any privilege";
// a role the policy gives nothing is not listed) and kind:39002 (every
// member) event.
func (g *GroupsService) publishGroupRosterMirrors(ctx context.Context, s *Session, rec *GroupRecord) {
	members := make([]string, 0, len(rec.Members))
	for _, m := range rec.Members {
		members = append(members, m.Pubkey)
	}

	adminsEv := g.groupAdminsEvent(s.selfPubkey, rec)
	adminsEv.CreatedAt = mirrorCreatedAt(ctx, s, nip29.KindGroupAdmins, rec.ID)
	publishSelfSigned(ctx, s, adminsEv)

	membersEv := nip29.NewGroupMembers(nip29.GroupMembersParams{SelfPubkey: s.selfPubkey, ID: rec.ID, Members: members})
	membersEv.CreatedAt = mirrorCreatedAt(ctx, s, nip29.KindGroupMembers, rec.ID)
	publishSelfSigned(ctx, s, membersEv)
}

// publishGroupPinsMirror self-signs+stores rec's current pinned list as a
// kind:39005 event.
func publishGroupPinsMirror(ctx context.Context, s *Session, rec *GroupRecord) {
	ev := nip29.NewGroupPinnedEvents(nip29.GroupPinnedEventsParams{
		SelfPubkey: s.selfPubkey,
		ID:         rec.ID,
		Events:     rec.Pins.Events,
		Addresses:  rec.Pins.Addresses,
	})
	ev.CreatedAt = mirrorCreatedAt(ctx, s, nip29.KindGroupPinnedEvents, rec.ID)
	publishSelfSigned(ctx, s, ev)
}

/////////////////////////////////////////////////////////////////////
// Visibility gating (REQ/COUNT)
/////////////////////////////////////////////////////////////////////

// deniedPrivateGroupFilter scans filters for a "d" or "h" tag naming a
// group (the two tags group-related events carry a group id in -- see
// nip29.GroupIDFromTags/GroupIDFromDTag) that the session may not see: a
// private group none of s's authenticated identities is a member of, or a
// group that doesn't exist on this relay at all. It returns the offending
// group id and true on the first such filter found; ("", false) if every
// group referenced is either public or one a member of s's authenticated
// identities, including when none are referenced at all, filters is nil,
// or g is nil.
//
// Without this, decision 2's private+closed default (see
// docs/specs/nip29-groups-plan.md's "Visibility gating" section) is a
// no-op: a group's own kind:39000/39001/39002 events would be
// world-readable by REQ the moment handleCreate publishes them, regardless
// of the "private" flag they carry.
//
// The nonexistent-group case deliberately returns the exact same denial
// as a private-no-access one, not a distinct "(nothing found)" success:
// without this, an unauthenticated prober could brute-force group ids and
// learn, for each one, whether it exists and is private, by telling a
// restricted CLOSED (exists, private, no access) apart from a normal
// empty EOSE (anything else) -- an existence oracle that never reveals a
// group's content but does reveal its id. Converging on the restricted
// response (rather than making the private-no-access case silently
// empty) keeps this signal meaningful for a legitimate caller: "you don't
// get this," for whatever reason, instead of both cases quietly saying
// "nothing here."
func (g *GroupsService) deniedPrivateGroupFilter(s groupReader, filters *nip01.SubscriptionFilterGroup) (string, bool) {
	if g == nil || filters == nil {
		return "", false
	}
	for _, filter := range filters.GetAll() {
		for _, groupID := range groupIDsInFilter(filter) {
			if !g.Exists(groupID) {
				return groupID, true
			}
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
func (g *GroupsService) anyIdentityIsMember(s groupReader, groupID string) bool {
	for _, pk := range s.readerPubkeys() {
		if g.IsMember(groupID, pk) {
			return true
		}
	}
	return false
}

// anyIdentityCanPerform reports whether CanPerform allows any identity
// authenticated on s one of kinds in groupID: a relay admin, a role the
// policy gives one of them, or the host's authorizer. Holding a role is
// not enough -- a role the policy gives nothing (a "vip" badge) must not
// read what only those who act on it may.
func (g *GroupsService) anyIdentityCanPerform(s groupReader, groupID string, kinds ...int) bool {
	for _, pk := range s.readerPubkeys() {
		for _, k := range kinds {
			if g.CanPerform(groupID, pk, k) {
				return true
			}
		}
	}
	return false
}

// recordModeration stores an accepted moderation event when the
// moderation log is on (SetModerationLog), so clients can read a group's
// log back with {"kinds":[9000,...],"#h":[id]}.
func (g *GroupsService) recordModeration(ctx context.Context, s *Session, ev *nip01.Event) {
	if !g.moderationLog.Load() {
		return
	}
	if err := s.store.InsertEvents(ctx, []*nip01.Event{ev}); err != nil {
		s.config.Logger.Error().Err(err).Int("kind", ev.Kind).Msg("failed to store NIP-29 moderation event")
	}
}

// deniedModerationEvent reports whether a stored moderation event (the
// moderation log) is withheld from s: it is for the group's members, and
// an invite, which carries its code, for those who may create one.
func (g *GroupsService) deniedModerationEvent(s groupReader, ev *nip01.Event) bool {
	id, err := nip29.GroupIDFromTags(ev.Tags)
	if err != nil || !g.Exists(id) {
		return true
	}
	if ev.Kind == nip29.KindCreateInvite {
		return !g.anyIdentityCanPerform(s, id, nip29.KindCreateInvite)
	}
	return !g.anyIdentityIsMember(s, id)
}

// deniedPendingJoin reports whether a stored join request is withheld from
// s: only the requester and those who may answer it (kind 9000 or 9001)
// see it.
func (g *GroupsService) deniedPendingJoin(s groupReader, ev *nip01.Event) bool {
	id, err := nip29.GroupIDFromTags(ev.Tags)
	if err != nil || !g.Exists(id) {
		return true
	}
	for _, pk := range s.readerPubkeys() {
		if pk == ev.PubKey {
			return false
		}
	}
	return !g.anyIdentityCanPerform(s, id, nip29.KindPutUser, nip29.KindRemoveUser)
}

// groupReader is whoever a group-visibility check is for: a WebSocket
// session (every identity it authenticated) or an HTTP caller (its NIP-98
// signer) -- so REQ and the /query bridge run the very same checks.
type groupReader interface {
	readerPubkeys() []string
}

func (s *Session) readerPubkeys() []string {
	ids := s.Identities()
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.Pubkey
	}
	return out
}

// pubkeyReader is a groupReader for a fixed set of pubkeys.
type pubkeyReader []string

func (p pubkeyReader) readerPubkeys() []string { return p }

// groupIDsInFilter collects the group ids a filter's "d" and "h" tag
// filters name. "h" always names a group; "d" only when the filter can
// return group metadata (no kinds, or a 39000-39005 kind) -- for any other
// kind it is a NIP-33 identifier, and treating it as a group id refused
// every addressable lookup (articles, spaces) naming no group.
func groupIDsInFilter(filter *nip01.SubscriptionFilter) []string {
	if filter == nil {
		return nil
	}
	var ids []string
	if dNamesGroup(filter) {
		ids = append(ids, filter.Tags["d"]...)
	}
	ids = append(ids, filter.Tags["h"]...)
	return ids
}

func dNamesGroup(filter *nip01.SubscriptionFilter) bool {
	if len(filter.Kinds) == 0 {
		return true
	}
	for _, k := range filter.Kinds {
		if nip29.IsGroupMetadataKind(k) {
			return true
		}
	}
	return false
}

/////////////////////////////////////////////////////////////////////
// Visibility gating (per-event, at delivery time)
/////////////////////////////////////////////////////////////////////

// deniedGroupWrite returns why ev may not be posted into a group it names
// with "h", or "" if it may: a private, closed or restricted group takes
// posts from its members only; any other group from anyone.
func (g *GroupsService) deniedGroupWrite(ev *nip01.Event) string {
	if g == nil || ev == nil {
		return ""
	}
	for _, tag := range ev.Tags {
		if len(tag) < 2 || tag[0] != "h" || !g.Exists(tag[1]) {
			continue
		}
		id := tag[1]
		if (g.IsPrivate(id) || g.IsClosed(id) || g.IsRestricted(id)) && !g.IsMember(id, ev.PubKey) {
			return "restricted: only members may post in group " + id
		}
	}
	return ""
}

// needsPrivacyCheck reports whether results for filters must go through
// deniedPrivateGroupPotentialEvent: whenever a private group exists, since
// its content can match any filter, not just a group-metadata one.
func (g *GroupsService) needsPrivacyCheck(filters *nip01.SubscriptionFilterGroup) bool {
	return g.anyPrivate() || mayDeliverGroupMetadataKind(filters) || mayDeliverModerationKind(filters) ||
		g.mayDeliverMemberNotice(filters)
}

// mayDeliverModerationKind is mayDeliverGroupMetadataKind for the stored
// moderation log (kinds 9000-9020) and pending join requests (9021).
func mayDeliverModerationKind(filters *nip01.SubscriptionFilterGroup) bool {
	if filters == nil {
		return false
	}
	for _, f := range filters.GetAll() {
		if len(f.Kinds) == 0 {
			return true
		}
		for _, k := range f.Kinds {
			if nip29.IsModerationKind(k) || k == nip29.KindJoinRequest {
				return true
			}
		}
	}
	return false
}

// anyPrivate reports whether any hosted group is private.
func (g *GroupsService) anyPrivate() bool {
	if g == nil {
		return false
	}
	snap := g.cache.snap.Load()
	if snap == nil {
		return false
	}
	for _, rec := range snap.groups {
		if rec != nil && rec.Metadata.Private {
			return true
		}
	}
	return false
}

// mayDeliverGroupMetadataKind reports whether filters could possibly
// deliver a relay-authored group-metadata event (kind 39000-39005) -- an
// unset Kinds list matches any kind, so that counts as "may" too. This is
// a cheap pre-check so deniedPrivateGroupPotentialEvent's per-event bytes
// parsing below only runs for subscriptions that could plausibly see one.
func mayDeliverGroupMetadataKind(filters *nip01.SubscriptionFilterGroup) bool {
	if filters == nil {
		return false
	}
	for _, f := range filters.GetAll() {
		if len(f.Kinds) == 0 {
			return true
		}
		for _, k := range f.Kinds {
			if nip29.IsGroupMetadataKind(k) {
				return true
			}
		}
	}
	return false
}

// deniedPrivateGroupEvent reports whether ev -- a candidate event about to
// be delivered to s -- is a relay-authored group-metadata event
// (kind 39000-39005) belonging to a private or hidden group that none of
// s's authenticated identities is a member of, or content tagged into a
// private one. A hidden group hides only its metadata; its content is
// gated by "private" alone.
//
// This is deniedPrivateGroupFilter's companion, applied to the event
// actually being delivered rather than the request's own "d"/"h" tags.
// groupIDsInFilter can only see a group id the client's own filter named;
// a bare {"kinds":[39000]} REQ names none at all, so deniedPrivateGroupFilter
// has nothing to check and the query would otherwise run unrestricted
// against every group's metadata in the store, private or not. Gating at
// delivery instead of at the request closes that bypass while leaving
// public groups, and any kind outside this range, untouched.
func (g *GroupsService) deniedPrivateGroupEvent(s groupReader, ev *nip01.Event) bool {
	if g == nil || ev == nil {
		return false
	}
	if g.isMemberNoticeKind(ev.Kind) {
		return g.deniedMemberNotice(s, ev)
	}
	if nip29.IsModerationKind(ev.Kind) {
		return g.deniedModerationEvent(s, ev)
	}
	if ev.Kind == nip29.KindJoinRequest {
		return g.deniedPendingJoin(s, ev)
	}
	if nip29.IsGroupMetadataKind(ev.Kind) {
		groupID, err := nip29.GroupIDFromDTag(ev.Tags)
		if err == nil && (g.IsPrivate(groupID) || g.IsHidden(groupID)) && !g.anyIdentityIsMember(s, groupID) {
			return true
		}
		// A mirror whose group is gone (deleted before its events were
		// purged) has no privacy left to check: never serve it.
		if err == nil && !g.Exists(groupID) {
			return true
		}
	}
	// Group content: anything tagged into a private group. Without this a
	// non-member read a private group's messages by asking by kind, id or
	// author instead of by #h.
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "h" && g.IsPrivate(tag[1]) && !g.anyIdentityIsMember(s, tag[1]) {
			return true
		}
	}
	return false
}

// deniedPrivateGroupPotentialEvent is deniedPrivateGroupEvent's entry point
// from the delivery loop, which only has the candidate's raw JSON bytes
// (relay/store.go's PotentialEvent.Bytes) on hand rather than a parsed
// *nip01.Event. A malformed payload is passed through rather than denied:
// the store only ever writes what it accepted at ingest, which is already
// validated JSON, so a parse failure here would mean a bug elsewhere, not
// an attacker-controlled bypass.
func (g *GroupsService) deniedPrivateGroupPotentialEvent(s groupReader, pe *PotentialEvent) bool {
	if g == nil || pe == nil {
		return false
	}
	// Only an event carrying a "d" or "h" tag can belong to a group; skip
	// the parse for everything else.
	if !bytes.Contains(pe.Bytes, []byte(`"h"`)) && !bytes.Contains(pe.Bytes, []byte(`"d"`)) {
		return false
	}
	var ev nip01.Event
	if err := json.Unmarshal(pe.Bytes, &ev); err != nil {
		return false
	}
	return g.deniedPrivateGroupEvent(s, &ev)
}
