package relay

import (
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
	switch ev.Kind {
	case nip29.KindCreateGroup:
		g.handleCreate(ctx, s, ev)
	case nip29.KindDeleteGroup:
		g.handleDeleteGroup(ctx, s, ev)
	case nip29.KindPutUser:
		g.handlePutUser(ctx, s, ev)
	case nip29.KindRemoveUser:
		g.handleRemoveUser(ctx, s, ev)
	case nip29.KindEditMetadata:
		g.handleEditMetadata(ctx, s, ev)
	case nip29.KindDeleteEvent:
		g.handleDeleteEvent(ctx, s, ev)
	case nip29.KindCreateInvite:
		g.handleCreateInvite(s, ev)
	case nip29.KindUpdatePinList:
		g.handleUpdatePinList(ctx, s, ev)
	case nip29.KindJoinRequest:
		g.handleJoinRequest(ctx, s, ev)
	case nip29.KindLeaveRequest:
		g.handleLeaveRequest(ctx, s, ev)
	default:
		// A moderation kind inside 9000-9020 this build doesn't give any
		// specific meaning to (see nip29.IsModerationKind's own doc
		// comment: an unrecognized kind in the range still parses, so a
		// relay can forward/store one it predates). Phase 1-3 implement
		// every currently-specified kind, so reaching here means either a
		// future NIP-29 revision or a client mistake -- either way, still
		// answered explicitly rather than silently dropped.
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: false,
			Message:  "restricted: unsupported NIP-29 event kind",
		})
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9007 create / kind:9008 delete
/////////////////////////////////////////////////////////////////////

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
		// Accepted only as its own admin's idempotent retry; anyone else's
		// create changed nothing and must not read as success.
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: g.IsAdmin(groupID, ev.PubKey),
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

	publishGroupMetadataMirror(ctx, s, rec)
	publishGroupRosterMirrors(ctx, s, rec)

	s.reply(&wire.OkSubscriptionResponse{
		EventID:  ev.ID,
		Accepted: true,
		Message:  fmt.Sprintf("info: group %s created.", groupID),
	})
}

// handleDeleteGroup implements kind:9008: admin-gated teardown, checked
// against the group's own roster (not relay-wide NIP-43 role) -- a
// relay-wide admin with no role in this specific group may not delete it.
//
// NIP-29 "Subgroups": when a parent is deleted, its remaining children
// automatically become roots. Delete returns the record as it stood
// immediately before removal, so its own Children list -- the parent's
// reverse index, already paid for by the reparent bookkeeping below --
// is exactly what needs detaching; no scan over every other group.
func (g *GroupsService) handleDeleteGroup(ctx context.Context, s *Session, ev *nip01.Event) {
	groupID, err := nip29.GroupIDFromTags(ev.Tags)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}

	if !g.Exists(groupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}

	if !g.CanPerform(groupID, ev.PubKey, nip29.KindDeleteGroup) {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: false,
			Message:  "restricted: only a group admin may delete this group.",
		})
		return
	}

	// See GroupsService.linkMu's own doc comment: Delete reads this
	// group's own Children before removing it, then this function
	// mutates each of them -- the same kind of multi-record sequence a
	// concurrent reparent elsewhere must not interleave with.
	g.linkMu.Lock()
	defer g.linkMu.Unlock()

	deleted, err := g.Delete(groupID)
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", groupID).Msg("failed to delete group")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not delete group"})
		return
	}

	var children []string
	if deleted != nil {
		children = deleted.Metadata.Children
	}
	for _, childID := range children {
		child, err := g.SetParent(childID, "")
		if err != nil {
			s.config.Logger.Error().Err(err).Str("group", groupID).Str("child", childID).
				Msg("failed to promote child to root after parent deletion")
			continue
		}
		if child != nil {
			publishGroupMetadataMirror(ctx, s, child)
		}
	}

	s.reply(&wire.OkSubscriptionResponse{
		EventID:  ev.ID,
		Accepted: true,
		Message:  fmt.Sprintf("info: group %s deleted.", groupID),
	})
}

/////////////////////////////////////////////////////////////////////
// kind:9000 put-user / kind:9001 remove-user (Phase 2)
/////////////////////////////////////////////////////////////////////

// handlePutUser implements kind:9000: an admin (per ModerationPolicy) adds
// pubkey to the group's roster, optionally with roles.
func (g *GroupsService) handlePutUser(ctx context.Context, s *Session, ev *nip01.Event) {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}
	if !g.Exists(action.GroupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindPutUser) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: you may not add members to this group."})
		return
	}

	rec, err := g.UpsertMember(action.GroupID, GroupMember{Pubkey: action.Pubkey, Roles: action.Roles})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to add group member")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update group roster"})
		return
	}

	publishGroupRosterMirrors(ctx, s, rec)
	s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: member added."})
}

// handleRemoveUser implements kind:9001: an admin (per ModerationPolicy)
// removes pubkey from the group's roster.
func (g *GroupsService) handleRemoveUser(ctx context.Context, s *Session, ev *nip01.Event) {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}
	if !g.Exists(action.GroupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindRemoveUser) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: you may not remove members from this group."})
		return
	}

	rec, err := g.RemoveMember(action.GroupID, action.Pubkey)
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to remove group member")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update group roster"})
		return
	}

	publishGroupRosterMirrors(ctx, s, rec)
	s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: member removed."})
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
func (g *GroupsService) handleEditMetadata(ctx context.Context, s *Session, ev *nip01.Event) {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}
	if !g.Exists(action.GroupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindEditMetadata) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: only a group admin may edit this group's metadata."})
		return
	}

	// Held for the rest of this call: a reparent reads and mutates up to
	// three records (this group, its old parent, its new parent), and
	// that whole sequence needs to run as one unit against a concurrent
	// edit elsewhere -- see GroupsService.linkMu's own doc comment.
	g.linkMu.Lock()
	defer g.linkMu.Unlock()

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
			s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: a group cannot be its own parent."})
			return
		case !g.Exists(newParent):
			s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: the named parent group does not exist."})
			return
		case g.createsCycle(newParent, action.GroupID):
			s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: that parent assignment would create a cycle."})
			return
		case !g.IsAdmin(newParent, ev.PubKey):
			s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: you must also be an admin of the new parent group."})
			return
		case g.IsPrivate(action.GroupID) != g.IsPrivate(newParent):
			// A kind:39000 mirror is self-signed once and cached, so its
			// tags can't be redacted per viewer -- a public parent's
			// child tag (or a private parent's public child) would
			// permanently reveal the other group's id to every viewer of
			// the visible side, regardless of their own membership. Both
			// groups must share the same Private setting before they can
			// be linked.
			s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: cannot link groups with different privacy settings."})
			return
		}
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
	if current != nil {
		if !isPermutation(current.Metadata.Children, action.Metadata.Children) {
			s.reply(&wire.OkSubscriptionResponse{
				EventID:  ev.ID,
				Accepted: false,
				Message:  "restricted: this edit must re-list every current subgroup; none may be added or omitted here.",
			})
			return
		}
	}

	rec, err := g.SetMetadata(action.GroupID, groupMetadataFieldsFromAction(action.Metadata))
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to update group metadata")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update group metadata"})
		return
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

	s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: group metadata updated."})
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
func (g *GroupsService) handleDeleteEvent(ctx context.Context, s *Session, ev *nip01.Event) {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}
	if !g.Exists(action.GroupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindDeleteEvent) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: only a group admin may delete group events."})
		return
	}

	targets, err := s.store.QueryEvents(ctx, &nip01.SubscriptionFilter{IDs: []string{action.EventID}, Limit: 1})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("event", action.EventID).Msg("failed to look up event for group moderator delete")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not look up that event"})
		return
	}
	if len(targets) == 0 {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such event."})
		return
	}
	targetGroupID, err := nip29.GroupIDFromTags(targets[0].Tags)
	if err != nil || targetGroupID != action.GroupID {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: that event does not belong to this group."})
		return
	}

	pes, err := s.store.FindEvents(ctx, &nip01.SubscriptionFilter{IDs: []string{action.EventID}, Limit: 1})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("event", action.EventID).Msg("failed to resolve event for group moderator delete")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not delete that event"})
		return
	}
	if err := s.store.DeleteAll(pes); err != nil {
		s.config.Logger.Error().Err(err).Str("event", action.EventID).Msg("failed to delete group event")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not delete that event"})
		return
	}

	s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: event deleted."})
}

/////////////////////////////////////////////////////////////////////
// kind:9009 create-invite / kind:9021 join (Phase 3 + Phase 2)
/////////////////////////////////////////////////////////////////////

// handleCreateInvite implements kind:9009: an admin (per ModerationPolicy)
// creates a group-scoped invite code, stored separately from NIP-43's own
// invite claims (relay/store_groups.go's indexGroupInvites).
func (g *GroupsService) handleCreateInvite(s *Session, ev *nip01.Event) {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}
	if !g.Exists(action.GroupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindCreateInvite) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: only a group admin may create invites."})
		return
	}

	if err := g.store.PutGroupInvite(&GroupInvite{GroupID: action.GroupID, Code: action.Code, CreatedAt: time.Now().Unix()}); err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to persist group invite")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not store invite"})
		return
	}

	s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: invite created."})
}

// handleJoinRequest implements kind:9021 -- NIP-29's own group-scoped join
// request, distinct from NIP-43's relay-wide kind:28934. An open group
// (Metadata.Closed == false) admits any request outright; a closed one
// requires a valid, unused invite code (kind:9009) in the request's "code"
// tag -- there is no pending-approval queue in this build, so without a
// code a closed group's join is simply refused, with the admin's own
// kind:9000 put-user as the only other path in.
func (g *GroupsService) handleJoinRequest(ctx context.Context, s *Session, ev *nip01.Event) {
	jr, err := nip29.ParseJoinRequest(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}
	if !g.Exists(jr.GroupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}
	if g.IsMember(jr.GroupID, ev.PubKey) {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: true,
			Message:  nip29.DuplicateErrorPrefix + "you are already a member of this group.",
		})
		return
	}

	if g.IsClosed(jr.GroupID) {
		if jr.Code == "" {
			s.reply(&wire.OkSubscriptionResponse{
				EventID:  ev.ID,
				Accepted: false,
				Message:  "restricted: this group is closed; an invite code or admin approval is required.",
			})
			return
		}
		if _, err := s.store.ConsumeGroupInvite(jr.GroupID, jr.Code); err != nil {
			msg := "restricted: that is an invalid invite code."
			if !isKnownGroupInviteError(err) {
				s.config.Logger.Error().Err(err).Str("group", jr.GroupID).Msg("failed to consume group invite claim")
				msg = "error: could not validate invite code"
			}
			s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: msg})
			return
		}
	}

	rec, err := g.UpsertMember(jr.GroupID, GroupMember{Pubkey: ev.PubKey})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", jr.GroupID).Msg("failed to add joining member")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not store membership"})
		return
	}

	publishGroupRosterMirrors(ctx, s, rec)
	s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: welcome to the group!"})
}

// handleLeaveRequest implements kind:9022 -- NIP-29's own group-scoped
// leave request, distinct from NIP-43's relay-wide kind:28936.
func (g *GroupsService) handleLeaveRequest(ctx context.Context, s *Session, ev *nip01.Event) {
	lr, err := nip29.ParseLeaveRequest(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}
	if !g.Exists(lr.GroupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}
	if !g.IsMember(lr.GroupID, ev.PubKey) {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: true,
			Message:  nip29.DuplicateErrorPrefix + "you are not a member of this group.",
		})
		return
	}

	rec, err := g.RemoveMember(lr.GroupID, ev.PubKey)
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", lr.GroupID).Msg("failed to remove leaving member")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update membership"})
		return
	}

	publishGroupRosterMirrors(ctx, s, rec)
	s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: you have left the group."})
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
func (g *GroupsService) handleUpdatePinList(ctx context.Context, s *Session, ev *nip01.Event) {
	action, err := nip29.ParseModerationAction(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}
	if !g.Exists(action.GroupID) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: no such group."})
		return
	}
	if !g.CanPerform(action.GroupID, ev.PubKey, nip29.KindUpdatePinList) {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: only a group admin may update this group's pinned list."})
		return
	}

	rec, err := g.SetPins(action.GroupID, GroupPins{Events: action.PinnedEvents, Addresses: action.PinnedAddresses})
	if err != nil {
		s.config.Logger.Error().Err(err).Str("group", action.GroupID).Msg("failed to update group pins")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update pinned list"})
		return
	}

	publishGroupPinsMirror(ctx, s, rec)
	s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: true, Message: "info: pinned list updated."})
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

// publishGroupRosterMirrors self-signs+stores rec's current roster as a
// kind:39001 (every member holding at least one role) and kind:39002
// (every member) event.
func publishGroupRosterMirrors(ctx context.Context, s *Session, rec *GroupRecord) {
	var admins []nip29.Admin
	members := make([]string, 0, len(rec.Members))
	for _, m := range rec.Members {
		members = append(members, m.Pubkey)
		if len(m.Roles) > 0 {
			admins = append(admins, nip29.Admin{Pubkey: m.Pubkey, Roles: m.Roles})
		}
	}

	adminsEv := nip29.NewGroupAdmins(nip29.GroupAdminsParams{SelfPubkey: s.selfPubkey, ID: rec.ID, Admins: admins})
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
func (g *GroupsService) deniedPrivateGroupFilter(s *Session, filters *nip01.SubscriptionFilterGroup) (string, bool) {
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
func (g *GroupsService) anyIdentityIsMember(s *Session, groupID string) bool {
	for _, id := range s.Identities() {
		if g.IsMember(groupID, id.Pubkey) {
			return true
		}
	}
	return false
}

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
// (kind 39000-39005) belonging to a private group that none of s's
// authenticated identities is a member of.
//
// This is deniedPrivateGroupFilter's companion, applied to the event
// actually being delivered rather than the request's own "d"/"h" tags.
// groupIDsInFilter can only see a group id the client's own filter named;
// a bare {"kinds":[39000]} REQ names none at all, so deniedPrivateGroupFilter
// has nothing to check and the query would otherwise run unrestricted
// against every group's metadata in the store, private or not. Gating at
// delivery instead of at the request closes that bypass while leaving
// public groups, and any kind outside this range, untouched.
func (g *GroupsService) deniedPrivateGroupEvent(s *Session, ev *nip01.Event) bool {
	if g == nil || ev == nil || !nip29.IsGroupMetadataKind(ev.Kind) {
		return false
	}
	groupID, err := nip29.GroupIDFromDTag(ev.Tags)
	if err != nil || !g.IsPrivate(groupID) {
		return false
	}
	return !g.anyIdentityIsMember(s, groupID)
}

// deniedPrivateGroupPotentialEvent is deniedPrivateGroupEvent's entry point
// from the delivery loop, which only has the candidate's raw JSON bytes
// (relay/store.go's PotentialEvent.Bytes) on hand rather than a parsed
// *nip01.Event. A malformed payload is passed through rather than denied:
// the store only ever writes what it accepted at ingest, which is already
// validated JSON, so a parse failure here would mean a bug elsewhere, not
// an attacker-controlled bypass.
func (g *GroupsService) deniedPrivateGroupPotentialEvent(s *Session, pe *PotentialEvent) bool {
	if g == nil || pe == nil {
		return false
	}
	var ev nip01.Event
	if err := json.Unmarshal(pe.Bytes, &ev); err != nil {
		return false
	}
	return g.deniedPrivateGroupEvent(s, &ev)
}
