package nip29

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	testPubkeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPubkeyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testEventID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testPrivKey = "0acd1245d4b0e9cae1a3b0e1a1e0cf3d1e5b2a7c8d9e0f1a2b3c4d5e6f70268c"
)

func ev(kind int, tags ...[]string) *nip01.Event {
	return &nip01.Event{Kind: kind, PubKey: testPubkeyA, Tags: tags}
}

/////////////////////////////////////////////////////////////////////
// Kind predicates
/////////////////////////////////////////////////////////////////////

func TestKindPredicates(t *testing.T) {
	tests := []struct {
		kind       int
		moderation bool
		userReq    bool
		metadata   bool
		needsH     bool
	}{
		{kind: KindPutUser, moderation: true, needsH: true},
		{kind: KindRemoveUser, moderation: true, needsH: true},
		{kind: KindEditMetadata, moderation: true, needsH: true},
		{kind: KindDeleteEvent, moderation: true, needsH: true},
		{kind: KindCreateGroup, moderation: true, needsH: true},
		{kind: KindDeleteGroup, moderation: true, needsH: true},
		{kind: KindCreateInvite, moderation: true, needsH: true},
		{kind: KindUpdatePinList, moderation: true, needsH: true},
		{kind: 9019, moderation: true, needsH: true},
		{kind: 9020, moderation: true, needsH: true},
		{kind: KindJoinRequest, userReq: true, needsH: true},
		{kind: KindLeaveRequest, userReq: true, needsH: true},
		{kind: KindGroupMetadata, metadata: true},
		{kind: KindGroupAdmins, metadata: true},
		{kind: KindGroupMembers, metadata: true},
		{kind: KindGroupRoles, metadata: true},
		{kind: KindLiveParticipants, metadata: true},
		{kind: KindGroupPinnedEvents, metadata: true},
		{kind: 8999},
		{kind: 9021, userReq: true, needsH: true},
		{kind: 38999},
		{kind: 39006},
		{kind: 1},
	}

	for _, tc := range tests {
		if got := IsModerationKind(tc.kind); got != tc.moderation {
			t.Errorf("IsModerationKind(%d) = %v, want %v", tc.kind, got, tc.moderation)
		}
		if got := IsUserRequestKind(tc.kind); got != tc.userReq {
			t.Errorf("IsUserRequestKind(%d) = %v, want %v", tc.kind, got, tc.userReq)
		}
		if got := IsGroupMetadataKind(tc.kind); got != tc.metadata {
			t.Errorf("IsGroupMetadataKind(%d) = %v, want %v", tc.kind, got, tc.metadata)
		}
		if got := IsRelayAuthoredKind(tc.kind); got != tc.metadata {
			t.Errorf("IsRelayAuthoredKind(%d) = %v, want %v", tc.kind, got, tc.metadata)
		}
		if got := RequiresGroupIDTag(tc.kind); got != tc.needsH {
			t.Errorf("RequiresGroupIDTag(%d) = %v, want %v", tc.kind, got, tc.needsH)
		}
	}
}

/////////////////////////////////////////////////////////////////////
// h / d tags and timeline references
/////////////////////////////////////////////////////////////////////

func TestGroupIDFromTags(t *testing.T) {
	tests := []struct {
		name      string
		tags      [][]string
		want      string
		wantErrIs error
	}{
		{name: "present", tags: [][]string{{"h", "pizza"}}, want: "pizza"},
		{name: "first wins when duplicated", tags: [][]string{{"h", "pizza"}, {"h", "pasta"}}, want: "pizza"},
		{name: "missing", tags: [][]string{{"p", testPubkeyA}}, wantErrIs: ErrMissingHTag},
		{name: "empty value", tags: [][]string{{"h", ""}}, wantErrIs: ErrEmptyHTag},
		{name: "malformed single-element tag", tags: [][]string{{"h"}}, wantErrIs: ErrMissingHTag},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GroupIDFromTags(tc.tags)
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTimelineReferences(t *testing.T) {
	t.Run("spec example parses", func(t *testing.T) {
		refs, err := TimelineReferences([][]string{{"previous", "eb96c864", "2db75638", "b5d1065f"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(refs) != 3 {
			t.Fatalf("refs = %v, want 3", refs)
		}
	})

	t.Run("zero references is legitimate", func(t *testing.T) {
		refs, err := TimelineReferences([][]string{{"h", "g"}})
		if err != nil || refs != nil {
			t.Fatalf("refs = %v err = %v", refs, err)
		}
	})

	t.Run("wrong length is rejected", func(t *testing.T) {
		_, err := TimelineReferences([][]string{{"previous", "eb96c8"}})
		if !errors.Is(err, ErrInvalidReference) {
			t.Fatalf("err = %v, want ErrInvalidReference", err)
		}
	})

	t.Run("non-hex is rejected", func(t *testing.T) {
		_, err := TimelineReferences([][]string{{"previous", "zzzzzzzz"}})
		if !errors.Is(err, ErrInvalidReference) {
			t.Fatalf("err = %v, want ErrInvalidReference", err)
		}
	})

	t.Run("AddTimelineReferences truncates full ids", func(t *testing.T) {
		event := NewCreateGroup(testPubkeyA, "g")
		AddTimelineReferences(event, testEventID, testEventID)
		refs, err := TimelineReferences(event.Tags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(refs) != 2 {
			t.Fatalf("refs = %v, want 2", refs)
		}
		for _, ref := range refs {
			if len(ref) != TimelineReferenceLength {
				t.Errorf("ref %q not truncated to %d", ref, TimelineReferenceLength)
			}
		}
	})

	t.Run("no tag added for no ids", func(t *testing.T) {
		event := NewCreateGroup(testPubkeyA, "g")
		before := len(event.Tags)
		AddTimelineReferences(event)
		if len(event.Tags) != before {
			t.Errorf("tags grew from %d to %d", before, len(event.Tags))
		}
	})
}

/////////////////////////////////////////////////////////////////////
// Moderation policy -- the role capability matrix
/////////////////////////////////////////////////////////////////////

func TestModerationPolicy(t *testing.T) {
	// The spec's own worked example: an admin may edit metadata, delete
	// messages and remove users; a moderator may only delete messages.
	policy := ModerationPolicy{
		"admin":     {KindEditMetadata, KindDeleteEvent, KindRemoveUser, KindPutUser},
		"moderator": {KindDeleteEvent},
	}

	tests := []struct {
		name  string
		roles []string
		kind  int
		want  bool
	}{
		{name: "admin may remove a user", roles: []string{"admin"}, kind: KindRemoveUser, want: true},
		{name: "admin may edit metadata", roles: []string{"admin"}, kind: KindEditMetadata, want: true},
		{name: "moderator may delete an event", roles: []string{"moderator"}, kind: KindDeleteEvent, want: true},
		{name: "moderator may not remove a user", roles: []string{"moderator"}, kind: KindRemoveUser, want: false},
		{name: "moderator may not edit metadata", roles: []string{"moderator"}, kind: KindEditMetadata, want: false},
		{name: "unknown role may do nothing", roles: []string{"gardener"}, kind: KindDeleteEvent, want: false},
		{name: "no roles may do nothing", roles: nil, kind: KindDeleteEvent, want: false},
		{name: "several roles union their powers", roles: []string{"gardener", "admin"}, kind: KindRemoveUser, want: true},
		{name: "nobody may delete the group under this policy", roles: []string{"admin", "moderator"}, kind: KindDeleteGroup, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.AllowsAny(tc.roles, tc.kind); got != tc.want {
				t.Errorf("AllowsAny(%v, %d) = %v, want %v", tc.roles, tc.kind, got, tc.want)
			}
		})
	}

	t.Run("Allows is single-role", func(t *testing.T) {
		if !policy.Allows("admin", KindPutUser) {
			t.Error("admin should be allowed put-user")
		}
		if policy.Allows("moderator", KindPutUser) {
			t.Error("moderator should not be allowed put-user")
		}
	})

	t.Run("RoleNames advertises what 39003 should carry", func(t *testing.T) {
		names := policy.RoleNames()
		if len(names) != 2 {
			t.Fatalf("RoleNames = %v, want 2", names)
		}
	})

	t.Run("a nil policy denies everything", func(t *testing.T) {
		var empty ModerationPolicy
		if empty.Allows("admin", KindRemoveUser) || empty.AllowsAny([]string{"admin"}, KindRemoveUser) {
			t.Error("nil policy should deny")
		}
	})
}

/////////////////////////////////////////////////////////////////////
// Group metadata (39000)
/////////////////////////////////////////////////////////////////////

func TestParseGroupMetadata(t *testing.T) {
	t.Run("spec example", func(t *testing.T) {
		meta, err := ParseGroupMetadata(ev(KindGroupMetadata,
			[]string{"d", "pizza-lovers"},
			[]string{"name", "Pizza Lovers"},
			[]string{"picture", "https://pizza.com/pizza.png"},
			[]string{"banner", "https://pizza.com/banner.png"},
			[]string{"about", "a group for people who love pizza"},
			[]string{"private"},
			[]string{"closed"},
			[]string{"supported_kinds", "9", "11"},
		))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.ID != "pizza-lovers" || meta.Name != "Pizza Lovers" {
			t.Errorf("unexpected: %+v", meta)
		}
		if !meta.Private || !meta.Closed {
			t.Error("private/closed flags not set")
		}
		if meta.Restricted || meta.Hidden || meta.LiveKit {
			t.Error("absent flags should stay false")
		}
		if !meta.SupportsKind(9) || !meta.SupportsKind(11) || meta.SupportsKind(1) {
			t.Errorf("SupportedKinds = %v", meta.SupportedKinds)
		}
	})

	t.Run("absent supported_kinds means every kind", func(t *testing.T) {
		meta, err := ParseGroupMetadata(ev(KindGroupMetadata, []string{"d", "g"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.SupportedKindsSet {
			t.Error("SupportedKindsSet should be false")
		}
		if !meta.SupportsKind(1) || !meta.SupportsKind(30311) {
			t.Error("absent supported_kinds must support everything")
		}
	})

	t.Run("empty supported_kinds means no kinds, the AV-only case", func(t *testing.T) {
		meta, err := ParseGroupMetadata(ev(KindGroupMetadata,
			[]string{"d", "g"},
			[]string{"supported_kinds"},
			[]string{"livekit"},
		))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !meta.SupportedKindsSet {
			t.Fatal("SupportedKindsSet should be true for a present-but-empty tag")
		}
		if meta.SupportsKind(9) || meta.SupportsKind(1) {
			t.Error("empty supported_kinds must support nothing")
		}
		if !meta.LiveKit {
			t.Error("livekit flag not set")
		}
	})

	t.Run("subgroup carries a parent", func(t *testing.T) {
		meta, err := ParseGroupMetadata(ev(KindGroupMetadata, []string{"d", "child"}, []string{"parent", "root"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !meta.IsSubgroup() || meta.Parent != "root" {
			t.Errorf("Parent = %q", meta.Parent)
		}
	})

	t.Run("missing d tag", func(t *testing.T) {
		_, err := ParseGroupMetadata(ev(KindGroupMetadata, []string{"name", "x"}))
		if !errors.Is(err, ErrMissingDTag) {
			t.Fatalf("err = %v, want ErrMissingDTag", err)
		}
	})

	t.Run("non-numeric supported kind", func(t *testing.T) {
		_, err := ParseGroupMetadata(ev(KindGroupMetadata, []string{"d", "g"}, []string{"supported_kinds", "chat"}))
		if !errors.Is(err, ErrInvalidSupportKind) {
			t.Fatalf("err = %v, want ErrInvalidSupportKind", err)
		}
	})

	t.Run("wrong kind", func(t *testing.T) {
		_, err := ParseGroupMetadata(ev(KindGroupMembers, []string{"d", "g"}))
		if !errors.Is(err, ErrWrongKind) {
			t.Fatalf("err = %v, want ErrWrongKind", err)
		}
	})

	t.Run("round trip preserves the flag/kinds distinction", func(t *testing.T) {
		built := NewGroupMetadata(GroupMetadataParams{
			SelfPubkey:        testPubkeyA,
			ID:                "g",
			Name:              "G",
			Private:           true,
			Restricted:        true,
			Hidden:            true,
			Closed:            true,
			LiveKit:           true,
			SupportedKinds:    nil,
			SupportedKindsSet: true,
		})
		meta, err := ParseGroupMetadata(built)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if !meta.Private || !meta.Restricted || !meta.Hidden || !meta.Closed || !meta.LiveKit {
			t.Errorf("flags lost: %+v", meta)
		}
		if !meta.SupportedKindsSet || meta.SupportsKind(9) {
			t.Error("empty-but-set supported_kinds did not survive")
		}
	})
}

/////////////////////////////////////////////////////////////////////
// Admins, members, roles, live participants, pins (39001-39005)
/////////////////////////////////////////////////////////////////////

func TestParseGroupAdmins(t *testing.T) {
	admins, err := ParseGroupAdmins(ev(KindGroupAdmins,
		[]string{"d", "pizza-lovers"},
		[]string{"p", testPubkeyA, "ceo"},
		[]string{"p", testPubkeyB, "secretary", "gardener"},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admins.ID != "pizza-lovers" || len(admins.Admins) != 2 {
		t.Fatalf("unexpected: %+v", admins)
	}
	if got := admins.RolesFor(testPubkeyB); len(got) != 2 || got[0] != "secretary" {
		t.Errorf("RolesFor(B) = %v", got)
	}
	if got := admins.RolesFor(testEventID); got != nil {
		t.Errorf("RolesFor(stranger) = %v, want nil", got)
	}

	t.Run("invalid pubkey is fatal", func(t *testing.T) {
		_, err := ParseGroupAdmins(ev(KindGroupAdmins, []string{"d", "g"}, []string{"p", "nope"}))
		if !errors.Is(err, ErrInvalidPubkey) {
			t.Fatalf("err = %v, want ErrInvalidPubkey", err)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		built := NewGroupAdmins(GroupAdminsParams{
			SelfPubkey: testPubkeyA,
			ID:         "g",
			Admins:     []Admin{{Pubkey: testPubkeyA, Roles: []string{"admin"}}},
		})
		parsed, err := ParseGroupAdmins(built)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if len(parsed.RolesFor(testPubkeyA)) != 1 {
			t.Errorf("roles lost: %+v", parsed)
		}
	})
}

func TestParseGroupMembers(t *testing.T) {
	members, err := ParseGroupMembers(ev(KindGroupMembers,
		[]string{"d", "g"},
		[]string{"p", testPubkeyA},
		[]string{"p", testPubkeyB},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !members.Contains(testPubkeyA) || !members.Contains(testPubkeyB) {
		t.Errorf("members = %v", members.Members)
	}
	if members.Contains(testEventID) {
		t.Error("Contains reported a non-member")
	}

	t.Run("a partial list is legitimate", func(t *testing.T) {
		empty, err := ParseGroupMembers(ev(KindGroupMembers, []string{"d", "g"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(empty.Members) != 0 {
			t.Errorf("members = %v", empty.Members)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		built := NewGroupMembers(GroupMembersParams{SelfPubkey: testPubkeyA, ID: "g", Members: []string{testPubkeyB}})
		parsed, err := ParseGroupMembers(built)
		if err != nil || !parsed.Contains(testPubkeyB) {
			t.Fatalf("round-trip failed: %v %+v", err, parsed)
		}
	})
}

func TestParseGroupRoles(t *testing.T) {
	roles, err := ParseGroupRoles(ev(KindGroupRoles,
		[]string{"d", "g"},
		[]string{"role", "admin", "can do anything"},
		[]string{"role", "moderator"},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles.Roles) != 2 {
		t.Fatalf("roles = %+v", roles.Roles)
	}
	if roles.Roles[0].Description != "can do anything" || roles.Roles[1].Description != "" {
		t.Errorf("descriptions = %+v", roles.Roles)
	}

	t.Run("round trip", func(t *testing.T) {
		built := NewGroupRoles(GroupRolesParams{
			SelfPubkey: testPubkeyA,
			ID:         "g",
			Roles:      []GroupRole{{Name: "admin", Description: "d"}, {Name: "moderator"}},
		})
		parsed, err := ParseGroupRoles(built)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if len(parsed.Roles) != 2 || parsed.Roles[1].Name != "moderator" {
			t.Errorf("roles = %+v", parsed.Roles)
		}
	})
}

func TestParseLiveParticipants(t *testing.T) {
	// The roster of who is currently live in a group's AV room. Note the tag
	// is "participant", not "p" -- a "p" tag here must be ignored.
	live, err := ParseLiveParticipants(ev(KindLiveParticipants,
		[]string{"d", "g"},
		[]string{"participant", testPubkeyA},
		[]string{"participant", testPubkeyB},
		[]string{"p", testEventID},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(live.Participants) != 2 {
		t.Fatalf("participants = %v, want the two participant tags only", live.Participants)
	}

	t.Run("an empty room is legitimate", func(t *testing.T) {
		empty, err := ParseLiveParticipants(ev(KindLiveParticipants, []string{"d", "g"}))
		if err != nil || len(empty.Participants) != 0 {
			t.Fatalf("err = %v participants = %v", err, empty.Participants)
		}
	})

	t.Run("invalid participant pubkey is fatal", func(t *testing.T) {
		_, err := ParseLiveParticipants(ev(KindLiveParticipants, []string{"d", "g"}, []string{"participant", "nope"}))
		if !errors.Is(err, ErrInvalidPubkey) {
			t.Fatalf("err = %v, want ErrInvalidPubkey", err)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		built := NewLiveParticipants(LiveParticipantsParams{SelfPubkey: testPubkeyA, ID: "g", Participants: []string{testPubkeyA}})
		parsed, err := ParseLiveParticipants(built)
		if err != nil || len(parsed.Participants) != 1 {
			t.Fatalf("round-trip failed: %v %+v", err, parsed)
		}
	})
}

func TestParseGroupPinnedEvents(t *testing.T) {
	addr, err := utils.FormatATag(30311, testPubkeyA, "stream-1")
	if err != nil {
		t.Fatalf("FormatATag: %v", err)
	}
	pins, err := ParseGroupPinnedEvents(ev(KindGroupPinnedEvents,
		[]string{"d", "g"},
		[]string{"e", testEventID},
		[]string{"a", addr},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pins.Events) != 1 || len(pins.Addresses) != 1 {
		t.Fatalf("events = %v addresses = %v", pins.Events, pins.Addresses)
	}

	t.Run("malformed a tag is fatal", func(t *testing.T) {
		_, err := ParseGroupPinnedEvents(ev(KindGroupPinnedEvents, []string{"d", "g"}, []string{"a", "nonsense"}))
		if !errors.Is(err, ErrInvalidATag) {
			t.Fatalf("err = %v, want ErrInvalidATag", err)
		}
	})

	t.Run("malformed e tag is fatal", func(t *testing.T) {
		_, err := ParseGroupPinnedEvents(ev(KindGroupPinnedEvents, []string{"d", "g"}, []string{"e", "short"}))
		if !errors.Is(err, ErrInvalidEventID) {
			t.Fatalf("err = %v, want ErrInvalidEventID", err)
		}
	})
}

/////////////////////////////////////////////////////////////////////
// User requests (9021, 9022)
/////////////////////////////////////////////////////////////////////

func TestJoinAndLeaveRequests(t *testing.T) {
	t.Run("join with code and reason", func(t *testing.T) {
		event := NewJoinRequest(testPubkeyA, "pizza", "invite-123", "let me in")
		req, err := ParseJoinRequest(event)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.GroupID != "pizza" || req.Code != "invite-123" || req.Reason != "let me in" {
			t.Errorf("unexpected: %+v", req)
		}
	})

	t.Run("join without a code", func(t *testing.T) {
		req, err := ParseJoinRequest(NewJoinRequest(testPubkeyA, "pizza", "", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.Code != "" {
			t.Errorf("Code = %q, want empty", req.Code)
		}
	})

	t.Run("join without an h tag", func(t *testing.T) {
		_, err := ParseJoinRequest(ev(KindJoinRequest, []string{"code", "x"}))
		if !errors.Is(err, ErrMissingHTag) {
			t.Fatalf("err = %v, want ErrMissingHTag", err)
		}
	})

	t.Run("leave request", func(t *testing.T) {
		req, err := ParseLeaveRequest(NewLeaveRequest(testPubkeyA, "pizza", "bye"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.GroupID != "pizza" || req.Reason != "bye" {
			t.Errorf("unexpected: %+v", req)
		}
	})

	t.Run("leave request rejects the wrong kind", func(t *testing.T) {
		_, err := ParseLeaveRequest(ev(KindJoinRequest, []string{"h", "g"}))
		if !errors.Is(err, ErrWrongKind) {
			t.Fatalf("err = %v, want ErrWrongKind", err)
		}
	})

	t.Run("duplicate rejection carries the required prefix", func(t *testing.T) {
		err := DuplicateJoinError("already a member")
		if !IsDuplicateJoinError(err.Error()) {
			t.Fatalf("%q lacks the duplicate prefix", err)
		}
		if IsDuplicateJoinError("payment required") {
			t.Error("a plain refusal must not read as duplicate")
		}
		if IsDuplicateJoinError("dup") {
			t.Error("a message shorter than the prefix must not match")
		}
	})
}

/////////////////////////////////////////////////////////////////////
// Moderation actions (9000-9020)
/////////////////////////////////////////////////////////////////////

func TestParseModerationAction(t *testing.T) {
	addr, err := utils.FormatATag(30311, testPubkeyA, "s")
	if err != nil {
		t.Fatalf("FormatATag: %v", err)
	}

	tests := []struct {
		name      string
		event     *nip01.Event
		wantErrIs error
		check     func(t *testing.T, a *ModerationAction)
	}{
		{
			name:  "put-user with roles",
			event: NewPutUser(testPubkeyA, "g", testPubkeyB, "moderator"),
			check: func(t *testing.T, a *ModerationAction) {
				if a.Pubkey != testPubkeyB || len(a.Roles) != 1 || a.Roles[0] != "moderator" {
					t.Errorf("unexpected: %+v", a)
				}
			},
		},
		{
			name:  "put-user without roles",
			event: NewPutUser(testPubkeyA, "g", testPubkeyB),
			check: func(t *testing.T, a *ModerationAction) {
				if a.Pubkey != testPubkeyB || len(a.Roles) != 0 {
					t.Errorf("unexpected: %+v", a)
				}
			},
		},
		{
			name:  "remove-user",
			event: NewRemoveUser(testPubkeyA, "g", testPubkeyB),
			check: func(t *testing.T, a *ModerationAction) {
				if a.Pubkey != testPubkeyB {
					t.Errorf("Pubkey = %q", a.Pubkey)
				}
			},
		},
		{
			name:      "put-user without a p tag",
			event:     ev(KindPutUser, []string{"h", "g"}),
			wantErrIs: ErrMissingPTag,
		},
		{
			name:      "remove-user without a p tag",
			event:     ev(KindRemoveUser, []string{"h", "g"}),
			wantErrIs: ErrMissingPTag,
		},
		{
			name:  "delete-event",
			event: NewDeleteEvent(testPubkeyA, "g", testEventID),
			check: func(t *testing.T, a *ModerationAction) {
				if a.EventID != testEventID {
					t.Errorf("EventID = %q", a.EventID)
				}
			},
		},
		{
			name:      "delete-event without an e tag",
			event:     ev(KindDeleteEvent, []string{"h", "g"}),
			wantErrIs: ErrMissingETag,
		},
		{
			name:  "create-group needs nothing but the group id",
			event: NewCreateGroup(testPubkeyA, "g"),
			check: func(t *testing.T, a *ModerationAction) {
				if a.GroupID != "g" {
					t.Errorf("GroupID = %q", a.GroupID)
				}
			},
		},
		{
			name:  "delete-group needs nothing but the group id",
			event: NewDeleteGroup(testPubkeyA, "g"),
			check: func(t *testing.T, a *ModerationAction) {
				if a.Kind != KindDeleteGroup {
					t.Errorf("Kind = %d", a.Kind)
				}
			},
		},
		{
			name:  "create-invite",
			event: NewCreateInvite(testPubkeyA, "g", "code-1"),
			check: func(t *testing.T, a *ModerationAction) {
				if a.Code != "code-1" {
					t.Errorf("Code = %q", a.Code)
				}
			},
		},
		{
			name:      "create-invite without a code",
			event:     ev(KindCreateInvite, []string{"h", "g"}),
			wantErrIs: ErrMissingCodeTag,
		},
		{
			name:  "update-pin-list with both reference kinds",
			event: NewUpdatePinList(testPubkeyA, "g", []string{testEventID}, []string{addr}),
			check: func(t *testing.T, a *ModerationAction) {
				if len(a.PinnedEvents) != 1 || len(a.PinnedAddresses) != 1 {
					t.Errorf("pins = %v / %v", a.PinnedEvents, a.PinnedAddresses)
				}
			},
		},
		{
			name:  "empty update-pin-list clears the pins",
			event: NewUpdatePinList(testPubkeyA, "g", nil, nil),
			check: func(t *testing.T, a *ModerationAction) {
				if len(a.PinnedEvents) != 0 || len(a.PinnedAddresses) != 0 {
					t.Errorf("pins should be empty: %v / %v", a.PinnedEvents, a.PinnedAddresses)
				}
			},
		},
		{
			name:      "no h tag",
			event:     ev(KindCreateGroup),
			wantErrIs: ErrMissingHTag,
		},
		{
			name:      "not a moderation kind",
			event:     ev(KindJoinRequest, []string{"h", "g"}),
			wantErrIs: ErrWrongKind,
		},
		{
			name:      "bad timeline reference",
			event:     ev(KindCreateGroup, []string{"h", "g"}, []string{"previous", "xx"}),
			wantErrIs: ErrInvalidReference,
		},
		{
			name:  "unrecognized kind in range still parses",
			event: ev(9013, []string{"h", "g"}),
			check: func(t *testing.T, a *ModerationAction) {
				if a.Kind != 9013 || a.GroupID != "g" {
					t.Errorf("unexpected: %+v", a)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			action, err := ParseModerationAction(tc.event)
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tc.check(t, action)
		})
	}
}

func TestEditMetadataCarriesMetadataFields(t *testing.T) {
	event := NewEditMetadata(testPubkeyA, "pizza", GroupMetadataParams{
		Name:              "Pizza Lovers",
		About:             "pizza",
		Private:           true,
		SupportedKinds:    []int{9},
		SupportedKindsSet: true,
	})

	action, err := ParseModerationAction(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action.GroupID != "pizza" {
		t.Errorf("GroupID = %q", action.GroupID)
	}
	if action.Metadata == nil {
		t.Fatal("Metadata = nil, want the edited fields")
	}
	if action.Metadata.Name != "Pizza Lovers" || !action.Metadata.Private {
		t.Errorf("metadata = %+v", action.Metadata)
	}
	if !action.Metadata.SupportsKind(9) || action.Metadata.SupportsKind(11) {
		t.Errorf("supported kinds = %v", action.Metadata.SupportedKinds)
	}
	// The group is named by "h", so no stray "d" tag should be emitted.
	for _, tag := range event.Tags {
		if len(tag) >= 1 && tag[0] == "d" {
			t.Errorf("edit-metadata should not carry a d tag: %v", tag)
		}
	}
}

/////////////////////////////////////////////////////////////////////
// Interop: buzz uses these kinds for its huddle lifecycle
/////////////////////////////////////////////////////////////////////

// TestBuzzHuddleLifecycleKinds pins the NIP-29 kinds block/buzz uses for its
// huddle (voice room) lifecycle, so a rename or renumber here shows up as a
// failing interop test rather than as a silently broken client.
//
// Observed in buzz's mobile/HUDDLES.md: it creates the ephemeral backing
// channel with 9007, counts members from a 39002 snapshot, submits 9022 when
// another human remains, and archives the ended huddle with 9002.
func TestBuzzHuddleLifecycleKinds(t *testing.T) {
	if KindCreateGroup != 9007 {
		t.Errorf("KindCreateGroup = %d, want 9007 (buzz creates its backing channel with this)", KindCreateGroup)
	}
	if KindGroupMembers != 39002 {
		t.Errorf("KindGroupMembers = %d, want 39002 (buzz counts non-bot members from this)", KindGroupMembers)
	}
	if KindLeaveRequest != 9022 {
		t.Errorf("KindLeaveRequest = %d, want 9022 (buzz submits this when another human remains)", KindLeaveRequest)
	}
	if KindEditMetadata != 9002 {
		t.Errorf("KindEditMetadata = %d, want 9002 (buzz archives the ended huddle with this)", KindEditMetadata)
	}
	if KindJoinRequest != 9021 {
		t.Errorf("KindJoinRequest = %d, want 9021", KindJoinRequest)
	}

	// Each must round-trip through this package, since a buzz client's events
	// have to survive our parsers to interoperate at all.
	for _, event := range []*nip01.Event{
		NewCreateGroup(testPubkeyA, "huddle-1"),
		NewEditMetadata(testPubkeyA, "huddle-1", GroupMetadataParams{Name: "archived"}),
	} {
		if _, err := ParseModerationAction(event); err != nil {
			t.Errorf("kind %d did not round-trip: %v", event.Kind, err)
		}
	}
	if _, err := ParseLeaveRequest(NewLeaveRequest(testPubkeyA, "huddle-1", "")); err != nil {
		t.Errorf("leave request did not round-trip: %v", err)
	}
	if _, err := ParseGroupMembers(NewGroupMembers(GroupMembersParams{SelfPubkey: testPubkeyA, ID: "huddle-1", Members: []string{testPubkeyB}})); err != nil {
		t.Errorf("members snapshot did not round-trip: %v", err)
	}
}

/////////////////////////////////////////////////////////////////////
// Signature-checking wrappers
/////////////////////////////////////////////////////////////////////

func TestValidateSignatureWrappers(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	t.Run("unsigned moderation action is rejected", func(t *testing.T) {
		if err := ValidateModerationAction(NewCreateGroup(pubkey, "g")); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("err = %v, want ErrInvalidSignature", err)
		}
	})

	t.Run("signed moderation action is accepted", func(t *testing.T) {
		event := NewCreateGroup(pubkey, "g")
		if err := event.Sign(testPrivKey); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := ValidateModerationAction(event); err != nil {
			t.Fatalf("ValidateModerationAction: %v", err)
		}
	})

	t.Run("unsigned group metadata is rejected", func(t *testing.T) {
		built := NewGroupMetadata(GroupMetadataParams{SelfPubkey: pubkey, ID: "g"})
		if err := ValidateGroupMetadata(built); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("err = %v, want ErrInvalidSignature", err)
		}
	})

	t.Run("signed group metadata is accepted", func(t *testing.T) {
		built := NewGroupMetadata(GroupMetadataParams{SelfPubkey: pubkey, ID: "g", Name: "G"})
		if err := built.Sign(testPrivKey); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := ValidateGroupMetadata(built); err != nil {
			t.Fatalf("ValidateGroupMetadata: %v", err)
		}
	})
}
