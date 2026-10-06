// Package nip29 implements NIP-29: Relay-based Groups -- relay-hosted
// groups, the moderation events that change their state, the relay-authored
// metadata events that mirror it, and the join/leave requests users send.
// This package is a pure protocol library (parsing, structural validation,
// and event construction); it has no dependency on relay/.
//
// Role semantics are deliberately not hardcoded here. The spec states that
// which role may perform which action "is specific to each relay and not
// specified", so this package supplies ModerationPolicy for a relay to
// declare its own mapping rather than inventing one.
package nip29

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Moderation and user-request kinds. Moderation events are expected to come
// from the relay master key or a group admin; join/leave requests come from
// ordinary users. Both carry the group id in an "h" tag.
const (
	KindPutUser       = 9000
	KindRemoveUser    = 9001
	KindEditMetadata  = 9002
	KindDeleteEvent   = 9005
	KindCreateGroup   = 9007
	KindDeleteGroup   = 9008
	KindCreateInvite  = 9009
	KindUpdatePinList = 9010
	KindJoinRequest   = 9021
	KindLeaveRequest  = 9022
)

// Relay-authored group metadata kinds. These carry the group id in a "d"
// tag instead of "h", MUST be signed by the relay's own NIP-11 "self"
// pubkey, and at most one of each exists per group at a time.
const (
	KindGroupMetadata     = 39000
	KindGroupAdmins       = 39001
	KindGroupMembers      = 39002
	KindGroupRoles        = 39003
	KindLiveParticipants  = 39004
	KindGroupPinnedEvents = 39005
)

// KindUserGroupList is the NIP-51 list in which a user remembers the groups
// they are in.
const KindUserGroupList = 10009

// The moderation-kind range. The spec reserves kinds 9000-9020 for
// moderation actions, of which only some are currently defined -- an
// unrecognized kind inside the range is still a moderation event.
const (
	ModerationKindMin = 9000
	ModerationKindMax = 9020
)

// Tag names this NIP defines.
const (
	TagGroupID  = "h"
	TagPrevious = "previous"
)

// TimelineReferenceLength is how many leading characters of an event id a
// "previous" reference carries: the first 8 characters, i.e. 4 bytes.
const TimelineReferenceLength = 8

// RecommendedTimelineReferences is the number of "previous" references the
// spec recommends clients include and relays enforce. There can legitimately
// be any number, including zero, so this is advice a relay may apply, not a
// rule this package enforces.
const RecommendedTimelineReferences = 3

// DuplicateErrorPrefix is the prefix the spec requires on the error message
// rejecting a join request from a pubkey that is already a member, so a
// client can tell "already in" apart from a real refusal.
const DuplicateErrorPrefix = "duplicate: "

// Failure modes, for callers that need to distinguish them (e.g. via
// errors.Is) rather than match on message text.
var (
	ErrWrongKind          = errors.New("nip29: wrong kind")
	ErrMissingHTag        = errors.New("nip29: missing h tag (group id)")
	ErrEmptyHTag          = errors.New("nip29: empty h tag (group id)")
	ErrMissingDTag        = errors.New("nip29: missing d tag (group id)")
	ErrMissingPTag        = errors.New("nip29: missing p tag")
	ErrMissingETag        = errors.New("nip29: missing e tag (event id)")
	ErrMissingCodeTag     = errors.New("nip29: missing code tag (invite code)")
	ErrMissingRoleTag     = errors.New("nip29: missing role tag")
	ErrInvalidPubkey      = errors.New("nip29: invalid pubkey")
	ErrInvalidEventID     = errors.New("nip29: invalid event id")
	ErrInvalidSupportKind = errors.New("nip29: supported_kinds entry is not a kind number")
	ErrInvalidATag        = errors.New("nip29: invalid a tag")
	ErrInvalidReference   = errors.New("nip29: invalid previous reference")
	ErrInvalidSignature   = errors.New("nip29: invalid signature")
	ErrDuplicateParentTag = errors.New("nip29: more than one parent tag")
)

/////////////////////////////////////////////////////////////////////
// Kind predicates
/////////////////////////////////////////////////////////////////////

// IsModerationKind reports whether kind falls in the moderation range
// (9000-9020). An unrecognized kind in the range is still a moderation
// event, so this is a range check rather than a list of known kinds.
func IsModerationKind(kind int) bool {
	return kind >= ModerationKindMin && kind <= ModerationKindMax
}

// IsUserRequestKind reports whether kind is one of the two requests an
// ordinary user sends about their own membership.
func IsUserRequestKind(kind int) bool {
	return kind == KindJoinRequest || kind == KindLeaveRequest
}

// IsGroupMetadataKind reports whether kind is one of the relay-authored
// metadata events (39000-39005), which carry "d" rather than "h".
func IsGroupMetadataKind(kind int) bool {
	return kind >= KindGroupMetadata && kind <= KindGroupPinnedEvents
}

// IsRelayAuthoredKind reports whether kind must be signed by the relay's own
// NIP-11 "self" identity rather than by an arbitrary client. Relays should
// reject these when signed by anyone else.
func IsRelayAuthoredKind(kind int) bool {
	return IsGroupMetadataKind(kind)
}

// RequiresGroupIDTag reports whether events of this kind must carry an "h"
// tag naming their group -- true for moderation events and user requests,
// false for the relay-authored metadata events that use "d" instead.
func RequiresGroupIDTag(kind int) bool {
	return IsModerationKind(kind) || IsUserRequestKind(kind)
}

/////////////////////////////////////////////////////////////////////
// Group id tags and timeline references
/////////////////////////////////////////////////////////////////////

// GroupIDFromTags returns the group id from an "h" tag. Every event a user
// sends to a group -- chat, note or moderation action -- must carry one.
func GroupIDFromTags(tags [][]string) (string, error) {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == TagGroupID {
			if tag[1] == "" {
				return "", ErrEmptyHTag
			}
			return tag[1], nil
		}
	}
	return "", ErrMissingHTag
}

// GroupIDFromDTag returns the group id from a "d" tag, as the relay-authored
// metadata events carry it.
func GroupIDFromDTag(tags [][]string) (string, error) {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "d" {
			return tag[1], nil
		}
	}
	return "", ErrMissingDTag
}

// TimelineReferences returns the "previous" tag's event-id prefixes: the
// first 8 characters of recently seen events, included so a message cannot
// be replayed into a forked copy of the group out of context. Relays are
// expected to reject references they cannot find in their own database,
// which is a store-aware decision and therefore not made here.
func TimelineReferences(tags [][]string) ([]string, error) {
	var refs []string
	for _, tag := range tags {
		if len(tag) < 1 || tag[0] != TagPrevious {
			continue
		}
		for _, ref := range tag[1:] {
			if len(ref) != TimelineReferenceLength {
				return nil, fmt.Errorf("%w: %q is %d chars, want %d", ErrInvalidReference, ref, len(ref), TimelineReferenceLength)
			}
			if !isHex(ref) {
				return nil, fmt.Errorf("%w: %q is not hex", ErrInvalidReference, ref)
			}
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

// AddTimelineReferences appends a "previous" tag to an event. Each reference
// is truncated to its first 8 characters, so callers may pass full event ids.
func AddTimelineReferences(event *nip01.Event, eventIDs ...string) {
	if len(eventIDs) == 0 {
		return
	}
	tag := []string{TagPrevious}
	for _, id := range eventIDs {
		if len(id) > TimelineReferenceLength {
			id = id[:TimelineReferenceLength]
		}
		tag = append(tag, id)
	}
	event.Tags = append(event.Tags, tag)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}

/////////////////////////////////////////////////////////////////////
// Moderation policy
/////////////////////////////////////////////////////////////////////

// ModerationPolicy maps a role name to the moderation kinds that role may
// perform. The spec is explicit that this mapping "is specific to each relay
// and not specified here" -- and that relays MUST check it before accepting a
// moderation event -- so this type lets a relay declare its own policy
// instead of inheriting a guess. Role names are arbitrary: a relay may call
// them "admin"/"moderator" or "ceo"/"secretary", and should advertise
// whichever it uses in its kind:39003 event.
type ModerationPolicy map[string][]int

// Allows reports whether role may perform kind.
func (p ModerationPolicy) Allows(role string, kind int) bool {
	for _, allowed := range p[role] {
		if allowed == kind {
			return true
		}
	}
	return false
}

// AllowsAny reports whether any of roles may perform kind, which is the
// question to ask of an admin holding several roles at once.
func (p ModerationPolicy) AllowsAny(roles []string, kind int) bool {
	for _, role := range roles {
		if p.Allows(role, kind) {
			return true
		}
	}
	return false
}

// RoleNames returns the role names this policy defines, suitable for
// building the kind:39003 event that advertises them.
func (p ModerationPolicy) RoleNames() []string {
	names := make([]string, 0, len(p))
	for name := range p {
		names = append(names, name)
	}
	return names
}

/////////////////////////////////////////////////////////////////////
// Group metadata (kind 39000)
/////////////////////////////////////////////////////////////////////

// GroupMetadata is a parsed kind:39000 event: how clients should display a
// group, plus the four access flags and the optional supported-kinds list.
//
// SupportedKindsSet distinguishes an absent supported_kinds tag from a
// present-but-empty one, which the spec gives opposite meanings: absent means
// every kind is supported, empty means none are (the AV-only group case).
type GroupMetadata struct {
	ID      string
	Name    string
	Picture string
	Banner  string
	About   string
	Parent  string
	// Children is this group's own ordered ["child", "<id>"] tags -- set
	// only on a group that is itself a parent (NIP-29 "Subgroups"). Order
	// is significant (the parent admin's own display/arrangement), so
	// callers must not treat it as an unordered set.
	Children          []string
	Private           bool
	Restricted        bool
	Hidden            bool
	Closed            bool
	LiveKit           bool
	SupportedKinds    []int
	SupportedKindsSet bool
}

// SupportsKind reports whether the group accepts events of this kind,
// honouring the absent/empty distinction described on GroupMetadata.
func (m *GroupMetadata) SupportsKind(kind int) bool {
	if !m.SupportedKindsSet {
		return true
	}
	for _, k := range m.SupportedKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// IsSubgroup reports whether this group hangs off a parent group.
func (m *GroupMetadata) IsSubgroup() bool { return m.Parent != "" }

// ParseGroupMetadata parses and structurally validates a kind:39000 event.
func ParseGroupMetadata(event *nip01.Event) (*GroupMetadata, error) {
	if event.Kind != KindGroupMetadata {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindGroupMetadata)
	}

	meta := &GroupMetadata{}
	haveD := false
	haveParent := false
	for _, tag := range event.Tags {
		if len(tag) < 1 {
			continue
		}
		// The access flags are single-element tags: presence is the value.
		switch tag[0] {
		case "private":
			meta.Private = true
			continue
		case "restricted":
			meta.Restricted = true
			continue
		case "hidden":
			meta.Hidden = true
			continue
		case "closed":
			meta.Closed = true
			continue
		case "livekit":
			meta.LiveKit = true
			continue
		case "supported_kinds":
			meta.SupportedKindsSet = true
			for _, raw := range tag[1:] {
				kind, err := strconv.Atoi(raw)
				if err != nil {
					return nil, fmt.Errorf("%w: %q", ErrInvalidSupportKind, raw)
				}
				meta.SupportedKinds = append(meta.SupportedKinds, kind)
			}
			continue
		}
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "d":
			meta.ID = tag[1]
			haveD = true
		case "name":
			meta.Name = tag[1]
		case "picture":
			meta.Picture = tag[1]
		case "banner":
			meta.Banner = tag[1]
		case "about":
			meta.About = tag[1]
		case "parent":
			// Spec: a kind:9002 MAY carry at most one parent tag, so the
			// resulting kind:39000 does too -- a second one is malformed,
			// not "last one wins" silently.
			if haveParent {
				return nil, ErrDuplicateParentTag
			}
			haveParent = true
			meta.Parent = tag[1]
		case "child":
			meta.Children = append(meta.Children, tag[1])
		}
	}
	if !haveD {
		return nil, ErrMissingDTag
	}
	return meta, nil
}

// ValidateGroupMetadata checks the signature and structure of a kind:39000
// event. It does not check that the signer is the relay's own "self"
// identity -- that is config-aware and belongs in relay/, not here.
func ValidateGroupMetadata(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseGroupMetadata(event)
	return err
}

// GroupMetadataParams describes a kind:39000 event. SelfPubkey and ID are
// required.
type GroupMetadataParams struct {
	SelfPubkey string
	ID         string
	Name       string
	Picture    string
	Banner     string
	About      string
	Parent     string
	// Children is this group's ordered list of subgroup ids, emitted as
	// one ["child", id] tag per entry. See GroupMetadata.Children.
	Children          []string
	Private           bool
	Restricted        bool
	Hidden            bool
	Closed            bool
	LiveKit           bool
	SupportedKinds    []int
	SupportedKindsSet bool
	Content           string
}

// NewGroupMetadata builds an unsigned kind:39000 event. Caller must sign it
// with the relay's own "self" private key.
func NewGroupMetadata(p GroupMetadataParams) *nip01.Event {
	tags := [][]string{{"d", p.ID}}
	tags = appendIfSet(tags, "name", p.Name)
	tags = appendIfSet(tags, "picture", p.Picture)
	tags = appendIfSet(tags, "banner", p.Banner)
	tags = appendIfSet(tags, "about", p.About)
	tags = appendIfSet(tags, "parent", p.Parent)
	for _, child := range p.Children {
		tags = append(tags, []string{"child", child})
	}
	tags = appendFlag(tags, "private", p.Private)
	tags = appendFlag(tags, "restricted", p.Restricted)
	tags = appendFlag(tags, "hidden", p.Hidden)
	tags = appendFlag(tags, "closed", p.Closed)
	tags = appendFlag(tags, "livekit", p.LiveKit)
	if p.SupportedKindsSet {
		tag := []string{"supported_kinds"}
		for _, kind := range p.SupportedKinds {
			tag = append(tag, strconv.Itoa(kind))
		}
		tags = append(tags, tag)
	}
	return nip01.NewUnsignedEvent(KindGroupMetadata, p.SelfPubkey, p.Content, tags...)
}

/////////////////////////////////////////////////////////////////////
// Group admins, members, roles, live participants, pins (39001-39005)
/////////////////////////////////////////////////////////////////////

// Admin is one entry in a kind:39001 admin list: a pubkey plus the roles it
// holds. Roles SHOULD correspond to those the relay advertises in kind:39003.
type Admin struct {
	Pubkey string
	Roles  []string
}

// GroupAdmins is a parsed kind:39001 event.
type GroupAdmins struct {
	ID     string
	Admins []Admin
}

// ParseGroupAdmins parses and structurally validates a kind:39001 event.
func ParseGroupAdmins(event *nip01.Event) (*GroupAdmins, error) {
	if event.Kind != KindGroupAdmins {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindGroupAdmins)
	}
	id, err := GroupIDFromDTag(event.Tags)
	if err != nil {
		return nil, err
	}
	admins := &GroupAdmins{ID: id}
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != "p" {
			continue
		}
		if err := utils.Validate32Key(tag[1]); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkey, tag[1], err)
		}
		admins.Admins = append(admins.Admins, Admin{Pubkey: tag[1], Roles: copyStrings(tag[2:])})
	}
	return admins, nil
}

// RolesFor returns the roles held by pubkey, or nil when it is not an admin.
func (a *GroupAdmins) RolesFor(pubkey string) []string {
	for _, admin := range a.Admins {
		if admin.Pubkey == pubkey {
			return admin.Roles
		}
	}
	return nil
}

// GroupAdminsParams describes a kind:39001 event.
type GroupAdminsParams struct {
	SelfPubkey string
	ID         string
	Admins     []Admin
	Content    string
}

// NewGroupAdmins builds an unsigned kind:39001 event.
func NewGroupAdmins(p GroupAdminsParams) *nip01.Event {
	tags := [][]string{{"d", p.ID}}
	for _, admin := range p.Admins {
		tags = append(tags, append([]string{"p", admin.Pubkey}, admin.Roles...))
	}
	return nip01.NewUnsignedEvent(KindGroupAdmins, p.SelfPubkey, p.Content, tags...)
}

// GroupMembers is a parsed kind:39002 event. Per spec a client should not
// assume this is present, nor that it lists every member: a relay may publish
// a subset or none at all.
type GroupMembers struct {
	ID      string
	Members []string
}

// ParseGroupMembers parses and structurally validates a kind:39002 event.
func ParseGroupMembers(event *nip01.Event) (*GroupMembers, error) {
	if event.Kind != KindGroupMembers {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindGroupMembers)
	}
	id, err := GroupIDFromDTag(event.Tags)
	if err != nil {
		return nil, err
	}
	members := &GroupMembers{ID: id}
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != "p" {
			continue
		}
		if err := utils.Validate32Key(tag[1]); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkey, tag[1], err)
		}
		members.Members = append(members.Members, tag[1])
	}
	return members, nil
}

// Contains reports whether pubkey appears in this (possibly partial) list.
// A false result is not proof of non-membership -- the list may be a subset.
func (m *GroupMembers) Contains(pubkey string) bool {
	for _, member := range m.Members {
		if member == pubkey {
			return true
		}
	}
	return false
}

// GroupMembersParams describes a kind:39002 event.
type GroupMembersParams struct {
	SelfPubkey string
	ID         string
	Members    []string
	Content    string
}

// NewGroupMembers builds an unsigned kind:39002 event.
func NewGroupMembers(p GroupMembersParams) *nip01.Event {
	tags := [][]string{{"d", p.ID}}
	for _, member := range p.Members {
		tags = append(tags, []string{"p", member})
	}
	return nip01.NewUnsignedEvent(KindGroupMembers, p.SelfPubkey, p.Content, tags...)
}

// GroupRole is one entry in a kind:39003 role list.
type GroupRole struct {
	Name        string
	Description string
}

// GroupRoles is a parsed kind:39003 event: the roles this relay supports
// according to its own internal logic.
type GroupRoles struct {
	ID    string
	Roles []GroupRole
}

// ParseGroupRoles parses and structurally validates a kind:39003 event.
func ParseGroupRoles(event *nip01.Event) (*GroupRoles, error) {
	if event.Kind != KindGroupRoles {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindGroupRoles)
	}
	id, err := GroupIDFromDTag(event.Tags)
	if err != nil {
		return nil, err
	}
	roles := &GroupRoles{ID: id}
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != "role" {
			continue
		}
		role := GroupRole{Name: tag[1]}
		if len(tag) >= 3 {
			role.Description = tag[2]
		}
		roles.Roles = append(roles.Roles, role)
	}
	return roles, nil
}

// GroupRolesParams describes a kind:39003 event.
type GroupRolesParams struct {
	SelfPubkey string
	ID         string
	Roles      []GroupRole
	Content    string
}

// NewGroupRoles builds an unsigned kind:39003 event.
func NewGroupRoles(p GroupRolesParams) *nip01.Event {
	tags := [][]string{{"d", p.ID}}
	for _, role := range p.Roles {
		tag := []string{"role", role.Name}
		if role.Description != "" {
			tag = append(tag, role.Description)
		}
		tags = append(tags, tag)
	}
	return nip01.NewUnsignedEvent(KindGroupRoles, p.SelfPubkey, p.Content, tags...)
}

// LiveParticipants is a parsed kind:39004 event: who is currently live in a
// group's audio/video room. The relay republishes it as people join and
// leave, and clients are expected to subscribe to it. The spec names it after
// LiveKit, but the event itself carries nothing LiveKit-specific -- it is
// just a live roster, usable with any media transport.
type LiveParticipants struct {
	ID           string
	Participants []string
}

// ParseLiveParticipants parses and structurally validates a kind:39004
// event. Note the participant tag name is "participant", not "p".
func ParseLiveParticipants(event *nip01.Event) (*LiveParticipants, error) {
	if event.Kind != KindLiveParticipants {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindLiveParticipants)
	}
	id, err := GroupIDFromDTag(event.Tags)
	if err != nil {
		return nil, err
	}
	live := &LiveParticipants{ID: id}
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != "participant" {
			continue
		}
		if err := utils.Validate32Key(tag[1]); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkey, tag[1], err)
		}
		live.Participants = append(live.Participants, tag[1])
	}
	return live, nil
}

// LiveParticipantsParams describes a kind:39004 event.
type LiveParticipantsParams struct {
	SelfPubkey   string
	ID           string
	Participants []string
	Content      string
}

// NewLiveParticipants builds an unsigned kind:39004 event.
func NewLiveParticipants(p LiveParticipantsParams) *nip01.Event {
	tags := [][]string{{"d", p.ID}}
	for _, participant := range p.Participants {
		tags = append(tags, []string{"participant", participant})
	}
	return nip01.NewUnsignedEvent(KindLiveParticipants, p.SelfPubkey, p.Content, tags...)
}

// GroupPinnedEvents is a parsed kind:39005 event: the group's pinned events
// in display order. Events holds "e" references to regular events and
// Addresses holds "a" references to addressable ones.
type GroupPinnedEvents struct {
	ID        string
	Events    []string
	Addresses []string
}

// ParseGroupPinnedEvents parses and structurally validates a kind:39005
// event.
func ParseGroupPinnedEvents(event *nip01.Event) (*GroupPinnedEvents, error) {
	if event.Kind != KindGroupPinnedEvents {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindGroupPinnedEvents)
	}
	id, err := GroupIDFromDTag(event.Tags)
	if err != nil {
		return nil, err
	}
	pins := &GroupPinnedEvents{ID: id}
	events, addresses, err := parsePinReferences(event.Tags)
	if err != nil {
		return nil, err
	}
	pins.Events, pins.Addresses = events, addresses
	return pins, nil
}

// GroupPinnedEventsParams describes a kind:39005 event.
type GroupPinnedEventsParams struct {
	SelfPubkey string
	ID         string
	Events     []string
	Addresses  []string
	Content    string
}

// NewGroupPinnedEvents builds an unsigned kind:39005 event.
func NewGroupPinnedEvents(p GroupPinnedEventsParams) *nip01.Event {
	tags := [][]string{{"d", p.ID}}
	tags = appendPinReferences(tags, p.Events, p.Addresses)
	return nip01.NewUnsignedEvent(KindGroupPinnedEvents, p.SelfPubkey, p.Content, tags...)
}

func parsePinReferences(tags [][]string) (events, addresses []string, err error) {
	for _, tag := range tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "e":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventID, tag[1], err)
			}
			events = append(events, tag[1])
		case "a":
			if _, _, _, err := utils.ParseATag(tag[1]); err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %w", ErrInvalidATag, tag[1], err)
			}
			addresses = append(addresses, tag[1])
		}
	}
	return events, addresses, nil
}

func appendPinReferences(tags [][]string, events, addresses []string) [][]string {
	for _, id := range events {
		tags = append(tags, []string{"e", id})
	}
	for _, addr := range addresses {
		tags = append(tags, []string{"a", addr})
	}
	return tags
}

func appendIfSet(tags [][]string, name, value string) [][]string {
	if value == "" {
		return tags
	}
	return append(tags, []string{name, value})
}

func appendFlag(tags [][]string, name string, set bool) [][]string {
	if !set {
		return tags
	}
	return append(tags, []string{name})
}

func copyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

/////////////////////////////////////////////////////////////////////
// User requests (kinds 9021, 9022)
/////////////////////////////////////////////////////////////////////

// JoinRequest is a parsed kind:9021 event. Code carries an optional invite
// code, which a relay may have preauthorized via a kind:9009 create-invite.
//
// A relay MUST reject the request when the pubkey has not been added to the
// group, and MUST prefix the error with DuplicateErrorPrefix when the pubkey
// is already a member. Both are store-aware decisions made in relay/.
type JoinRequest struct {
	GroupID string
	Code    string
	Reason  string
}

// ParseJoinRequest parses and structurally validates a kind:9021 event.
func ParseJoinRequest(event *nip01.Event) (*JoinRequest, error) {
	if event.Kind != KindJoinRequest {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindJoinRequest)
	}
	groupID, err := GroupIDFromTags(event.Tags)
	if err != nil {
		return nil, err
	}
	req := &JoinRequest{GroupID: groupID, Reason: event.Content}
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "code" {
			req.Code = tag[1]
			break
		}
	}
	return req, nil
}

// NewJoinRequest builds an unsigned kind:9021 event. Code and reason are
// both optional.
func NewJoinRequest(pubkey, groupID, code, reason string) *nip01.Event {
	tags := [][]string{{TagGroupID, groupID}}
	tags = appendIfSet(tags, "code", code)
	return nip01.NewUnsignedEvent(KindJoinRequest, pubkey, reason, tags...)
}

// DuplicateJoinError wraps a reason in the prefix the spec requires when
// rejecting a join request from a pubkey that is already a member, so clients
// can tell "you are already in" apart from a genuine refusal.
func DuplicateJoinError(reason string) error {
	return errors.New(DuplicateErrorPrefix + reason)
}

// IsDuplicateJoinError reports whether a relay's rejection message carries
// the duplicate prefix.
func IsDuplicateJoinError(message string) bool {
	return len(message) >= len(DuplicateErrorPrefix) && message[:len(DuplicateErrorPrefix)] == DuplicateErrorPrefix
}

// LeaveRequest is a parsed kind:9022 event. The relay answers an accepted one
// by issuing a kind:9001 remove-user of its own.
type LeaveRequest struct {
	GroupID string
	Reason  string
}

// ParseLeaveRequest parses and structurally validates a kind:9022 event.
func ParseLeaveRequest(event *nip01.Event) (*LeaveRequest, error) {
	if event.Kind != KindLeaveRequest {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindLeaveRequest)
	}
	groupID, err := GroupIDFromTags(event.Tags)
	if err != nil {
		return nil, err
	}
	return &LeaveRequest{GroupID: groupID, Reason: event.Content}, nil
}

// NewLeaveRequest builds an unsigned kind:9022 event.
func NewLeaveRequest(pubkey, groupID, reason string) *nip01.Event {
	return nip01.NewUnsignedEvent(KindLeaveRequest, pubkey, reason, []string{TagGroupID, groupID})
}

/////////////////////////////////////////////////////////////////////
// Moderation events (kinds 9000-9020)
/////////////////////////////////////////////////////////////////////

// ModerationAction is a parsed moderation event. Which fields carry meaning
// depends on Kind, per the spec's action table: PutUser/RemoveUser use
// Pubkey (and PutUser also Roles), DeleteEvent uses EventID, CreateInvite
// uses Code, UpdatePinList uses PinnedEvents and PinnedAddresses, EditMetadata
// carries the group-metadata fields in Metadata, and CreateGroup/DeleteGroup
// need nothing beyond the group id.
type ModerationAction struct {
	Kind            int
	GroupID         string
	Reason          string
	Pubkey          string
	Roles           []string
	EventID         string
	Code            string
	PinnedEvents    []string
	PinnedAddresses []string
	Metadata        *GroupMetadata
	Previous        []string
}

// ParseModerationAction parses and structurally validates any moderation
// event in the 9000-9020 range, enforcing the arguments its kind requires.
// An unrecognized kind inside the range parses with just its group id, so a
// relay can forward or store a moderation action this build predates without
// rejecting it outright.
func ParseModerationAction(event *nip01.Event) (*ModerationAction, error) {
	if !IsModerationKind(event.Kind) {
		return nil, fmt.Errorf("%w: got %d, want %d-%d", ErrWrongKind, event.Kind, ModerationKindMin, ModerationKindMax)
	}
	groupID, err := GroupIDFromTags(event.Tags)
	if err != nil {
		return nil, err
	}
	previous, err := TimelineReferences(event.Tags)
	if err != nil {
		return nil, err
	}

	action := &ModerationAction{
		Kind:     event.Kind,
		GroupID:  groupID,
		Reason:   event.Content,
		Previous: previous,
	}

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			if action.Pubkey != "" {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkey, tag[1], err)
			}
			action.Pubkey = tag[1]
			action.Roles = copyStrings(tag[2:])
		case "code":
			action.Code = tag[1]
		}
	}

	switch event.Kind {
	case KindPutUser, KindRemoveUser:
		if action.Pubkey == "" {
			return nil, ErrMissingPTag
		}
	case KindDeleteEvent:
		events, _, err := parsePinReferences(event.Tags)
		if err != nil {
			return nil, err
		}
		if len(events) == 0 {
			return nil, ErrMissingETag
		}
		action.EventID = events[0]
	case KindCreateInvite:
		if action.Code == "" {
			return nil, ErrMissingCodeTag
		}
	case KindUpdatePinList:
		// Zero references is legitimate: an empty list clears every pin.
		events, addresses, err := parsePinReferences(event.Tags)
		if err != nil {
			return nil, err
		}
		action.PinnedEvents, action.PinnedAddresses = events, addresses
	case KindEditMetadata:
		meta, err := parseMetadataFields(event.Tags)
		if err != nil {
			return nil, err
		}
		meta.ID = groupID
		action.Metadata = meta
	}

	return action, nil
}

// ValidateModerationAction checks the signature and structure of a moderation
// event. It does not check that the signer is allowed to perform the action:
// that needs the group's admin list and the relay's own ModerationPolicy, so
// it belongs in relay/.
func ValidateModerationAction(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseModerationAction(event)
	return err
}

// parseMetadataFields reads the group-metadata fields a kind:9002
// edit-metadata action carries. Unlike kind:39000 it has no "d" tag -- the
// group is named by "h" -- so this shares the field parsing without the
// identifier requirement.
func parseMetadataFields(tags [][]string) (*GroupMetadata, error) {
	stub := &nip01.Event{Kind: KindGroupMetadata, Tags: append([][]string{{"d", ""}}, tags...)}
	meta, err := ParseGroupMetadata(stub)
	if err != nil {
		return nil, err
	}
	meta.ID = ""
	return meta, nil
}

// NewPutUser builds an unsigned kind:9000 event adding a pubkey to a group,
// optionally with roles.
func NewPutUser(pubkey, groupID, memberPubkey string, roles ...string) *nip01.Event {
	return nip01.NewUnsignedEvent(KindPutUser, pubkey, "",
		[]string{TagGroupID, groupID},
		append([]string{"p", memberPubkey}, roles...),
	)
}

// NewRemoveUser builds an unsigned kind:9001 event removing a pubkey from a
// group.
func NewRemoveUser(pubkey, groupID, memberPubkey string) *nip01.Event {
	return nip01.NewUnsignedEvent(KindRemoveUser, pubkey, "",
		[]string{TagGroupID, groupID},
		[]string{"p", memberPubkey},
	)
}

// NewEditMetadata builds an unsigned kind:9002 event. The group is named by
// the "h" tag, so Params.ID is ignored in favour of groupID.
func NewEditMetadata(pubkey, groupID string, p GroupMetadataParams) *nip01.Event {
	built := NewGroupMetadata(p)
	tags := [][]string{{TagGroupID, groupID}}
	for _, tag := range built.Tags {
		if len(tag) >= 1 && tag[0] == "d" {
			continue
		}
		tags = append(tags, tag)
	}
	return nip01.NewUnsignedEvent(KindEditMetadata, pubkey, p.Content, tags...)
}

// NewDeleteEvent builds an unsigned kind:9005 event deleting one event from a
// group.
func NewDeleteEvent(pubkey, groupID, eventID string) *nip01.Event {
	return nip01.NewUnsignedEvent(KindDeleteEvent, pubkey, "",
		[]string{TagGroupID, groupID},
		[]string{"e", eventID},
	)
}

// NewCreateGroup builds an unsigned kind:9007 event.
func NewCreateGroup(pubkey, groupID string) *nip01.Event {
	return nip01.NewUnsignedEvent(KindCreateGroup, pubkey, "", []string{TagGroupID, groupID})
}

// NewDeleteGroup builds an unsigned kind:9008 event.
func NewDeleteGroup(pubkey, groupID string) *nip01.Event {
	return nip01.NewUnsignedEvent(KindDeleteGroup, pubkey, "", []string{TagGroupID, groupID})
}

// NewCreateInvite builds an unsigned kind:9009 event carrying an invite code
// a later kind:9021 join request may present.
func NewCreateInvite(pubkey, groupID, code string) *nip01.Event {
	return nip01.NewUnsignedEvent(KindCreateInvite, pubkey, "",
		[]string{TagGroupID, groupID},
		[]string{"code", code},
	)
}

// NewUpdatePinList builds an unsigned kind:9010 event. The list is absolute:
// pinning, unpinning, reordering and clearing are all done by submitting the
// full desired list, so passing none clears every pin.
func NewUpdatePinList(pubkey, groupID string, events, addresses []string) *nip01.Event {
	tags := appendPinReferences([][]string{{TagGroupID, groupID}}, events, addresses)
	return nip01.NewUnsignedEvent(KindUpdatePinList, pubkey, "", tags...)
}

/////////////////////////////////////////////////////////////////////
// Signature-checking wrappers for the relay-authored kinds
/////////////////////////////////////////////////////////////////////

// The Validate* functions below check signature and structure. None of them
// checks that the signer is the relay's own NIP-11 "self" identity, which
// relays MUST also enforce for these kinds -- that is config-aware and lives
// in relay/, not here.

// ValidateGroupAdmins checks a kind:39001 event.
func ValidateGroupAdmins(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseGroupAdmins(event)
	return err
}

// ValidateGroupMembers checks a kind:39002 event.
func ValidateGroupMembers(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseGroupMembers(event)
	return err
}

// ValidateGroupRoles checks a kind:39003 event.
func ValidateGroupRoles(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseGroupRoles(event)
	return err
}

// ValidateLiveParticipants checks a kind:39004 event.
func ValidateLiveParticipants(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseLiveParticipants(event)
	return err
}

// ValidateGroupPinnedEvents checks a kind:39005 event.
func ValidateGroupPinnedEvents(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseGroupPinnedEvents(event)
	return err
}

// ValidateJoinRequest checks a kind:9021 event.
func ValidateJoinRequest(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseJoinRequest(event)
	return err
}

// ValidateLeaveRequest checks a kind:9022 event.
func ValidateLeaveRequest(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseLeaveRequest(event)
	return err
}
