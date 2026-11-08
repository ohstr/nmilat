package relay

import (
	"context"
	"github.com/ohstr/nmilat/nip01"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/nip29"
)

// groupSnapshot is an immutable point-in-time view of the NIP-29 group set,
// keyed by group id. Each *GroupRecord is itself treated as immutable once
// placed in a snapshot -- a mutation always builds a fresh *GroupRecord
// (GroupRecord.withMember/withoutMember, or a plain shallow copy for a
// metadata/pins change) and hands it to put/replace, never edits one
// returned by Get in place. That is what makes a plain shallow copy of the
// outer map safe for add/remove, exactly as membershipSnapshot relies on
// for its own entries (relay/membership_cache.go).
type groupSnapshot struct {
	groups map[string]*GroupRecord
}

// groupsCache is an O(1), lock-light-for-readers group lookup -- the same
// atomic.Pointer swap pattern as membershipCache (relay/membership_cache.go),
// scoped per-group instead of relay-wide. See that type's doc comment for
// why atomic.Load beats RWMutex here.
type groupsCache struct {
	snap    atomic.Pointer[groupSnapshot]
	writeMu sync.Mutex
}

// Len returns the number of cached groups.
func (c *groupsCache) Len() int {
	snap := c.snap.Load()
	if snap == nil {
		return 0
	}
	return len(snap.groups)
}

// Get returns the cached record for id, or nil if id names no known group.
// Callers must not mutate the returned record.
func (c *groupsCache) Get(id string) *GroupRecord {
	snap := c.snap.Load()
	if snap == nil {
		return nil
	}
	return snap.groups[id]
}

// replace atomically swaps the entire group set. Cold start (load every
// group from the authoritative store once at relay construction) goes
// through this.
func (c *groupsCache) replace(records []*GroupRecord) {
	next := &groupSnapshot{groups: make(map[string]*GroupRecord, len(records))}
	for _, rec := range records {
		next.groups[rec.ID] = rec
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.snap.Store(next)
}

// put copy-on-writes rec into the group set, keyed by rec.ID -- an insert
// if rec.ID is new, an overwrite (a role/metadata/pins change) if not.
// writeMu is held across the copy so concurrent put/remove/replace calls
// serialize against each other -- readers are never blocked by it, since
// they only ever touch snap.Load().
func (c *groupsCache) put(rec *GroupRecord) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	cur := c.snap.Load()
	size := 0
	if cur != nil {
		size = len(cur.groups)
	}
	next := &groupSnapshot{groups: make(map[string]*GroupRecord, size+1)}
	if cur != nil {
		for k, v := range cur.groups {
			next.groups[k] = v
		}
	}
	next.groups[rec.ID] = rec
	c.snap.Store(next)
}

// remove copy-on-writes id out of the group set.
func (c *groupsCache) remove(id string) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	cur := c.snap.Load()
	if cur == nil {
		return
	}
	if _, ok := cur.groups[id]; !ok {
		return
	}
	next := &groupSnapshot{groups: make(map[string]*GroupRecord, len(cur.groups)-1)}
	for k, v := range cur.groups {
		if k != id {
			next.groups[k] = v
		}
	}
	c.snap.Store(next)
}

// defaultGroupModerationPolicy is nmilat's own answer to the question NIP-29
// deliberately leaves to each relay ("which role may perform which
// moderation action is specific to each relay and not specified here"): a
// single "admin" role holds every moderation permission this build
// implements. GroupsService.SetModerationPolicy lets an embedder replace
// this with a richer, multi-role policy without touching relay/groups.go.
var defaultGroupModerationPolicy = nip29.ModerationPolicy{
	"admin": {
		nip29.KindPutUser,
		nip29.KindRemoveUser,
		nip29.KindEditMetadata,
		nip29.KindDeleteEvent,
		nip29.KindDeleteGroup,
		nip29.KindCreateInvite,
		nip29.KindUpdatePinList,
	},
}

// GroupsService resolves NIP-29 group existence/roster/visibility status
// and owns keeping the in-memory cache in sync with the authoritative
// store. A nil *GroupsService is a valid, common case -- NIP-29 group
// hosting not configured on this relay -- and every method reports the
// "doesn't exist"/no-op answer unconditionally, so call sites never need
// their own nil check.
type GroupsService struct {
	store *EventStore
	cache groupsCache

	// policy is an atomic.Pointer, not a plain field, so a live
	// SetModerationPolicy call (an embedder reconfiguring roles) can never
	// data-race against CanPerform reading it from a concurrent request --
	// the same reasoning groupsCache's own snap field documents.
	policy atomic.Pointer[nip29.ModerationPolicy]

	// relayAdmins hold every moderation permission in every hosted group,
	// whatever its roster says: NIP-29 expects moderation events "sent by
	// the relay master key or by group admins". Set by SetRelayAdmins.
	relayAdmins atomic.Pointer[map[string]bool]

	// authorizer, when set, grants a moderation kind beyond the policy;
	// see SetAuthorizer.
	authorizer atomic.Pointer[groupAuthorizer]

	// grantCeiling, when set, keeps role changes within the sender's own
	// powers; see SetGrantCeiling.
	grantCeiling atomic.Bool

	// memberNotices, when set, are the kinds of the seat notices the
	// relay signs; see SetMemberNotices.
	memberNotices atomic.Pointer[MemberNoticeKinds]

	// moderationLog, when set, stores accepted moderation events so
	// clients can read a group's log; see SetModerationLog.
	moderationLog atomic.Bool

	// pendingJoins, when set, keeps a closed group's codeless join
	// requests for its admins; see SetPendingJoins.
	pendingJoins atomic.Bool

	// roleDescriptions describe the policy's roles in kind:39003; see
	// SetRoleDescriptions.
	roleDescriptions atomic.Pointer[map[string]string]

	// signer is the relay identity GroupsService signs kind:39003 with
	// outside a session (a policy change, startup); see setSigner.
	signer atomic.Pointer[groupsSigner]

	// mu serializes every change to hosted groups: each mutator's
	// read-modify-write of a record, and each moderation event's checks
	// together with the change they allow (handle holds it across the
	// whole handler), including the multi-record sequences of a NIP-29
	// reparent (the group, its old parent, its new parent) and a delete's
	// cascade over its children. Without it two concurrent roster changes
	// each copy the same record and the later write drops the earlier's
	// member, and a write racing a group's deletion recreates it. Group
	// writes already queue on the store's single write transaction, so one
	// lock for every group costs no throughput; readers never take it.
	mu sync.Mutex
}

// Count returns the number of hosted groups, from the in-memory cache.
func (g *GroupsService) Count() int {
	if g == nil {
		return 0
	}
	return g.cache.Len()
}

// NewGroupsService constructs a GroupsService backed by store, using
// defaultGroupModerationPolicy. Call LoadFromStore once, at relay
// construction, to pre-populate the in-memory cache before serving traffic.
func NewGroupsService(store *EventStore) *GroupsService {
	g := &GroupsService{store: store}
	g.policy.Store(&defaultGroupModerationPolicy)
	return g
}

// SetModerationPolicy replaces the policy CanPerform consults, and
// republishes every hosted group's kind:39003 to match. A no-op on a nil
// *GroupsService.
func (g *GroupsService) SetModerationPolicy(policy nip29.ModerationPolicy) {
	if g == nil {
		return
	}
	g.policy.Store(&policy)
	g.publishAllRoles(context.Background())
}

// SetModerationLog turns the moderation log on or off. On, every accepted
// moderation event except a group's deletion (kinds 9000-9020) is stored,
// readable by the group's members; an invite (9009) only by those
// CanPerform allows kind 9009. Off, the default, they are commands and
// nothing is kept. A deleted group's log goes with its other events.
func (g *GroupsService) SetModerationLog(on bool) {
	if g == nil {
		return
	}
	g.moderationLog.Store(on)
}

// SetPendingJoins turns pending join requests on or off. On, a closed
// group's join request without an invite code is stored instead of
// refused, readable by the requester and those CanPerform allows kind
// 9000 or 9001, until an admin answers it with kind:9000 (accept) or
// kind:9001 (decline), the requester joins another way or leaves, or an
// admin deletes it (9005).
// Off, the default, such a request is refused.
func (g *GroupsService) SetPendingJoins(on bool) {
	if g == nil {
		return
	}
	g.pendingJoins.Store(on)
}

// SetRoleDescriptions sets the description each role gets in kind:39003
// (role name -> text) and republishes every hosted group's. A role with
// no description is described by the actions the policy lets it take.
func (g *GroupsService) SetRoleDescriptions(descriptions map[string]string) {
	if g == nil {
		return
	}
	d := make(map[string]string, len(descriptions))
	for k, v := range descriptions {
		d[k] = v
	}
	g.roleDescriptions.Store(&d)
	g.publishAllRoles(context.Background())
}

// Roles returns the roles this relay advertises in kind:39003: the
// moderation policy's role names, sorted, with their descriptions.
func (g *GroupsService) Roles() []nip29.GroupRole {
	if g == nil {
		return nil
	}
	policy := g.policy.Load()
	if policy == nil {
		return nil
	}
	var desc map[string]string
	if d := g.roleDescriptions.Load(); d != nil {
		desc = *d
	}
	return policy.Roles(desc)
}

// SetRelayAdmins replaces the keys that act as admin of every hosted
// group: the relay's own key (NewSessionHandler passes NIP-11 "self"), plus
// any operator keys an embedder adds. They can moderate any group, e.g.
// recover one whose admins are gone, without holding a roster entry.
func (g *GroupsService) SetRelayAdmins(pubkeys ...string) {
	if g == nil {
		return
	}
	set := make(map[string]bool, len(pubkeys))
	for _, pk := range pubkeys {
		if pk != "" {
			set[strings.ToLower(pk)] = true
		}
	}
	g.relayAdmins.Store(&set)
}

// isRelayAdmin reports whether pubkey is one of SetRelayAdmins' keys.
func (g *GroupsService) isRelayAdmin(pubkey string) bool {
	set := g.relayAdmins.Load()
	return set != nil && (*set)[strings.ToLower(pubkey)]
}

// LoadFromStore populates the in-memory cache from the authoritative
// store -- called once at relay construction (cold start), not on any
// request path.
func (g *GroupsService) LoadFromStore() error {
	if g == nil {
		return nil
	}
	records, err := g.store.ListGroups()
	if err != nil {
		return err
	}
	g.cache.replace(records)
	return nil
}

// Exists reports whether id names a currently-hosted group.
func (g *GroupsService) Exists(id string) bool {
	if g == nil {
		return false
	}
	return g.cache.Get(id) != nil
}

// IsAdmin reports whether pubkey holds at least one role in group id, or
// is a relay admin (SetRelayAdmins) and id is hosted here.
func (g *GroupsService) IsAdmin(id, pubkey string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && (rec.IsAdmin(pubkey) || g.isRelayAdmin(pubkey))
}

// IsMember reports whether pubkey holds a roster entry in group id.
func (g *GroupsService) IsMember(id, pubkey string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.IsMember(pubkey)
}

// groupAuthorizer is the function SetAuthorizer installs.
type groupAuthorizer func(groupID, pubkey string, kind int) bool

// SetAuthorizer installs a host's own answer to "may pubkey perform a
// moderation action of kind in group groupID", consulted by CanPerform
// after the relay admins and the ModerationPolicy -- e.g. relay-wide roles
// that carry NIP-29 powers in every hosted group. It can only grant, never
// take away what the policy allows. nil removes it. A no-op on a nil
// *GroupsService.
func (g *GroupsService) SetAuthorizer(fn func(groupID, pubkey string, kind int) bool) {
	if g == nil {
		return
	}
	if fn == nil {
		g.authorizer.Store(nil)
		return
	}
	a := groupAuthorizer(fn)
	g.authorizer.Store(&a)
}

// SetGrantCeiling turns the grant ceiling on or off. On, a kind:9000 may
// only give a member roles whose every kind the sender may perform itself,
// and may only take roles from -- like a kind:9001 may only remove -- a
// member holding no moderation kind the sender lacks. Holding a kind means
// CanPerform, so a relay admin, or a key holding every kind, is never
// limited, and the creator's "admin" role can be given or taken only by
// someone holding all of its kinds. Off, the default, anyone allowed
// kind:9000/9001 may give or take any role.
func (g *GroupsService) SetGrantCeiling(on bool) {
	if g == nil {
		return
	}
	g.grantCeiling.Store(on)
}

// CanPerform reports whether pubkey may perform a moderation action of kind
// in group id: a relay admin (SetRelayAdmins) may perform any action in
// any hosted group; anyone else needs one of their own roles to allow it
// per GroupsService's ModerationPolicy, or the host's authorizer
// (SetAuthorizer) to. A pubkey with no roster entry, or holding no roles,
// gets nothing from the policy -- AllowsAny(nil, kind) is always false.
func (g *GroupsService) CanPerform(id, pubkey string, kind int) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	if rec == nil {
		return false
	}
	if g.isRelayAdmin(pubkey) {
		return true
	}
	if policy := g.policy.Load(); policy != nil && policy.AllowsAny(rec.RolesFor(pubkey), kind) {
		return true
	}
	if a := g.authorizer.Load(); a != nil && (*a)(id, pubkey, kind) {
		return true
	}
	return false
}

// moderationKinds returns every kind a pubkey could hold: the moderation
// kinds this build implements plus any other the policy names.
func (g *GroupsService) moderationKinds() []int {
	seen := map[int]bool{}
	var kinds []int
	add := func(ks []int) {
		for _, k := range ks {
			if !seen[k] {
				seen[k] = true
				kinds = append(kinds, k)
			}
		}
	}
	add(defaultGroupModerationPolicy["admin"])
	if policy := g.policy.Load(); policy != nil {
		for _, ks := range *policy {
			add(ks)
		}
	}
	return kinds
}

// outranks reports whether target holds a moderation kind in group id that
// sender doesn't.
func (g *GroupsService) outranks(id, target, sender string) bool {
	for _, k := range g.moderationKinds() {
		if g.CanPerform(id, target, k) && !g.CanPerform(id, sender, k) {
			return true
		}
	}
	return false
}

// grantCeilingPutUser returns why the grant ceiling refuses sender's
// kind:9000 setting target's roles in group id to roles, or "" if it
// allows it (or is off). A role target already holds is not a grant; one
// it loses is taken.
func (g *GroupsService) grantCeilingPutUser(id, sender, target string, roles []string) string {
	if !g.grantCeiling.Load() {
		return ""
	}
	rec := g.cache.Get(id)
	if rec == nil {
		return ""
	}
	current := rec.RolesFor(target)
	var policy nip29.ModerationPolicy
	if p := g.policy.Load(); p != nil {
		policy = *p
	}
	for _, role := range roles {
		if slices.Contains(current, role) {
			continue
		}
		for _, k := range policy[role] {
			if !g.CanPerform(id, sender, k) {
				return "restricted: you may not grant a role with powers you do not hold."
			}
		}
	}
	for _, role := range current {
		if !slices.Contains(roles, role) && g.outranks(id, target, sender) {
			return "restricted: you may not take roles from a member with powers you do not hold."
		}
	}
	return ""
}

// grantCeilingRemoveUser returns why the grant ceiling refuses sender's
// kind:9001 removing target from group id, or "" if it allows it (or is
// off).
func (g *GroupsService) grantCeilingRemoveUser(id, sender, target string) string {
	if !g.grantCeiling.Load() || !g.IsMember(id, target) {
		return ""
	}
	if g.outranks(id, target, sender) {
		return "restricted: you may not remove a member with powers you do not hold."
	}
	return ""
}

// hasPrivilege reports whether any of roles may perform at least one
// moderation action under the policy -- who kind:39001 lists.
func (g *GroupsService) hasPrivilege(roles []string) bool {
	policy := g.policy.Load()
	if policy == nil {
		return false
	}
	for _, role := range roles {
		if len((*policy)[role]) > 0 {
			return true
		}
	}
	return false
}

// IsPrivate reports whether id names a currently-hosted group whose
// metadata marks it private. An id naming no known group is not private --
// there is nothing to protect behind an id with no group behind it, so the
// REQ-time visibility gate (relay/packet.go) has nothing to enforce for it.
func (g *GroupsService) IsPrivate(id string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.Metadata.Private
}

// IsClosed reports whether id names a currently-hosted group whose
// metadata marks it closed -- gating kind:9021 join (relay/groups.go), not
// REQ-time visibility (that's IsPrivate's job; decision 2 in
// docs/specs/nip29-groups-plan.md is explicit that closed-vs-open only
// gates join, not read).
func (g *GroupsService) IsClosed(id string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.Metadata.Closed
}

// IsRestricted reports whether id names a currently-hosted group whose
// metadata marks it restricted: only members may post in it.
func (g *GroupsService) IsRestricted(id string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.Metadata.Restricted
}

// IsHidden reports whether id names a currently-hosted group whose metadata
// marks it hidden: its metadata events (kind 39000-39005) are for members
// only, while its content stays as readable as "private" allows.
func (g *GroupsService) IsHidden(id string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.Metadata.Hidden
}

// Create persists a freshly created group and updates the in-memory cache.
// Callers (GroupsService.HandleEvent's kind:9007 path) are responsible for
// checking Exists first; Create itself does not guard against overwriting
// an existing record.
func (g *GroupsService) Create(rec *GroupRecord) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.createLocked(rec)
}

func (g *GroupsService) createLocked(rec *GroupRecord) error {
	if err := g.store.PutGroup(rec); err != nil {
		return err
	}
	g.cache.put(rec)
	return nil
}

// Delete removes group id from the authoritative store and the in-memory
// cache, returning the record as it stood immediately before deletion (or
// (nil, nil) if id named no known group) so a caller that needs to act on
// what the group last contained -- NIP-29 subgroup cascade-to-root reads
// the deleted parent's own Children here -- gets it atomically, rather
// than racing a second read against a concurrent second delete.
func (g *GroupsService) Delete(id string) (*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.deleteLocked(id)
}

func (g *GroupsService) deleteLocked(id string) (*GroupRecord, error) {
	rec := g.cache.Get(id)
	if err := g.store.DeleteGroup(id); err != nil {
		return nil, err
	}
	g.cache.remove(id)
	return rec, nil
}

// Get returns id's persisted record, or (nil, nil) if id is not a
// currently-hosted group. Used by a future `ncli relay groups show`, not
// the request hot path.
func (g *GroupsService) Get(id string) (*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	return g.store.GetGroup(id)
}

// List returns every currently-hosted group's full persisted record. Used
// by a future `ncli relay groups list`, not the request hot path.
func (g *GroupsService) List() ([]*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	return g.store.ListGroups()
}

// updateLocked is every single-record mutator's read-modify-write: it
// reads group id's current record, builds the next one with change, and
// stores it. g.mu must be held, so no concurrent change to the group is
// lost and a group deleted meanwhile stays deleted. Returns (nil, nil) if
// id names no known group.
func (g *GroupsService) updateLocked(id string, change func(*GroupRecord) *GroupRecord) (*GroupRecord, error) {
	cur := g.cache.Get(id)
	if cur == nil {
		return nil, nil
	}
	next := change(cur)
	if err := g.store.PutGroup(next); err != nil {
		return nil, err
	}
	g.cache.put(next)
	return next, nil
}

// update is updateLocked taking g.mu itself, for the exported mutators.
func (g *GroupsService) update(id string, change func(*GroupRecord) *GroupRecord) (*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.updateLocked(id, change)
}

// UpsertMember adds member to group id's roster, or replaces its existing
// entry if member.Pubkey already holds one (kind:9000 put-user). Returns
// the updated record, or (nil, nil) if id names no known group.
func (g *GroupsService) UpsertMember(id string, member GroupMember) (*GroupRecord, error) {
	return g.update(id, withMember(member))
}

func (g *GroupsService) upsertMemberLocked(id string, member GroupMember) (*GroupRecord, error) {
	return g.updateLocked(id, withMember(member))
}

func withMember(member GroupMember) func(*GroupRecord) *GroupRecord {
	return func(cur *GroupRecord) *GroupRecord { return cur.withMember(member) }
}

// RemoveMember removes pubkey's roster entry from group id (kind:9001
// remove-user, or a kind:9022 self-leave). Returns the updated record, or
// (nil, nil) if id names no known group.
func (g *GroupsService) RemoveMember(id, pubkey string) (*GroupRecord, error) {
	return g.update(id, withoutMember(pubkey))
}

func (g *GroupsService) removeMemberLocked(id, pubkey string) (*GroupRecord, error) {
	return g.updateLocked(id, withoutMember(pubkey))
}

func withoutMember(pubkey string) func(*GroupRecord) *GroupRecord {
	return func(cur *GroupRecord) *GroupRecord { return cur.withoutMember(pubkey) }
}

// SetMetadata replaces group id's metadata wholesale (kind:9002
// edit-metadata submits the complete desired state, the same "absolute"
// convention kind:9010's pin list uses). Returns the updated record, or
// (nil, nil) if id names no known group.
func (g *GroupsService) SetMetadata(id string, fields GroupMetadataFields) (*GroupRecord, error) {
	return g.update(id, withMetadata(fields))
}

func (g *GroupsService) setMetadataLocked(id string, fields GroupMetadataFields) (*GroupRecord, error) {
	return g.updateLocked(id, withMetadata(fields))
}

func withMetadata(fields GroupMetadataFields) func(*GroupRecord) *GroupRecord {
	return func(cur *GroupRecord) *GroupRecord {
		next := *cur
		next.Metadata = fields
		return &next
	}
}

// SetPins replaces group id's pinned list wholesale (kind:9010). Returns
// the updated record, or (nil, nil) if id names no known group.
func (g *GroupsService) SetPins(id string, pins GroupPins) (*GroupRecord, error) {
	return g.update(id, withPins(pins))
}

func (g *GroupsService) setPinsLocked(id string, pins GroupPins) (*GroupRecord, error) {
	return g.updateLocked(id, withPins(pins))
}

func withPins(pins GroupPins) func(*GroupRecord) *GroupRecord {
	return func(cur *GroupRecord) *GroupRecord {
		next := *cur
		next.Pins = pins
		return &next
	}
}

// SetChildren replaces group id's ordered subgroup-id list wholesale
// (kind:9002 edit-metadata's "parent reorders its own children" path).
// Returns the updated record, or (nil, nil) if id names no known group.
//
// Deliberately a dedicated mutator, not routed through SetMetadata:
// SetMetadata replaces the *entire* Metadata struct, so building a bare
// GroupMetadataFields{Children: children} and passing it there would
// silently wipe Name/Private/Closed/every other field on the group
// being updated -- exactly the footgun this helper exists to make
// structurally impossible.
func (g *GroupsService) SetChildren(id string, children []string) (*GroupRecord, error) {
	return g.update(id, withChildren(children))
}

func (g *GroupsService) setChildrenLocked(id string, children []string) (*GroupRecord, error) {
	return g.updateLocked(id, withChildren(children))
}

func withChildren(children []string) func(*GroupRecord) *GroupRecord {
	return func(cur *GroupRecord) *GroupRecord {
		next := *cur
		next.Metadata.Children = children
		return &next
	}
}

// SetParent replaces group id's own parent reference (empty string
// detaches to root). Returns the updated record, or (nil, nil) if id
// names no known group. Same rationale as SetChildren: a dedicated
// single-field mutator so a reparent or a delete-cascade can't
// accidentally wipe the rest of the group's metadata.
func (g *GroupsService) SetParent(id string, parent string) (*GroupRecord, error) {
	return g.update(id, withParent(parent))
}

func (g *GroupsService) setParentLocked(id string, parent string) (*GroupRecord, error) {
	return g.updateLocked(id, withParent(parent))
}

func withParent(parent string) func(*GroupRecord) *GroupRecord {
	return func(cur *GroupRecord) *GroupRecord {
		next := *cur
		next.Metadata.Parent = parent
		return &next
	}
}

// removeChild drops childID from parentID's Children list, if present.
// Returns the updated parent record, or (nil, nil) if parentID names no
// known group. g.mu must be held.
func (g *GroupsService) removeChild(parentID, childID string) (*GroupRecord, error) {
	return g.updateLocked(parentID, func(cur *GroupRecord) *GroupRecord {
		children := make([]string, 0, len(cur.Metadata.Children))
		for _, id := range cur.Metadata.Children {
			if id != childID {
				children = append(children, id)
			}
		}
		return withChildren(children)(cur)
	})
}

// addChild appends childID to parentID's Children list. Returns the
// updated parent record, or (nil, nil) if parentID names no known group.
// Callers are responsible for not calling this with a childID already
// present (handleEditMetadata's own validation is what actually decides
// whether an addition is allowed at all). g.mu must be held.
func (g *GroupsService) addChild(parentID, childID string) (*GroupRecord, error) {
	return g.updateLocked(parentID, func(cur *GroupRecord) *GroupRecord {
		return withChildren(append(append([]string{}, cur.Metadata.Children...), childID))(cur)
	})
}

// createsCycle reports whether setting groupID's parent to startParent
// would create a cycle in the parent chain -- including startParent
// itself eventually leading back to groupID. Walks via a visited-set,
// not a bounded counter, so it always terminates in O(chain length)
// even against a pre-existing cycle elsewhere that doesn't involve
// groupID at all.
func (g *GroupsService) createsCycle(startParent, groupID string) bool {
	visited := map[string]bool{}
	current := startParent
	for current != "" {
		if current == groupID {
			return true
		}
		if visited[current] {
			return false
		}
		visited[current] = true
		rec := g.cache.Get(current)
		if rec == nil {
			return false
		}
		current = rec.Metadata.Parent
	}
	return false
}

// newGroupRecord builds the GroupRecord a kind:9007 creates: creator as
// sole admin (role "admin", matching defaultGroupModerationPolicy) and
// member, private+closed per decision 2 in
// docs/specs/nip29-groups-plan.md.
func newGroupRecord(id, creator string) *GroupRecord {
	return &GroupRecord{
		ID:        id,
		Metadata:  GroupMetadataFields{Private: true, Closed: true},
		Members:   []GroupMember{{Pubkey: creator, Roles: []string{"admin"}}},
		CreatedAt: time.Now().Unix(),
	}
}

// groupsSigner is the relay identity relay-authored group events are
// signed with.
type groupsSigner struct {
	pubkey, privkey string
}

// setSigner gives GroupsService the relay's own key, so it can publish
// kind:39003 without a session. NewSessionHandler calls it; without it
// roles are published only from a session (on group creation).
func (g *GroupsService) setSigner(pubkey, privkey string) {
	if g == nil || pubkey == "" || privkey == "" {
		return
	}
	g.signer.Store(&groupsSigner{pubkey: pubkey, privkey: privkey})
}

// groupRolesEvent builds group id's unsigned kind:39003 from the current
// policy.
func (g *GroupsService) groupRolesEvent(selfPubkey, id string) *nip01.Event {
	return nip29.NewGroupRoles(nip29.GroupRolesParams{SelfPubkey: selfPubkey, ID: id, Roles: g.Roles()})
}

// publishRoles signs and stores group id's kind:39003, unless the stored
// one already lists the same roles. Its created_at is strictly newer than
// the stored one's, so a same-second republish can't lose the tie.
func (g *GroupsService) publishRoles(ctx context.Context, pubkey, privkey, id string) {
	ev := g.groupRolesEvent(pubkey, id)
	prev, err := g.store.QueryEvents(ctx, &nip01.SubscriptionFilter{
		Kinds: []int{nip29.KindGroupRoles}, Authors: []string{pubkey}, Tags: map[string][]string{"d": {id}}, Limit: 1,
	})
	if err == nil && len(prev) == 1 {
		if tagsEqual(prev[0].Tags, ev.Tags) {
			return
		}
		if ev.CreatedAt <= prev[0].CreatedAt {
			ev.CreatedAt = prev[0].CreatedAt + 1
		}
	}
	if err := ev.Sign(privkey); err != nil {
		return
	}
	_ = g.store.InsertEvents(ctx, []*nip01.Event{ev})
}

// publishAllRoles republishes every hosted group's kind:39003 with the
// signer from setSigner; a no-op until one is set.
func (g *GroupsService) publishAllRoles(ctx context.Context) {
	sg := g.signer.Load()
	if sg == nil {
		return
	}
	snap := g.cache.snap.Load()
	if snap == nil {
		return
	}
	for id := range snap.groups {
		g.publishRoles(ctx, sg.pubkey, sg.privkey, id)
	}
}

func tagsEqual(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
