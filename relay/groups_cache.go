package relay

import (
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

	// linkMu serializes NIP-29 "Subgroups" cross-group mutation: a
	// reparent touches up to three records (the group itself, its old
	// parent, its new parent), and a delete cascades over every one of
	// the deleted group's own children. groupsCache's own writeMu keeps
	// each *individual* Get/put memory-safe, but gives no atomicity
	// across that multi-record sequence -- two concurrent reparents of
	// the same child to two different new parents could otherwise both
	// successfully addChild on their own target, leaving the "losing"
	// parent's Children listing a child whose own Parent no longer
	// points back at it. Held for the whole validate-then-mutate
	// sequence in handleEditMetadata's reparent path and
	// handleDeleteGroup's cascade, never for a same-group-only edit
	// (which groupsCache's own synchronization already covers alone).
	linkMu sync.Mutex
}

// NewGroupsService constructs a GroupsService backed by store, using
// defaultGroupModerationPolicy. Call LoadFromStore once, at relay
// construction, to pre-populate the in-memory cache before serving traffic.
func NewGroupsService(store *EventStore) *GroupsService {
	g := &GroupsService{store: store}
	g.policy.Store(&defaultGroupModerationPolicy)
	return g
}

// SetModerationPolicy replaces the policy CanPerform consults. A no-op on
// a nil *GroupsService.
func (g *GroupsService) SetModerationPolicy(policy nip29.ModerationPolicy) {
	if g == nil {
		return
	}
	g.policy.Store(&policy)
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

// IsAdmin reports whether pubkey holds at least one role in group id.
func (g *GroupsService) IsAdmin(id, pubkey string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.IsAdmin(pubkey)
}

// IsMember reports whether pubkey holds a roster entry in group id.
func (g *GroupsService) IsMember(id, pubkey string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.IsMember(pubkey)
}

// CanPerform reports whether pubkey's own roles in group id let it perform
// a moderation action of kind, per GroupsService's ModerationPolicy. A
// pubkey with no roster entry, or holding no roles, can never perform any
// moderation action -- AllowsAny(nil, kind) is always false.
func (g *GroupsService) CanPerform(id, pubkey string, kind int) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	if rec == nil {
		return false
	}
	policy := g.policy.Load()
	if policy == nil {
		return false
	}
	return policy.AllowsAny(rec.RolesFor(pubkey), kind)
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

// Create persists a freshly created group and updates the in-memory cache.
// Callers (GroupsService.HandleEvent's kind:9007 path) are responsible for
// checking Exists first; Create itself does not guard against overwriting
// an existing record.
func (g *GroupsService) Create(rec *GroupRecord) error {
	if g == nil {
		return nil
	}
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

// UpsertMember adds member to group id's roster, or replaces its existing
// entry if member.Pubkey already holds one (kind:9000 put-user). Returns
// the updated record, or (nil, nil) if id names no known group.
func (g *GroupsService) UpsertMember(id string, member GroupMember) (*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	cur := g.cache.Get(id)
	if cur == nil {
		return nil, nil
	}
	next := cur.withMember(member)
	if err := g.store.PutGroup(next); err != nil {
		return nil, err
	}
	g.cache.put(next)
	return next, nil
}

// RemoveMember removes pubkey's roster entry from group id (kind:9001
// remove-user, or a kind:9022 self-leave). Returns the updated record, or
// (nil, nil) if id names no known group.
func (g *GroupsService) RemoveMember(id, pubkey string) (*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	cur := g.cache.Get(id)
	if cur == nil {
		return nil, nil
	}
	next := cur.withoutMember(pubkey)
	if err := g.store.PutGroup(next); err != nil {
		return nil, err
	}
	g.cache.put(next)
	return next, nil
}

// SetMetadata replaces group id's metadata wholesale (kind:9002
// edit-metadata submits the complete desired state, the same "absolute"
// convention kind:9010's pin list uses). Returns the updated record, or
// (nil, nil) if id names no known group.
func (g *GroupsService) SetMetadata(id string, fields GroupMetadataFields) (*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	cur := g.cache.Get(id)
	if cur == nil {
		return nil, nil
	}
	next := *cur
	next.Metadata = fields
	if err := g.store.PutGroup(&next); err != nil {
		return nil, err
	}
	g.cache.put(&next)
	return &next, nil
}

// SetPins replaces group id's pinned list wholesale (kind:9010). Returns
// the updated record, or (nil, nil) if id names no known group.
func (g *GroupsService) SetPins(id string, pins GroupPins) (*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	cur := g.cache.Get(id)
	if cur == nil {
		return nil, nil
	}
	next := *cur
	next.Pins = pins
	if err := g.store.PutGroup(&next); err != nil {
		return nil, err
	}
	g.cache.put(&next)
	return &next, nil
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
	if g == nil {
		return nil, nil
	}
	cur := g.cache.Get(id)
	if cur == nil {
		return nil, nil
	}
	next := *cur
	next.Metadata.Children = children
	if err := g.store.PutGroup(&next); err != nil {
		return nil, err
	}
	g.cache.put(&next)
	return &next, nil
}

// SetParent replaces group id's own parent reference (empty string
// detaches to root). Returns the updated record, or (nil, nil) if id
// names no known group. Same rationale as SetChildren: a dedicated
// single-field mutator so a reparent or a delete-cascade can't
// accidentally wipe the rest of the group's metadata.
func (g *GroupsService) SetParent(id string, parent string) (*GroupRecord, error) {
	if g == nil {
		return nil, nil
	}
	cur := g.cache.Get(id)
	if cur == nil {
		return nil, nil
	}
	next := *cur
	next.Metadata.Parent = parent
	if err := g.store.PutGroup(&next); err != nil {
		return nil, err
	}
	g.cache.put(&next)
	return &next, nil
}

// removeChild drops childID from parentID's Children list, if present.
// Returns the updated parent record, or (nil, nil) if parentID names no
// known group.
func (g *GroupsService) removeChild(parentID, childID string) (*GroupRecord, error) {
	parent := g.cache.Get(parentID)
	if parent == nil {
		return nil, nil
	}
	children := make([]string, 0, len(parent.Metadata.Children))
	for _, id := range parent.Metadata.Children {
		if id != childID {
			children = append(children, id)
		}
	}
	return g.SetChildren(parentID, children)
}

// addChild appends childID to parentID's Children list. Returns the
// updated parent record, or (nil, nil) if parentID names no known group.
// Callers are responsible for not calling this with a childID already
// present (handleEditMetadata's own validation is what actually decides
// whether an addition is allowed at all).
func (g *GroupsService) addChild(parentID, childID string) (*GroupRecord, error) {
	parent := g.cache.Get(parentID)
	if parent == nil {
		return nil, nil
	}
	children := append(append([]string{}, parent.Metadata.Children...), childID)
	return g.SetChildren(parentID, children)
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
