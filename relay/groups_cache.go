package relay

import (
	"sync"
	"sync/atomic"
	"time"
)

// groupSnapshot is an immutable point-in-time view of the NIP-29 group set,
// keyed by group id. Each *GroupRecord is itself treated as immutable once
// placed in a snapshot -- a mutation always builds a fresh *GroupRecord and
// hands it to put/replace, never edits one returned by Get in place. That
// is what makes a plain shallow copy of the outer map safe for
// add/remove, exactly as membershipSnapshot relies on for its own entries
// (relay/membership_cache.go).
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
// if rec.ID is new, an overwrite (e.g. a future phase's role/membership
// change) if not. writeMu is held across the copy so concurrent
// put/remove/replace calls serialize against each other -- readers are
// never blocked by it, since they only ever touch snap.Load().
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

// GroupsService resolves NIP-29 group existence/admin/membership/visibility
// status and owns keeping the in-memory cache in sync with the
// authoritative store. A nil *GroupsService is a valid, common case --
// NIP-29 group hosting not configured on this relay -- and every method
// reports the "doesn't exist"/no-op answer unconditionally, so call sites
// never need their own nil check.
type GroupsService struct {
	store *EventStore
	cache groupsCache
}

// NewGroupsService constructs a GroupsService backed by store. Call
// LoadFromStore once, at relay construction, to pre-populate the in-memory
// cache before serving traffic.
func NewGroupsService(store *EventStore) *GroupsService {
	return &GroupsService{store: store}
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

// IsAdmin reports whether pubkey holds an admin role in group id.
func (g *GroupsService) IsAdmin(id, pubkey string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.IsAdmin(pubkey)
}

// IsMember reports whether pubkey is a member of group id.
func (g *GroupsService) IsMember(id, pubkey string) bool {
	if g == nil {
		return false
	}
	rec := g.cache.Get(id)
	return rec != nil && rec.IsMember(pubkey)
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
	return rec != nil && rec.Private
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
// cache.
func (g *GroupsService) Delete(id string) error {
	if g == nil {
		return nil
	}
	if err := g.store.DeleteGroup(id); err != nil {
		return err
	}
	g.cache.remove(id)
	return nil
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

// newGroupRecord builds the GroupRecord a Phase 1 kind:9007 creates: creator
// as sole admin and member, private+closed per decision 2 in
// docs/specs/nip29-groups-plan.md (there is no kind:9002 edit-metadata
// handling yet to ever flip Private false, so every group Phase 1 can
// create stays private for its whole lifetime).
func newGroupRecord(id, creator string) *GroupRecord {
	return &GroupRecord{
		ID:        id,
		Admins:    []string{creator},
		Members:   []string{creator},
		Private:   true,
		CreatedAt: time.Now().Unix(),
	}
}
