package relay

import (
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip43"
)

// membershipSnapshot is an immutable point-in-time view of the NIP-43
// member set. Immutability is what makes atomic.Pointer swaps safe:
// readers that loaded a snapshot before a swap keep observing it
// consistently, never a partially-mutated map.
type membershipSnapshot struct {
	members map[[32]byte]struct{}
}

// membershipCache is an O(1), lock-light-for-readers membership lookup.
// Reads use atomic.Pointer.Load, not an RWMutex: RLock still touches a
// shared reader-count word under a CAS, which becomes a real contention
// point at high concurrent AUTH throughput across many connections/cores,
// whereas an atomic load touches no shared mutable word other readers
// contend on. Writes (join/leave/cold-start/manual-republish, a later
// phase) are rare by comparison, so paying a full copy-on-write there,
// serialized by writeMu, is the right trade -- see add/remove/replace.
//
// A dedicated authoritative store (relay/store_membership.go, a later
// phase) owns actually persisting membership state; this type only ever
// holds a fast in-memory mirror of it.
type membershipCache struct {
	snap    atomic.Pointer[membershipSnapshot]
	writeMu sync.Mutex
}

// decodePubkey decodes a hex pubkey into a fixed 32-byte array key,
// entirely on the stack -- no allocation, and never panics on malformed
// input, so hot-path callers don't need their own pre-validation just to
// call IsMember safely.
func decodePubkey(pubkeyHex string) (key [32]byte, ok bool) {
	if len(pubkeyHex) != 64 {
		return key, false
	}
	if _, err := hex.Decode(key[:], []byte(pubkeyHex)); err != nil {
		return key, false
	}
	return key, true
}

// IsMember reports whether pubkeyHex is a current member. Malformed input
// is never a member.
func (c *membershipCache) IsMember(pubkeyHex string) bool {
	key, ok := decodePubkey(pubkeyHex)
	if !ok {
		return false
	}
	snap := c.snap.Load()
	if snap == nil {
		return false
	}
	_, isMember := snap.members[key]
	return isMember
}

// replace atomically swaps the entire member set. Cold start (load every
// member from the authoritative store once at relay construction) and the
// belt-and-suspenders resync when an operator manually republishes a raw
// kind:13534 event (both a later phase) go through this. Malformed entries
// in pubkeys are silently skipped, not fatal to the whole replace.
func (c *membershipCache) replace(pubkeys []string) {
	next := &membershipSnapshot{members: make(map[[32]byte]struct{}, len(pubkeys))}
	for _, pk := range pubkeys {
		if key, ok := decodePubkey(pk); ok {
			next.members[key] = struct{}{}
		}
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.snap.Store(next)
}

// add copy-on-writes pubkeyHex into the member set. A no-op if pubkeyHex is
// malformed. writeMu is held across the copy so concurrent add/remove/
// replace calls serialize against each other -- readers are never blocked
// by it, since they only ever touch snap.Load().
func (c *membershipCache) add(pubkeyHex string) {
	key, ok := decodePubkey(pubkeyHex)
	if !ok {
		return
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	cur := c.snap.Load()
	size := 0
	if cur != nil {
		size = len(cur.members)
	}
	next := &membershipSnapshot{members: make(map[[32]byte]struct{}, size+1)}
	if cur != nil {
		for k := range cur.members {
			next.members[k] = struct{}{}
		}
	}
	next.members[key] = struct{}{}
	c.snap.Store(next)
}

// remove copy-on-writes pubkeyHex out of the member set.
func (c *membershipCache) remove(pubkeyHex string) {
	key, ok := decodePubkey(pubkeyHex)
	if !ok {
		return
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	cur := c.snap.Load()
	if cur == nil {
		return
	}
	if _, isMember := cur.members[key]; !isMember {
		return
	}
	next := &membershipSnapshot{members: make(map[[32]byte]struct{}, len(cur.members)-1)}
	for k := range cur.members {
		if k != key {
			next.members[k] = struct{}{}
		}
	}
	c.snap.Store(next)
}

// MembershipService resolves NIP-43 membership status for a pubkey and
// owns keeping the in-memory cache in sync with the authoritative store.
// A nil *MembershipService is a valid, common case -- NIP-43 not
// configured on this relay -- and every method reports the "not a
// member"/no-op answer unconditionally, so call sites never need their
// own nil check.
type MembershipService struct {
	store *EventStore
	cache membershipCache
}

// NewMembershipService constructs a MembershipService backed by store.
// Call LoadFromStore once, at relay construction, to pre-populate the
// in-memory cache before serving traffic.
func NewMembershipService(store *EventStore) *MembershipService {
	return &MembershipService{store: store}
}

// LoadFromStore populates the in-memory cache from the authoritative
// store -- called once at relay construction (cold start), not on any
// request path.
func (m *MembershipService) LoadFromStore() error {
	if m == nil {
		return nil
	}
	pubkeys, err := m.store.ListMembers()
	if err != nil {
		return err
	}
	m.cache.replace(pubkeys)
	return nil
}

// IsMember reports whether pubkey is a current, direct/active NIP-43
// member.
func (m *MembershipService) IsMember(pubkey string) bool {
	if m == nil {
		return false
	}
	return m.cache.IsMember(pubkey)
}

// Join enrolls pubkey as a member with the given roles, persisting it to
// the authoritative store and updating the in-memory cache.
func (m *MembershipService) Join(pubkey string, roles []string) error {
	if m == nil {
		return nil
	}
	if err := m.store.PutMember(&MemberRecord{
		Pubkey:   pubkey,
		Roles:    roles,
		JoinedAt: time.Now().Unix(),
	}); err != nil {
		return err
	}
	m.cache.add(pubkey)
	return nil
}

// Leave removes pubkey's membership from the authoritative store and the
// in-memory cache.
func (m *MembershipService) Leave(pubkey string) error {
	if m == nil {
		return nil
	}
	if err := m.store.RemoveMember(pubkey); err != nil {
		return err
	}
	m.cache.remove(pubkey)
	return nil
}

// ReplaceFromEvent re-derives the authoritative member set from a
// manually-published kind:13534 event's member tags -- the
// belt-and-suspenders resync for an operator who publishes a raw
// membership-list event directly instead of going through Join/Leave.
func (m *MembershipService) ReplaceFromEvent(ev *nip01.Event) error {
	if m == nil {
		return nil
	}
	list, err := nip43.ParseMembershipList(ev)
	if err != nil {
		return err
	}
	pubkeys := make([]string, 0, len(list.Members))
	now := time.Now().Unix()
	for _, mem := range list.Members {
		pubkeys = append(pubkeys, mem.Pubkey)
		if err := m.store.PutMember(&MemberRecord{Pubkey: mem.Pubkey, Roles: mem.Roles, JoinedAt: now}); err != nil {
			return err
		}
	}
	m.cache.replace(pubkeys)
	return nil
}
