package relay

import (
	"encoding/json"
	"errors"

	bolt "go.etcd.io/bbolt"
)

// indexGroups is the authoritative NIP-29 group set: one key per group,
// keyed by group id -- not one JSON blob for the whole set, for the same
// reason indexMembers (relay/store_membership.go) is laid out that way: a
// single-blob rewrite on every create/delete would be O(group-count) per
// mutation, whereas individual keys make create/delete O(1). The in-memory
// groupsCache (relay/groups_cache.go) is a fast mirror of this bucket, never
// the other way around.
var indexGroups = []byte{14}

// indexGroupInvites stores NIP-29 group-scoped invite-code state, keyed by
// "<groupID>\x00<code>" -- deliberately separate from NIP-43's own
// indexInviteClaims bucket (relay/store_membership.go), since a kind:9009
// code is only ever valid to join the one group that created it.
var indexGroupInvites = []byte{15}

var (
	ErrGroupInviteNotFound  = errors.New("relay: group invite not found")
	ErrGroupInviteExhausted = errors.New("relay: group invite already used")
)

// GroupMember is one roster entry: a pubkey plus the roles it holds.
// Holding zero roles is an ordinary member; holding at least one role is
// what this package calls an admin (see GroupRecord.IsAdmin) -- which
// specific role names map to which moderation kinds is
// GroupsService.policy's job (nip29.ModerationPolicy), not this type's.
type GroupMember struct {
	Pubkey string   `json:"pubkey"`
	Roles  []string `json:"roles,omitempty"`
}

// GroupMetadataFields is the persisted subset of a NIP-29 group's
// kind:39000 metadata. Private gates the REQ-time visibility check
// (relay/packet.go); Closed gates kind:9021 join (relay/groups.go). The
// rest round-trips for display via kind:39000 only. Mirrors
// nip29.GroupMetadata's shape with explicit json tags, since that type
// belongs to a pure-protocol package not designed around bbolt storage.
type GroupMetadataFields struct {
	Name    string `json:"name,omitempty"`
	Picture string `json:"picture,omitempty"`
	Banner  string `json:"banner,omitempty"`
	About   string `json:"about,omitempty"`
	Parent  string `json:"parent,omitempty"`
	// Children is this group's ordered subgroup ids (NIP-29 "Subgroups"),
	// set only on a group that is itself a parent. See
	// GroupsService.SetChildren -- mutate it only through that, never via
	// SetMetadata's own full-replace, or an unrelated edit silently drops
	// every subgroup link.
	Children          []string `json:"children,omitempty"`
	Private           bool     `json:"private"`
	Restricted        bool     `json:"restricted,omitempty"`
	Hidden            bool     `json:"hidden,omitempty"`
	Closed            bool     `json:"closed"`
	LiveKit           bool     `json:"livekit,omitempty"`
	SupportedKinds    []int    `json:"supported_kinds,omitempty"`
	SupportedKindsSet bool     `json:"supported_kinds_set,omitempty"`
}

// GroupPins is the persisted subset of a NIP-29 group's kind:39005 pinned
// list.
type GroupPins struct {
	Events    []string `json:"events,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

// GroupRecord is the authoritative, persisted record for one NIP-29 group.
type GroupRecord struct {
	ID        string              `json:"id"`
	Metadata  GroupMetadataFields `json:"metadata"`
	Members   []GroupMember       `json:"members"`
	Pins      GroupPins           `json:"pins"`
	CreatedAt int64               `json:"created_at"`
}

// member returns id's own roster entry, or (zero, false) if pubkey holds
// no roster entry at all. Separate from RolesFor so "not a member" and
// "a member with zero roles" are never confused -- both would otherwise
// report a nil Roles slice.
func (r *GroupRecord) member(pubkey string) (GroupMember, bool) {
	for _, m := range r.Members {
		if m.Pubkey == pubkey {
			return m, true
		}
	}
	return GroupMember{}, false
}

// IsMember reports whether pubkey holds any roster entry in this group,
// with or without roles.
func (r *GroupRecord) IsMember(pubkey string) bool {
	_, ok := r.member(pubkey)
	return ok
}

// IsAdmin reports whether pubkey is a member holding at least one role.
// Which specific actions that unlocks is GroupsService.CanPerform's job.
func (r *GroupRecord) IsAdmin(pubkey string) bool {
	m, ok := r.member(pubkey)
	return ok && len(m.Roles) > 0
}

// RolesFor returns pubkey's own roles, or nil if pubkey is not a member at
// all (indistinguishable here from "a member with zero roles" -- callers
// that need to tell those apart should use member via IsMember first).
func (r *GroupRecord) RolesFor(pubkey string) []string {
	m, _ := r.member(pubkey)
	return m.Roles
}

// withMember returns a copy of r with member upserted by pubkey -- a new
// *GroupRecord, never a mutation in place, since groupsCache treats a
// cached record as immutable once published (relay/groups_cache.go).
func (r *GroupRecord) withMember(member GroupMember) *GroupRecord {
	next := *r
	members := make([]GroupMember, 0, len(r.Members)+1)
	replaced := false
	for _, existing := range r.Members {
		if existing.Pubkey == member.Pubkey {
			members = append(members, member)
			replaced = true
			continue
		}
		members = append(members, existing)
	}
	if !replaced {
		members = append(members, member)
	}
	next.Members = members
	return &next
}

// withoutMember returns a copy of r with pubkey's roster entry removed, if
// it had one.
func (r *GroupRecord) withoutMember(pubkey string) *GroupRecord {
	next := *r
	members := make([]GroupMember, 0, len(r.Members))
	for _, existing := range r.Members {
		if existing.Pubkey != pubkey {
			members = append(members, existing)
		}
	}
	next.Members = members
	return &next
}

// GetGroup returns the persisted record for id, or (nil, nil) if id is not
// a currently-hosted group -- absence is a normal, common outcome, not an
// error.
func (s *EventStore) GetGroup(id string) (*GroupRecord, error) {
	var rec GroupRecord
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexGroups)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(id))
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &rec)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &rec, nil
}

// PutGroup inserts or overwrites rec's group record.
func (s *EventStore) PutGroup(rec *GroupRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(indexGroups)
		if err != nil {
			return err
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(rec.ID), data)
	})
}

// DeleteGroup removes id's group record outright. A no-op, not an error, if
// id doesn't exist.
func (s *EventStore) DeleteGroup(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexGroups)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(id))
	})
}

// ListGroups returns every group record currently persisted. Used for
// cold-start cache loading at relay construction, not the request hot path.
func (s *EventStore) ListGroups() ([]*GroupRecord, error) {
	var records []*GroupRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexGroups)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec GroupRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			records = append(records, &rec)
			return nil
		})
	})
	return records, err
}

/////////////////////////////////////////////////////////////////////
// Group-scoped invites (kind:9009), separate from NIP-43's own
/////////////////////////////////////////////////////////////////////

// GroupInvite is the persisted state for one NIP-29 kind:9009 invite code.
// Unlike NIP-43's InviteClaim, a kind:9009 event carries nothing beyond a
// bare code (see nip29.NewCreateInvite) -- no TTL or max-uses to persist --
// so a code is simply valid until consumed once.
type GroupInvite struct {
	GroupID   string `json:"group_id"`
	Code      string `json:"code"`
	CreatedAt int64  `json:"created_at"`
	Used      bool   `json:"used"`
}

func groupInviteKey(groupID, code string) []byte {
	return []byte(groupID + "\x00" + code)
}

// PutGroupInvite inserts or overwrites inv's invite record.
func (s *EventStore) PutGroupInvite(inv *GroupInvite) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(indexGroupInvites)
		if err != nil {
			return err
		}
		data, err := json.Marshal(inv)
		if err != nil {
			return err
		}
		return b.Put(groupInviteKey(inv.GroupID, inv.Code), data)
	})
}

// GetGroupInvite returns the persisted invite, or (nil, nil) if code is not
// a known invite for groupID.
func (s *EventStore) GetGroupInvite(groupID, code string) (*GroupInvite, error) {
	var inv GroupInvite
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexGroupInvites)
		if b == nil {
			return nil
		}
		data := b.Get(groupInviteKey(groupID, code))
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &inv)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &inv, nil
}

// ConsumeGroupInvite atomically loads, validates, and marks groupID's code
// used in a single bbolt transaction -- avoiding a check-then-act race
// between concurrent kind:9021 join requests redeeming the same code.
// Returns ErrGroupInviteNotFound / ErrGroupInviteExhausted for the
// respective failure, or the (now-used) invite on success.
func (s *EventStore) ConsumeGroupInvite(groupID, code string) (*GroupInvite, error) {
	var result GroupInvite
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(indexGroupInvites)
		if err != nil {
			return err
		}
		key := groupInviteKey(groupID, code)
		data := b.Get(key)
		if data == nil {
			return ErrGroupInviteNotFound
		}
		var inv GroupInvite
		if err := json.Unmarshal(data, &inv); err != nil {
			return err
		}
		if inv.Used {
			return ErrGroupInviteExhausted
		}
		inv.Used = true
		result = inv
		newData, err := json.Marshal(inv)
		if err != nil {
			return err
		}
		return b.Put(key, newData)
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
