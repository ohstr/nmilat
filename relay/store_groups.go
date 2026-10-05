package relay

import (
	"encoding/json"

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

// GroupRecord is the authoritative, persisted record for one NIP-29 group.
// Phase 1 only ever populates it with the creator as sole admin and member
// (see relay/groups.go); later phases grow Admins/Members via kind:9000/9001.
type GroupRecord struct {
	ID string `json:"id"`

	// Private gates REQ-time visibility (relay/packet.go): a REQ naming a
	// private group's id via a "d"/"h" tag filter is only served to a
	// session authenticated as one of Members. Every group Phase 1 creates
	// starts (and, absent kind:9002 edit-metadata handling, stays) private
	// per decision 2 in docs/specs/nip29-groups-plan.md.
	Private bool `json:"private"`

	Admins    []string `json:"admins"`
	Members   []string `json:"members"`
	CreatedAt int64    `json:"created_at"`
}

// IsAdmin reports whether pubkey holds an admin role in this group.
func (r *GroupRecord) IsAdmin(pubkey string) bool {
	for _, admin := range r.Admins {
		if admin == pubkey {
			return true
		}
	}
	return false
}

// IsMember reports whether pubkey is a member of this group. Every admin is
// also a member (Phase 1 always adds the creator to both lists), but this
// checks Members directly rather than assuming that invariant holds forever.
func (r *GroupRecord) IsMember(pubkey string) bool {
	for _, member := range r.Members {
		if member == pubkey {
			return true
		}
	}
	return false
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
