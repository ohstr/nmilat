package relay

import (
	"encoding/json"
	"errors"

	bolt "go.etcd.io/bbolt"
)

var (
	// indexMembers is the authoritative NIP-43 member set: one key per
	// member pubkey, not one JSON blob for the whole set -- a single-blob
	// rewrite on every join/leave would be O(member-count) per mutation;
	// individual keys make join/leave O(1). The in-memory membershipCache
	// (relay/membership_cache.go) is a fast mirror of this bucket, never
	// the other way around.
	indexMembers = []byte{12}

	// indexInviteClaims stores NIP-43 invite-code state, keyed by the
	// claim code itself.
	indexInviteClaims = []byte{13}
)

var (
	ErrInviteClaimNotFound  = errors.New("relay: invite claim not found")
	ErrInviteClaimExpired   = errors.New("relay: invite claim expired")
	ErrInviteClaimExhausted = errors.New("relay: invite claim already used")
)

// MemberRecord is the authoritative, persisted record for one NIP-43
// member.
type MemberRecord struct {
	Pubkey   string   `json:"pubkey"`
	Roles    []string `json:"roles,omitempty"`
	JoinedAt int64    `json:"joined_at"`
}

// GetMember returns the persisted record for pubkey, or (nil, nil) if
// pubkey is not currently a member -- absence is a normal, common outcome,
// not an error.
func (s *EventStore) GetMember(pubkey string) (*MemberRecord, error) {
	var rec MemberRecord
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexMembers)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(pubkey))
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

// PutMember inserts or overwrites rec's membership record.
func (s *EventStore) PutMember(rec *MemberRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(indexMembers)
		if err != nil {
			return err
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(rec.Pubkey), data)
	})
}

// RemoveMember deletes pubkey's membership record. A no-op, not an error,
// if pubkey isn't currently a member.
func (s *EventStore) RemoveMember(pubkey string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexMembers)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(pubkey))
	})
}

// ListMembers returns every member pubkey currently persisted. Used for
// cold-start cache loading at relay construction, not the request hot
// path.
func (s *EventStore) ListMembers() ([]string, error) {
	var pubkeys []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexMembers)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			pubkeys = append(pubkeys, string(k))
			return nil
		})
	})
	return pubkeys, err
}

// ListMemberRecords returns every member's full persisted record. Used by
// `ncli relay members list`, not the request hot path -- unlike ListMembers
// (pubkeys only, for cache warm-up), callers here need Roles/JoinedAt too,
// so this reads each record directly in one pass rather than making callers
// pair it with a GetMember per pubkey.
func (s *EventStore) ListMemberRecords() ([]*MemberRecord, error) {
	var records []*MemberRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexMembers)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec MemberRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			records = append(records, &rec)
			return nil
		})
	})
	return records, err
}

// InviteClaim is the persisted state for one NIP-43 invite code.
type InviteClaim struct {
	Code      string   `json:"code"`
	CreatedAt int64    `json:"created_at"`
	ExpiresAt int64    `json:"expires_at,omitempty"` // 0 = never expires
	MaxUses   int      `json:"max_uses,omitempty"`   // 0 = unlimited uses
	Uses      int      `json:"uses"`
	Roles     []string `json:"roles,omitempty"`
}

// GetInviteClaim returns the persisted claim, or (nil, nil) if code is not
// a known claim.
func (s *EventStore) GetInviteClaim(code string) (*InviteClaim, error) {
	var claim InviteClaim
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexInviteClaims)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(code))
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &claim)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &claim, nil
}

// PutInviteClaim inserts or overwrites claim.
func (s *EventStore) PutInviteClaim(claim *InviteClaim) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(indexInviteClaims)
		if err != nil {
			return err
		}
		data, err := json.Marshal(claim)
		if err != nil {
			return err
		}
		return b.Put([]byte(claim.Code), data)
	})
}

// ListInviteClaims returns every currently-stored invite claim. Used for
// `ncli relay invites list`, not the request hot path.
func (s *EventStore) ListInviteClaims() ([]*InviteClaim, error) {
	var claims []*InviteClaim
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexInviteClaims)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var claim InviteClaim
			if err := json.Unmarshal(v, &claim); err != nil {
				return err
			}
			claims = append(claims, &claim)
			return nil
		})
	})
	return claims, err
}

// DeleteInviteClaim removes code outright (distinct from ConsumeInviteClaim,
// which increments Uses on a valid claim) -- used for `ncli relay invites
// revoke`. A no-op, not an error, if code doesn't exist.
func (s *EventStore) DeleteInviteClaim(code string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexInviteClaims)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(code))
	})
}

// ConsumeInviteClaim atomically loads, validates, increments Uses, and
// persists code's claim in a single bbolt transaction -- avoiding a
// check-then-act race between concurrent Join Requests racing to use the
// same claim. Returns ErrInviteClaimNotFound / ErrInviteClaimExpired /
// ErrInviteClaimExhausted for the respective failure, or the
// (post-increment) claim on success.
func (s *EventStore) ConsumeInviteClaim(code string, now int64) (*InviteClaim, error) {
	var result InviteClaim
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(indexInviteClaims)
		if err != nil {
			return err
		}
		data := b.Get([]byte(code))
		if data == nil {
			return ErrInviteClaimNotFound
		}
		var claim InviteClaim
		if err := json.Unmarshal(data, &claim); err != nil {
			return err
		}
		if claim.ExpiresAt > 0 && now > claim.ExpiresAt {
			return ErrInviteClaimExpired
		}
		if claim.MaxUses > 0 && claim.Uses >= claim.MaxUses {
			return ErrInviteClaimExhausted
		}
		claim.Uses++
		result = claim
		newData, err := json.Marshal(claim)
		if err != nil {
			return err
		}
		return b.Put([]byte(code), newData)
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
