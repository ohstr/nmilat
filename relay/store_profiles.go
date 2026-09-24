package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
)

// The kind+pubkey index key is Kind(8) + Pubkey(32) + CreatedAt(8) +
// Evsid(8). These are named so a layout change has to update them here
// too, rather than leaving byte offsets to drift silently.
const (
	profilePrefixLen = 8 + 32
	profileKeyLen    = profilePrefixLen + 8 + 8
)

// FetchProfileEvents retrieves the latest Kind 0 (Metadata) events for the given pubkeys.
// It bypasses the standard subscription query mechanism for performance.
func (s *EventStore) FetchProfileEvents(ctx context.Context, pubkeys []string) ([]*nip01.Event, error) {
	var events []*nip01.Event

	// Kind 0 bytes
	kindBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(kindBytes, 0)

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexKindPubkey)
		if b == nil {
			return nil
		}
		c := b.Cursor()

		for _, pubkey := range pubkeys {
			pkBytes, err := hex.DecodeString(pubkey)
			if err != nil || len(pkBytes) != 32 {
				continue
			}

			// We want the LATEST event. In BoltDB, keys are sorted.
			// Our Key structure: [Kind (8)] [Pubkey (32)] [CreatedAt (8)] [Evsid (8)]
			// CreatedAt leads the suffix, so the largest key under this
			// prefix is the newest event by timestamp -- not merely the
			// last one inserted.
			// To find the latest, we seek to a key that is conceptually "after" the last possible
			// key for this Kind+Pubkey, then step back.

			// Construct Prefix: Kind (8) + Pubkey (32)
			prefix := make([]byte, profilePrefixLen)
			copy(prefix[0:8], kindBytes)
			copy(prefix[8:40], pkBytes)

			// Construct Seek Key: Prefix + max CreatedAt/Evsid suffix (0xFF...)
			seekKey := make([]byte, profileKeyLen)
			copy(seekKey, prefix)
			for i := profilePrefixLen; i < profileKeyLen; i++ {
				seekKey[i] = 0xFF
			}

			k, _ := c.Seek(seekKey)
			if k == nil {
				// Seek went past the end of the bucket
				k, _ = c.Last()
			} else {
				// Seek found a key >= seekKey.
				// Since seekKey has 0xFF at end, it's likely we found the NEXT prefix or nil.
				// So we step back to get the largest key < seekKey.
				k, _ = c.Prev()
			}

			// Verify we are still on the correct prefix
			if k != nil && bytes.HasPrefix(k, prefix) {
				// Found the latest entry!
				// Extract Evsid from the last 8 bytes of the Key. The
				// length must match exactly: a longer key means the layout
				// changed under us, and reading a fixed offset out of it
				// would silently yield a nonexistent evsid.
				if len(k) == profileKeyLen {
					evsid := binary.BigEndian.Uint64(k[profilePrefixLen+8 : profileKeyLen])
					ev, err := s.findEventUsingTx(tx, evsid)
					if err == nil {
						events = append(events, ev)
					}
				}
			}
		}
		return nil
	})

	return events, err
}
