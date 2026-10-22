package relay

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
)

// isZapKind reports whether kind is a zap receipt the zap index holds.
func isZapKind(kind int) bool { return kind == 9521 || kind == 9735 }

// IndexZap indexes a zap receipt — NIP-57 (Kind 9735) or AltZap (Kind 9521).
// It extracts the amount and the receiver pubkey and stores them in a dedicated bucket.
// A rebuild in progress gets every new zap too, so none is lost when it
// becomes the active index.
func (s *EventStore) IndexZap(tx *bolt.Tx, event *nip01.Event, evsid uint64) error {
	if !isZapKind(event.Kind) {
		return nil
	}
	for _, name := range [][]byte{activeZapBucket(tx), buildingZapBucket(tx)} {
		if name == nil {
			continue
		}
		bucket, err := tx.CreateBucketIfNotExists(name)
		if err != nil {
			return err
		}
		if err := putZap(bucket, event, evsid); err != nil {
			return err
		}
	}
	return nil
}

// putZap writes one zap receipt into bucket. A receipt with no parsable
// amount or receiver is skipped.
//
// Key: created_at(8) + evsid(8). Value: amount(8) + receiver(32), then a
// zapEntry (Other = sender) for the counting rules; values written before
// that are just the first 40 bytes.
func putZap(bucket *bolt.Bucket, event *nip01.Event, evsid uint64) error {
	f, err := parseZapFact(event)
	if err != nil {
		return nil
	}
	receiver, err := hex.DecodeString(f.Receiver)
	if err != nil || len(receiver) != 32 {
		return nil
	}
	value := make([]byte, 40, 40+zapEntryLen)
	binary.BigEndian.PutUint64(value[0:8], f.Amount)
	copy(value[8:40], receiver)
	value = append(value, zapEntry{Amount: f.Amount, Other: f.Sender, Signer: f.Signer, PaymentHash: f.PaymentHash, Valid: f.Valid}.encode()...)
	return bucket.Put(zapKey(event, evsid), value)
}

func zapKey(event *nip01.Event, evsid uint64) []byte {
	return append(itob(event.CreatedAt), itob(evsid)...)
}

// unindexZap removes a deleted receipt from the zap index.
func (s *EventStore) unindexZap(tx *bolt.Tx, event *nip01.Event, evsid uint64) error {
	if !isZapKind(event.Kind) {
		return nil
	}
	for _, name := range [][]byte{activeZapBucket(tx), buildingZapBucket(tx)} {
		if b := tx.Bucket(name); name != nil && b != nil {
			if err := b.Delete(zapKey(event, evsid)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ZapStats contains the aggregated zap amount for a pubkey.
type ZapStats struct {
	Pubkey     string `json:"pubkey"`
	TotalMLoki uint64 `json:"total_mloki"`
}

// GetTopZapped returns the top zapped public keys within the specified time window.
func (s *EventStore) GetTopZapped(ctx context.Context, since, until uint64, limit int) ([]ZapStats, error) {
	if limit <= 0 {
		return nil, nil
	}

	aggregation := make(map[string]uint64)

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(activeZapBucket(tx))
		if b == nil {
			return nil
		}

		c := b.Cursor()
		keys := lnurlKeys{tx: tx, cache: map[string]string{}}
		seen := map[string]bool{}

		// Start from 'since'
		minKey := make([]byte, 16)
		binary.BigEndian.PutUint64(minKey[0:8], since)
		// Evsid 0 for start of the timestamp

		// Iterate
		for k, v := c.Seek(minKey); k != nil; k, v = c.Next() {
			if len(k) < 8 {
				continue
			}

			timestamp := binary.BigEndian.Uint64(k[0:8])
			if timestamp > until {
				break
			}

			if len(v) < 40 {
				continue
			}

			amount := binary.BigEndian.Uint64(v[0:8])
			receiver := hex.EncodeToString(v[8:40])

			// Entries written before the counting rules (40 bytes) count
			// as they did until the next rebuild.
			if e, ok := decodeZapEntry(v[40:]); ok && !zapCounts(e, e.Other, receiver, keys.get(receiver), seen) {
				continue
			}

			aggregation[receiver] += amount
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort results
	type kv struct {
		Key   string
		Value uint64
	}

	var sorted []kv
	for k, v := range aggregation {
		sorted = append(sorted, kv{k, v})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	result := make([]ZapStats, 0, limit)
	for i, kv := range sorted {
		if i >= limit {
			break
		}
		result = append(result, ZapStats{
			Pubkey:     kv.Key,
			TotalMLoki: kv.Value,
		})
	}

	return result, nil
}

// QueryEvents finds events matching the filter.
func (s *EventStore) QueryEvents(ctx context.Context, filter *nip01.SubscriptionFilter) ([]*nip01.Event, error) {
	var events []*nip01.Event
	err := s.db.View(func(tx *bolt.Tx) error {
		pes, err := s.findEvents(ctx, tx, filter)
		if err != nil {
			return err
		}

		for _, pe := range pes {
			ev, err := s.findEventUsingTx(tx, pe.Evsid)
			if err != nil {
				continue
			}
			events = append(events, ev)
		}
		return nil
	})
	return events, err
}
