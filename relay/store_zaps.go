package relay

import (
	"context"
	"encoding/binary"
	"encoding/hex"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
)

// applyZap adds (or removes) one zap receipt — NIP-57 (kind 9735) or
// AltZap (kind 9521) — in a zap generation and returns the change in its
// entries.
func applyZap(_ *EventStore, tx *bolt.Tx, gen []byte, event *nip01.Event, evsid uint64, add bool) (int64, []string, error) {
	b, err := tx.CreateBucketIfNotExists(gen)
	if err != nil {
		return 0, nil, err
	}
	key := zapKey(event, evsid)
	had := b.Get(key) != nil
	if !add {
		if !had {
			return 0, nil, nil
		}
		return -1, nil, b.Delete(key)
	}
	if err := putZap(b, event, evsid); err != nil {
		return 0, nil, err
	}
	if !had && b.Get(key) != nil {
		return 1, nil, nil
	}
	return 0, nil, nil
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
	value := make([]byte, 40, 40+zapEntryLen+1)
	binary.BigEndian.PutUint64(value[0:8], f.Amount)
	copy(value[8:40], receiver)
	value = append(value, zapEntry{Amount: f.Amount, Other: f.Sender, Signer: f.Signer, PaymentHash: f.PaymentHash, Valid: f.Valid, Coin: f.Coin}.encode()...)
	return bucket.Put(zapKey(event, evsid), value)
}

func zapKey(event *nip01.Event, evsid uint64) []byte {
	return append(itob(event.CreatedAt), itob(evsid)...)
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
