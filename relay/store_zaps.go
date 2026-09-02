package relay

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
	bolt "go.etcd.io/bbolt"
)

// IndexZap indexes a zap receipt — NIP-57 (Kind 9735) or AltZap (Kind 5521).
// It extracts the amount and the receiver pubkey and stores them in a dedicated bucket.
func (s *EventStore) IndexZap(tx *bolt.Tx, event *nip01.Event, evsid uint64) error {
	if event.Kind != 5521 && event.Kind != 9735 {
		return nil
	}

	amount, receiver, err := parseZapEvent(event)
	if err != nil {
		// If we can't parse it as a valid zap (no amount/receiver), just skip indexing it in this bucket.
		return nil
	}

	bucket, err := tx.CreateBucketIfNotExists(indexZaps)
	if err != nil {
		return err
	}

	// Key: [Timestamp (8b)] [Evsid (8b)]
	key := make([]byte, 16)
	binary.BigEndian.PutUint64(key[0:8], uint64(event.CreatedAt))
	binary.BigEndian.PutUint64(key[8:16], evsid)

	// Value: [Amount (8b)] [ReceiverPubkey (32b)]
	receiverBytes, _ := hex.DecodeString(receiver) // parseZapEvent guarantees valid hex or empty
	if len(receiverBytes) != 32 {
		return nil // Should not happen if parseZapEvent is correct, but safety check
	}

	value := make([]byte, 40)
	binary.BigEndian.PutUint64(value[0:8], amount)
	copy(value[8:40], receiverBytes)

	return bucket.Put(key, value)
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
		b := tx.Bucket(indexZaps)
		if b == nil {
			return nil
		}

		c := b.Cursor()

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

			if len(v) != 40 {
				continue
			}

			amount := binary.BigEndian.Uint64(v[0:8])
			receiverBytes := v[8:40]
			receiver := hex.EncodeToString(receiverBytes)

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

// parseZapEvent extracts amount (in sats/msats normalized) and receiver pubkey.
func parseZapEvent(event *nip01.Event) (uint64, string, error) {
	// 1. Extract Receiver: collect p[1]/p[2] and r[1] in one pass.
	// p[1] may be a Nostr pubkey or a ConnectionKey (both are valid 64-hex).
	// p[2] is the provider ("nostr", "discord", "telegram", …); absent means "nostr".
	// r[1] is the resolved Nostr pubkey when p[1] is a ConnectionKey (web-identity-linked).
	var pVal, pProvider, rVal string
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			if pVal == "" {
				pVal = tag[1]
				if len(tag) >= 3 {
					pProvider = tag[2]
				}
			}
		case "r":
			if rVal == "" {
				rVal = tag[1]
			}
		}
	}

	if err := utils.Validate32Key(pVal); err != nil {
		return 0, "", fmt.Errorf("no valid receiver p tag: %w", err)
	}

	var receiver string
	switch {
	case utils.Validate32Key(rVal) == nil:
		// r tag present and valid → use resolved Nostr pubkey (web-identity-linked, with or without p[2])
		receiver = rVal
	case pProvider == "" || pProvider == "nostr":
		// no r tag, no web identity marker → p[1] is a pure Nostr pubkey
		receiver = pVal
	default:
		// Web Identity (non-Nostr platform) recipient with no resolved Nostr
		// pubkey in the "r" tag → exclude from leaderboard, since there's no
		// Nostr identity to credit.
		return 0, "", fmt.Errorf("p tag references a non-nostr provider (%q) but no resolved pubkey was found in an r tag", pProvider)
	}

	// 2. Extract Amount
	// Kind 5521: Check 'amount' tag assuming msats string.
	var amount uint64

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		if tag[0] == "amount" {
			// Assuming value is in msats
			val, err := strconv.ParseUint(tag[1], 10, 64)
			if err == nil {
				amount = val
			}
		} else if tag[0] == "description" && amount == 0 {
			// For Kind 5521, the amount is often in the embedded zap request (description tag)
			var inner struct {
				Tags [][]string `json:"tags"`
			}
			if err := json.Unmarshal([]byte(tag[1]), &inner); err == nil {
				for _, it := range inner.Tags {
					if len(it) >= 2 && it[0] == "amount" {
						val, err := strconv.ParseUint(it[1], 10, 64)
						if err == nil {
							amount = val
						}
						break
					}
				}
			}
		}
	}

	if amount == 0 {
		return 0, "", fmt.Errorf(`no "amount" tag found on the zap event or its embedded zap request ("description" tag)`)
	}

	return amount, receiver, nil
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
