package nip77

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// Reconcile processes a message from the other party and generates a response.
// It also returns IDs that the other party needs (idsHave) and IDs that we need (idsNeed) if available from IdLists.
func (n *Negentropy) Reconcile(theirMsg *Message) (*Message, []string, []string, error) {
	response := &Message{
		ProtocolVersion: ProtocolVersion1,
		Ranges:          make([]Range, 0),
	}

	var idsHave []string // IDs I have that they might need (from their IdList)
	var idsNeed []string // IDs I need that they have (from their IdList)

	// We process each range in their message
	// Their message covers the entire ID space (0, 0) -> (Inf, Inf)
	// We must also cover the entire ID space in our response.

	// Track our position in our sorted Items slice
	currentIdx := 0

	for _, theirRange := range theirMsg.Ranges {
		upperBound := theirRange.UpperBound

		// 1. Identify items within [lowerBound, upperBound)
		// We can just iterate from currentIdx until we hit upperBound
		startIdx := currentIdx
		endIdx := currentIdx

		for endIdx < len(n.Items) {
			item := n.Items[endIdx]

			// Check if item < upperBound
			if ItemIsBeforeBound(item, upperBound) {
				endIdx++
			} else {
				break
			}
		}

		myRangeItems := n.Items[startIdx:endIdx]
		currentIdx = endIdx // Advance for next range

		// 2. Respond to this range
		mode := theirRange.Mode

		switch mode {
		case 0: // Skip
			// They are done with this range. We also Skip.
			response.Ranges = append(response.Ranges, Range{
				UpperBound: upperBound,
				Mode:       0, // Skip
			})

		case 1: // Fingerprint
			myFingerprint := computeFingerprint(myRangeItems)

			if bytes.Equal(myRangeItemsFingerprint(theirRange.Payload, myRangeItems, myFingerprint), theirRange.Payload) {
				// Match!
				response.Ranges = append(response.Ranges, Range{
					UpperBound: upperBound,
					Mode:       0, // Skip
				})
			} else {
				// Mismatch - We need to split or send IDs

				// Threshold for sending IDs directly
				// If we have few items, just send them.
				if len(myRangeItems) < 100 { // Configurable threshold?
					// Send IdList
					payload, err := encodeIdList(myRangeItems)
					if err != nil {
						return nil, nil, nil, err
					}
					response.Ranges = append(response.Ranges, Range{
						UpperBound: upperBound,
						Mode:       2, // IdList
						Payload:    payload,
					})
				} else {
					// Split into up to 16 buckets
					numBuckets := 16
					itemsPerBucket := len(myRangeItems) / numBuckets
					if itemsPerBucket == 0 {
						numBuckets = len(myRangeItems)
						itemsPerBucket = 1
					}

					for b := 0; b < numBuckets; b++ {
						startIdx := b * itemsPerBucket
						endIdx := (b + 1) * itemsPerBucket
						if b == numBuckets-1 {
							endIdx = len(myRangeItems)
						}

						bucketItems := myRangeItems[startIdx:endIdx]
						fp := computeFingerprint(bucketItems)

						var bucketBound Bound
						if b == numBuckets-1 {
							bucketBound = upperBound
						} else {
							splitItem := myRangeItems[endIdx]
							bucketBound = Bound{
								Timestamp: splitItem.Timestamp,
								IDPrefix:  splitItem.ID[:],
							}
						}

						response.Ranges = append(response.Ranges, Range{
							UpperBound: bucketBound,
							Mode:       1, // Fingerprint
							Payload:    fp,
						})
					}
				}
			}

		case 2: // IdList
			// They sent us their IDs.
			// We calculate diffs.

			theirIDs, err := decodeIdList(theirRange.Payload)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to decode IdList: %w", err)
			}

			// Map for fast lookup
			theirMap := make(map[string]bool)
			for _, id := range theirIDs {
				theirMap[id] = true
			}

			// Calculate IdsHave (I have, they don't)
			for _, item := range myRangeItems {
				idHex := hex.EncodeToString(item.ID[:])
				if !theirMap[idHex] {
					idsHave = append(idsHave, idHex)
				} else {
					// We both have it, remove from map to find what they have but I don't
					delete(theirMap, idHex)
				}
			}

			// Remaining in theirMap are items they have but I don't
			for id := range theirMap {
				idsNeed = append(idsNeed, id)
			}

			if n.IsInitiator {
				// Client already has the diff info from the server's IdList.
				// Respond with Skip — no need to send our IDs back.
				response.Ranges = append(response.Ranges, Range{
					UpperBound: upperBound,
					Mode:       0, // Skip
				})
			} else {
				// Server must respond with its own IdList so the client
				// can learn what IDs the server has.
				payload, err := encodeIdList(myRangeItems)
				if err != nil {
					return nil, nil, nil, err
				}
				response.Ranges = append(response.Ranges, Range{
					UpperBound: upperBound,
					Mode:       2, // IdList
					Payload:    payload,
				})
			}
		}
	}

	return response, idsHave, idsNeed, nil
}

// ItemIsBeforeBound reports whether item sorts strictly before bound.
// Exported so callers can replicate Reconcile's range-partitioning (e.g. to
// estimate sync progress from a Message's ranges) without duplicating this
// comparison.
func ItemIsBeforeBound(item Item, bound Bound) bool {
	if bound.Timestamp == InfiniteTimestamp {
		return true
	}
	if item.Timestamp < bound.Timestamp {
		return true
	}
	if item.Timestamp > bound.Timestamp {
		return false
	}

	// Timestamps equal, check ID prefix
	prefixLen := len(bound.IDPrefix)

	// Compare common length
	for i := 0; i < prefixLen; i++ {
		if i >= 32 {
			break // Should not happen if prefix <= 32
		}
		if item.ID[i] < bound.IDPrefix[i] {
			return true
		}
		if item.ID[i] > bound.IDPrefix[i] {
			return false
		}
	}

	// If prefixes match:
	// Example: Bound Prefix "A", Item "AB". Key order: "A" < "AB".
	// But Bound is *exclusive*.
	// If Bound is "A", then "AA" >= "A".
	// So "AA" is NOT before "A".
	return false
}

func myRangeItemsFingerprint(theirPayload []byte, myItems []Item, computedFP []byte) []byte {
	// Helper to just return computedFP, but logically could check validity?
	return computedFP
}

func encodeIdList(items []Item) ([]byte, error) {
	// IdList := <length (Varint)> <ids (Id)>*
	var buf []byte
	buf = append(buf, encodeVarint(uint64(len(items)))...)
	for _, item := range items {
		buf = append(buf, item.ID[:]...)
	}
	return buf, nil
}

func decodeIdList(payload []byte) ([]string, error) {
	// Payload contains <length> <ids>
	buf := bytes.NewReader(payload)

	count, err := decodeReaderVarint(buf)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		idBytes := make([]byte, 32)
		n, err := buf.Read(idBytes)
		if err != nil {
			return nil, err
		}
		if n != 32 {
			return nil, fmt.Errorf("short read for ID")
		}
		ids = append(ids, hex.EncodeToString(idBytes))
	}

	return ids, nil
}
