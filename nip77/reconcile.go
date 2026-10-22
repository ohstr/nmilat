package nip77

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
)

// Reconcile processes a message from the other party and generates a response.
// It also returns IDs that the other party needs (idsHave) and IDs that we need (idsNeed) if available from IdLists.
//
// It follows the reference negentropy: a mismatched range is split into
// buckets, or listed when small; consecutive Skip ranges are merged and
// trailing ones dropped; and once the response nears FrameSizeLimit it ends
// with one Fingerprint for everything not yet written, which the next round
// picks up.
func (n *Negentropy) Reconcile(theirMsg *Message) (*Message, []string, []string, error) {
	response := &Message{ProtocolVersion: ProtocolVersion1}
	f := frame{size: 1, limit: n.frameLimit()}

	var idsHave []string // IDs I have that they might need (from their IdList)
	var idsNeed []string // IDs I need that they have (from their IdList)

	prevIdx := 0        // our items before this index are covered
	var prevBound Bound // their bound ending the previous range
	writtenIdx := 0     // our items before this index are covered by written ranges
	skip := false       // a Skip up to prevBound is pending
	full := false       // the response is at its limit

	for _, theirRange := range theirMsg.Ranges {
		lower := prevIdx
		upper := n.lowerBound(lower, theirRange.UpperBound)
		skipBefore := skip

		var o []Range
		doSkip := func() {
			if skip {
				skip = false
				o = append(o, Range{UpperBound: prevBound, Mode: 0})
			}
		}

		switch theirRange.Mode {
		case 0: // Skip
			skip = true

		case 1: // Fingerprint
			if bytes.Equal(computeFingerprint(n.Items[lower:upper]), theirRange.Payload) {
				skip = true
			} else {
				doSkip()
				o = append(o, n.splitRange(lower, upper, theirRange.UpperBound)...)
			}

		case 2: // IdList
			theirIDs, err := decodeIdList(theirRange.Payload)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to decode IdList: %w", err)
			}
			theirMap := make(map[string]bool, len(theirIDs))
			for _, id := range theirIDs {
				theirMap[id] = true
			}
			for _, item := range n.Items[lower:upper] {
				idHex := hex.EncodeToString(item.ID[:])
				if !theirMap[idHex] {
					if n.report(idHex) {
						idsHave = append(idsHave, idHex)
					}
				} else {
					delete(theirMap, idHex)
				}
			}
			for id := range theirMap {
				if n.report(id) {
					idsNeed = append(idsNeed, id)
				}
			}

			if n.IsInitiator {
				// The diff is known; nothing to send back for this range.
				skip = true
				break
			}

			// Responder: list our ids so the initiator learns the diff,
			// cutting the list at an item bound if it would not fit.
			doSkip()
			base := f.size + f.measure(o)
			end, bound := upper, theirRange.UpperBound
			for i := lower; i < upper; i++ {
				if f.exceeded(base + idListHeader + (i-lower+1)*32) {
					end, bound = i, Bound{Timestamp: n.Items[i].Timestamp, IDPrefix: append([]byte(nil), n.Items[i].ID[:]...)}
					full = true
					break
				}
			}
			payload, _ := encodeIdList(n.Items[lower:end])
			o = append(o, Range{UpperBound: bound, Mode: 2, Payload: payload})
			f.commit(response, o)
			o = nil
			upper, writtenIdx = end, end
		}

		if full || f.exceeded(f.size+f.measure(o)) {
			// Close settled ranges with their Skip, then cover everything
			// not yet written with one fingerprint.
			if !full && skipBefore {
				response.Ranges = append(response.Ranges, Range{UpperBound: prevBound, Mode: 0})
				writtenIdx = lower
			}
			response.Ranges = append(response.Ranges, Range{
				UpperBound: Bound{Timestamp: InfiniteTimestamp},
				Mode:       1,
				Payload:    computeFingerprint(n.Items[writtenIdx:]),
			})
			break
		}
		if len(o) > 0 {
			f.commit(response, o)
			writtenIdx = upper
		}

		prevIdx = upper
		prevBound = theirRange.UpperBound
	}

	return response, idsHave, idsNeed, nil
}

// report reports whether id is new to the caller. Only the initiator
// tracks ids; a responder's diff is not used.
func (n *Negentropy) report(id string) bool {
	if !n.IsInitiator {
		return true
	}
	if n.reported[id] {
		return false
	}
	if n.reported == nil {
		n.reported = map[string]bool{}
	}
	n.reported[id] = true
	return true
}

// idListHeader bounds an IdList range's bytes before its ids.
const idListHeader = 64

func (n *Negentropy) frameLimit() int {
	if n.FrameSizeLimit <= 0 {
		return 0
	}
	return max(n.FrameSizeLimit, MinFrameSizeLimit)
}

// lowerBound returns the first index at or after from whose item is not
// before bound.
func (n *Negentropy) lowerBound(from int, bound Bound) int {
	return from + sort.Search(len(n.Items)-from, func(i int) bool {
		return !ItemIsBeforeBound(n.Items[from+i], bound)
	})
}

// splitRange covers items[lower:upper] up to upperBound: an IdList when
// small, else buckets of fingerprints split at minimal bounds.
func (n *Negentropy) splitRange(lower, upper int, upperBound Bound) []Range {
	num := upper - lower
	if num < 2*buckets {
		payload, _ := encodeIdList(n.Items[lower:upper])
		return []Range{{UpperBound: upperBound, Mode: 2, Payload: payload}}
	}

	per, extra := num/buckets, num%buckets
	out := make([]Range, 0, buckets)
	curr := lower
	for i := range buckets {
		size := per
		if i < extra {
			size++
		}
		fp := computeFingerprint(n.Items[curr : curr+size])
		curr += size
		bound := upperBound
		if curr != upper {
			bound = minimalBound(n.Items[curr-1], n.Items[curr])
		}
		out = append(out, Range{UpperBound: bound, Mode: 1, Payload: fp})
	}
	return out
}

// minimalBound is the shortest bound with prev before it and curr not.
func minimalBound(prev, curr Item) Bound {
	if prev.Timestamp != curr.Timestamp {
		return Bound{Timestamp: curr.Timestamp}
	}
	shared := 0
	for shared < 31 && prev.ID[shared] == curr.ID[shared] {
		shared++
	}
	return Bound{Timestamp: curr.Timestamp, IDPrefix: append([]byte(nil), curr.ID[:shared+1]...)}
}

// frame tracks a response's encoded size against its limit.
type frame struct {
	size   int
	limit  int
	lastTs uint64
}

// exceeded mirrors the reference: stop 200 bytes short so the closing
// fingerprint always fits.
func (f *frame) exceeded(n int) bool {
	return f.limit > 0 && n > f.limit-200
}

// measure returns the encoded size of rs if written next.
func (f *frame) measure(rs []Range) int {
	last, n := f.lastTs, 0
	for _, r := range rs {
		n += rangeLen(r, &last)
	}
	return n
}

func (f *frame) commit(m *Message, rs []Range) {
	f.size += f.measure(rs)
	for _, r := range rs {
		if r.UpperBound.Timestamp != InfiniteTimestamp {
			f.lastTs = r.UpperBound.Timestamp
		}
	}
	m.Ranges = append(m.Ranges, rs...)
}

// rangeLen is the encoded size of r, as ToBytes writes it.
func rangeLen(r Range, lastTs *uint64) int {
	ts := uint64(0)
	if r.UpperBound.Timestamp != InfiniteTimestamp {
		ts = 1 + r.UpperBound.Timestamp - *lastTs
		*lastTs = r.UpperBound.Timestamp
	}
	n := len(encodeVarint(ts)) + len(encodeVarint(uint64(len(r.UpperBound.IDPrefix)))) + len(r.UpperBound.IDPrefix) + 1
	switch r.Mode {
	case 1:
		n += 16
	case 2:
		n += len(r.Payload)
	}
	return n
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
