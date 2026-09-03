// Package nip77 implements NIP-77: Negentropy Syncing, a range-based set
// reconciliation protocol relays and clients use to efficiently discover
// which events they're each missing without transferring full event lists.
package nip77

import (
	"crypto/sha256"
	"math"
)

// Constants
const (
	ProtocolVersion1  = 0x61
	InfiniteTimestamp = math.MaxUint64
)

// Item represents a single event in the reconciliation set.
// NIP-77 requires items to be sorted by Timestamp, then ID.
type Item struct {
	Timestamp uint64
	ID        [32]byte
}

// Compare returns -1 if i < other, 1 if i > other, 0 if equal
func (i Item) Compare(other Item) int {
	if i.Timestamp < other.Timestamp {
		return -1
	}
	if i.Timestamp > other.Timestamp {
		return 1
	}
	// Timestamps equal, compare IDs lexicographically
	for x := range 32 {
		if i.ID[x] < other.ID[x] {
			return -1
		}
		if i.ID[x] > other.ID[x] {
			return 1
		}
	}
	return 0
}

// Negentropy handles the reconciliation state
type Negentropy struct {
	Items       []Item
	IsInitiator bool // true = client (initiator), false = server (responder)
}

func New(items []Item) *Negentropy {
	// Assumption: items are already sorted by Timestamp, ID
	return &Negentropy{Items: items}
}

// Initiate builds the initial client message: a single range covering the
// entire ID space with a fingerprint over all local items.
func (n *Negentropy) Initiate() *Message {
	n.IsInitiator = true
	fp := computeFingerprint(n.Items)
	return &Message{
		ProtocolVersion: ProtocolVersion1,
		Ranges: []Range{
			{
				UpperBound: Bound{Timestamp: InfiniteTimestamp},
				Mode:       1, // Fingerprint
				Payload:    fp,
			},
		},
	}
}

// IsComplete returns true when all ranges in a response are Skip (mode 0),
// indicating that reconciliation has converged.
func IsComplete(msg *Message) bool {
	for _, r := range msg.Ranges {
		if r.Mode != 0 {
			return false
		}
	}
	return true
}

// --- Protocol Structures ---

type Message struct {
	ProtocolVersion byte
	Ranges          []Range
}

type Range struct {
	UpperBound Bound
	Mode       int // 0=Skip, 1=Fingerprint, 2=IdList
	Payload    []byte
}

type Bound struct {
	Timestamp uint64
	IDPrefix  []byte
}

// --- Fingerprint Logic ---

func computeFingerprint(items []Item) []byte {
	// * Compute the addition mod 2^256 of the element IDs (interpreted as 32-byte little-endian unsigned integers)
	// * Concatenate with the number of elements in the Range, encoded as a Varint
	// * Hash with SHA-256
	// * Take the first 16 bytes

	// 1. Addition mod 2^256
	sum := make([]byte, 32)
	for _, item := range items {
		addMod256(sum, item.ID)
	}

	// 2. Concatenate with Varint(Length)
	buf := make([]byte, 0, 32+10)
	buf = append(buf, sum...)
	buf = append(buf, encodeVarint(uint64(len(items)))...)

	// 3. Hash SHA-256
	hash := sha256.Sum256(buf)

	// 4. Take first 16 bytes
	return hash[:16]
}

// addMod256 adds b to a (little-endian 32-byte integers)
func addMod256(a []byte, b [32]byte) {
	var carry uint16 = 0
	// Little-endian addition
	// ID in NIP77 is byte string, but for math it says "interpreted as... little-endian"
	// NOTE: Nostr IDs are usually Big Endian hex strings.
	// But NIP-77 spec says: "element IDs (interpreted as 32-byte little-endian unsigned integers)"
	// Implementation note: The `ID` field in `Item` is raw bytes.
	// If it's a 32-byte array, index 0 is "first byte".
	// Little-endian integer means index 0 is LSB.
	// So we can just add byte-by-byte from 0 to 31.

	for i := range 32 {
		val := uint16(a[i]) + uint16(b[i]) + carry
		a[i] = byte(val)
		carry = val >> 8
	}
}

// encodeVarint encodes x as a MSB-first varint per NIP-77 spec.
// "most significant digit first, with as few digits as possible.
// Bit eight (the high bit) is set on each byte except the last."
func encodeVarint(x uint64) []byte {
	if x == 0 {
		return []byte{0}
	}

	var buf [10]byte
	idx := 9

	for x != 0 {
		buf[idx] = byte(x & 0x7F)
		x >>= 7
		idx--
	}

	result := buf[idx+1:]
	// Set high bit on all bytes except the last
	for i := 0; i < len(result)-1; i++ {
		result[i] |= 0x80
	}

	out := make([]byte, len(result))
	copy(out, result)
	return out
}
