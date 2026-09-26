// Package transport implements NIP-CASH's private transport: a batch envelope
// carrying many bill operations inside one NIP-44 ciphertext, so a relay sees
// neither which bills are in use nor a stable identifier for the caller.
//
// This package is protocol only — types, codecs, size policy and per-item proof
// construction/verification. It makes no network calls and holds no keys. The
// hub and the client both depend on it precisely so the two cannot drift on what
// a valid envelope is.
package transport

import (
	"errors"
	"fmt"
)

// MaxNIP44Plaintext is NIP-44's hard plaintext ceiling: 65535 bytes encrypt,
// 65536 is refused outright. It is a property of the encryption layer, not a
// tunable, so it bounds every configured limit below.
//
// This is measured behaviour, not a reading of the spec — a 65536-byte payload
// fails with "plaintext should be between 1b and 64kB".
const MaxNIP44Plaintext = 65535

// Default envelope limits. Every one of these is a hub policy knob rather than a
// constant, because the right value depends on what a hub's clients actually
// batch; these are the defaults a hub gets if it configures nothing.
const (
	// DefaultMaxEnvelopeBytes is the ceiling on the PADDED plaintext handed to
	// NIP-44, so it is bounded by MaxNIP44Plaintext.
	//
	// Two different ceilings are in play and they are easy to conflate. NIP-44's
	// 65535 applies to the PLAINTEXT. The ciphertext NIP-44 returns is base64,
	// roughly 4/3 of the plaintext, and it is that string which lands in the
	// event's content field — bounded by the RELAY's max message length, not by
	// NIP-44 at all.
	//
	// So 56 KiB is not about NIP-44 headroom; it is about what a relay must
	// accept. A full envelope at this limit becomes ~76 KiB of base64 on the
	// wire (see EstimatedWireBytes). That is comfortably inside this module's own
	// relay default read limit of ~1.1 MB, so the default needs no operator
	// action — but a hub raising MaxEnvelopeBytes, or pointing at a third-party
	// relay with a tighter max_message_length, must check the expanded size.
	// A relay that silently refuses an oversized message produces exactly the
	// silence this transport exists to remove.
	DefaultMaxEnvelopeBytes = 56 * 1024

	// DefaultMaxItems is a cheap pre-check, not the real constraint. Bytes are
	// the real constraint (see MaxEnvelopeBytes) because items vary hugely: an
	// item is ~900-1100 bytes once it carries a signed proof event, but one
	// cash_consolidate item can legitimately carry 100 nested source proofs. A
	// count cap alone cannot express that, so it exists only to reject an absurd
	// item count before anything is parsed or hashed.
	DefaultMaxItems = 32

	// DefaultPadBucketBytes is the padding granularity. Ciphertext length leaks
	// how much is inside, so an envelope is padded up to a multiple of this and
	// a single cash_status becomes indistinguishable from a small batch. NIP-44's
	// own padding is power-of-two-ish and far too coarse to hide batch size.
	DefaultPadBucketBytes = 4 * 1024

	// DefaultMaxVerifyBudget bounds the total signature verifications one
	// envelope may demand, counted structurally BEFORE any crypto runs. Without
	// it, 32 items each carrying 100 nested source proofs would be 3200
	// verifications — at ~373us each (measured) that is over a second of CPU
	// from a single envelope, which is a denial of service with valid syntax.
	DefaultMaxVerifyBudget = 200
)

// Limits is a hub's configured envelope policy. The hub enforces its own values
// on receipt; a client should ask the hub for them rather than assume, because a
// client that builds to its own idea of the limits gets a rejection it could
// have predicted locally.
type Limits struct {
	// MaxEnvelopeBytes caps the PADDED plaintext size, so padding can never
	// push an otherwise-valid envelope past NIP-44's ceiling.
	MaxEnvelopeBytes int
	MaxItems         int
	PadBucketBytes   int
	MaxVerifyBudget  int
}

// DefaultLimits returns the policy a hub gets when it configures nothing.
func DefaultLimits() Limits {
	return Limits{
		MaxEnvelopeBytes: DefaultMaxEnvelopeBytes,
		MaxItems:         DefaultMaxItems,
		PadBucketBytes:   DefaultPadBucketBytes,
		MaxVerifyBudget:  DefaultMaxVerifyBudget,
	}
}

var (
	ErrLimitsNotPositive    = errors.New("transport: every envelope limit must be positive")
	ErrLimitsAboveCeiling   = errors.New("transport: MaxEnvelopeBytes exceeds NIP-44's plaintext ceiling")
	ErrLimitsPadTooLarge    = errors.New("transport: PadBucketBytes exceeds MaxEnvelopeBytes")
	ErrEnvelopeTooLarge     = errors.New("transport: envelope exceeds the configured size limit")
	ErrTooManyItems         = errors.New("transport: envelope exceeds the configured item limit")
	ErrVerifyBudgetExceeded = errors.New("transport: envelope exceeds the configured verification budget")
)

// Validate rejects a policy that cannot be honoured. A hub calls this on the
// values it read from configuration, so a misconfiguration fails at startup
// rather than at the first envelope.
func (l Limits) Validate() error {
	if l.MaxEnvelopeBytes <= 0 || l.MaxItems <= 0 || l.PadBucketBytes <= 0 || l.MaxVerifyBudget <= 0 {
		return fmt.Errorf("%w: %+v", ErrLimitsNotPositive, l)
	}
	if l.MaxEnvelopeBytes > MaxNIP44Plaintext {
		return fmt.Errorf("%w: %d > %d", ErrLimitsAboveCeiling, l.MaxEnvelopeBytes, MaxNIP44Plaintext)
	}
	// Padding rounds up to a multiple of the bucket, so a bucket larger than the
	// ceiling could not be applied to any envelope at all.
	if l.PadBucketBytes > l.MaxEnvelopeBytes {
		return fmt.Errorf("%w: %d > %d", ErrLimitsPadTooLarge, l.PadBucketBytes, l.MaxEnvelopeBytes)
	}
	return nil
}

// PaddedSize returns the size n is padded up to: the smallest multiple of
// PadBucketBytes that is at least n. It returns ErrEnvelopeTooLarge when that
// target would exceed MaxEnvelopeBytes, so the caller learns locally instead of
// discovering it when the relay drops the event.
func (l Limits) PaddedSize(n int) (int, error) {
	if n < 0 {
		return 0, fmt.Errorf("transport: negative size %d", n)
	}
	buckets := (n + l.PadBucketBytes - 1) / l.PadBucketBytes
	if buckets == 0 {
		buckets = 1
	}
	padded := buckets * l.PadBucketBytes
	if padded > l.MaxEnvelopeBytes {
		return 0, fmt.Errorf("%w: %d bytes pads to %d, limit %d", ErrEnvelopeTooLarge, n, padded, l.MaxEnvelopeBytes)
	}
	return padded, nil
}

// EstimatedWireBytes reports roughly how large a full envelope becomes in an
// event's content field: NIP-44 returns base64, so the plaintext expands by about
// 4/3, plus a version byte, a 32-byte nonce and a 32-byte MAC before encoding.
//
// This is the figure to compare against a relay's NIP-11 max_message_length. It
// is deliberately an estimate and rounded up — use it to size relay limits with
// margin, not to decide whether one particular envelope will fit.
func (l Limits) EstimatedWireBytes() int {
	const nip44Overhead = 1 + 32 + 32 // version + nonce + MAC
	raw := l.MaxEnvelopeBytes + nip44Overhead
	return (raw + 2) / 3 * 4 // base64, rounded up
}
