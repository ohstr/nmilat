package transport

import (
	"errors"
	"testing"
)

func TestDefaultLimits_AreValid(t *testing.T) {
	if err := DefaultLimits().Validate(); err != nil {
		t.Fatalf("the defaults must be a usable policy: %v", err)
	}
}

// TestDefaultLimits_StayUnderTheNIP44Ceiling pins the constraint that actually
// applies to MaxEnvelopeBytes: it is a PLAINTEXT size, so NIP-44 bounds it.
func TestDefaultLimits_StayUnderTheNIP44Ceiling(t *testing.T) {
	l := DefaultLimits()
	if l.MaxEnvelopeBytes > MaxNIP44Plaintext {
		t.Fatalf("MaxEnvelopeBytes %d exceeds NIP-44's plaintext ceiling %d",
			l.MaxEnvelopeBytes, MaxNIP44Plaintext)
	}
}

// TestLimits_EstimatedWireBytes_ExpandsPastThePlaintextCeiling documents the
// ceiling that is easy to conflate with NIP-44's. The base64 ciphertext is ~4/3
// of the plaintext and it is bounded by the RELAY's max message length, not by
// NIP-44 — so a full envelope legitimately exceeds 65535 bytes ON THE WIRE while
// being a perfectly valid NIP-44 payload.
//
// The number matters operationally: a hub raising MaxEnvelopeBytes has to raise
// its relays' max_message_length too, or the relay drops the event and the caller
// sees silence.
func TestLimits_EstimatedWireBytes_ExpandsPastThePlaintextCeiling(t *testing.T) {
	l := DefaultLimits()
	wire := l.EstimatedWireBytes()

	if wire <= l.MaxEnvelopeBytes {
		t.Errorf("EstimatedWireBytes() = %d, expected it to exceed the %d plaintext size",
			wire, l.MaxEnvelopeBytes)
	}
	// Sanity on the ratio: base64 is 4/3, so expect ~1.33x, never 2x.
	if wire > l.MaxEnvelopeBytes*3/2 {
		t.Errorf("EstimatedWireBytes() = %d, more than 1.5x the plaintext %d — check the maths",
			wire, l.MaxEnvelopeBytes)
	}
	t.Logf("a full default envelope is %d bytes of plaintext and ~%d bytes on the wire; "+
		"relays must accept at least that", l.MaxEnvelopeBytes, wire)
}

func TestLimits_Validate(t *testing.T) {
	valid := DefaultLimits()

	tests := map[string]struct {
		mutate func(*Limits)
		want   error
	}{
		"zero envelope bytes": {func(l *Limits) { l.MaxEnvelopeBytes = 0 }, ErrLimitsNotPositive},
		"zero items":          {func(l *Limits) { l.MaxItems = 0 }, ErrLimitsNotPositive},
		"zero pad bucket":     {func(l *Limits) { l.PadBucketBytes = 0 }, ErrLimitsNotPositive},
		"zero verify budget":  {func(l *Limits) { l.MaxVerifyBudget = 0 }, ErrLimitsNotPositive},
		"negative items":      {func(l *Limits) { l.MaxItems = -1 }, ErrLimitsNotPositive},
		// The one that matters most: a hub must not be able to configure itself
		// past what NIP-44 will actually encrypt.
		"above the NIP-44 ceiling": {
			func(l *Limits) { l.MaxEnvelopeBytes = MaxNIP44Plaintext + 1 },
			ErrLimitsAboveCeiling,
		},
		"pad bucket larger than the ceiling": {
			func(l *Limits) { l.PadBucketBytes = l.MaxEnvelopeBytes + 1 },
			ErrLimitsPadTooLarge,
		},
		"consolidate cap below the two-source minimum": {
			func(l *Limits) { l.MaxConsolidateSources = 1 },
			ErrConsolidateCapTooLow,
		},
		// The one that caught NIP-CASH's own cap of 100.
		"consolidate cap whose maximal item cannot be encrypted": {
			func(l *Limits) { l.MaxConsolidateSources = 100 },
			ErrConsolidateCapTooHigh,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l := valid
			tc.mutate(&l)
			err := l.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want %v", err, tc.want)
			}
		})
	}

	// Exactly at the ceiling is allowed — it is a ceiling, not a bound to stay under.
	atCeiling := valid
	atCeiling.MaxEnvelopeBytes = MaxNIP44Plaintext
	if err := atCeiling.Validate(); err != nil {
		t.Errorf("MaxEnvelopeBytes exactly at the ceiling must be valid: %v", err)
	}
}

// TestLimits_PaddedSize_OnlyLandsOnBuckets is the size-leak property: if padded
// sizes were not multiples of the bucket, the ciphertext length would still
// disclose roughly how much is inside.
func TestLimits_PaddedSize_OnlyLandsOnBuckets(t *testing.T) {
	l := DefaultLimits()
	for n := 1; n <= l.MaxEnvelopeBytes; n += 97 { // stride is coprime-ish to the bucket
		padded, err := l.PaddedSize(n)
		if err != nil {
			t.Fatalf("PaddedSize(%d): %v", n, err)
		}
		if padded%l.PadBucketBytes != 0 {
			t.Fatalf("PaddedSize(%d) = %d, not a multiple of %d", n, padded, l.PadBucketBytes)
		}
		if padded < n {
			t.Fatalf("PaddedSize(%d) = %d, smaller than the input", n, padded)
		}
		if padded-n >= l.PadBucketBytes {
			t.Fatalf("PaddedSize(%d) = %d, padded by a whole bucket or more", n, padded)
		}
	}
}

// TestLimits_PaddedSize_SmallEnvelopesLookLikeBatches is the point of padding: a
// one-item read and a several-item batch must be the same size on the wire.
func TestLimits_PaddedSize_SmallEnvelopesLookLikeBatches(t *testing.T) {
	l := DefaultLimits()
	oneItem, err := l.PaddedSize(700) // a single cash_status with its proof
	if err != nil {
		t.Fatal(err)
	}
	fewItems, err := l.PaddedSize(3500) // three or four of them
	if err != nil {
		t.Fatal(err)
	}
	if oneItem != fewItems {
		t.Errorf("a 1-item envelope (%d) and a small batch (%d) are distinguishable by size",
			oneItem, fewItems)
	}
}

// TestEstimatedConsolidateItemBytes_MatchesMeasurements pins the cost model the
// consolidate cap is validated against. The three figures are from encoding real
// items; if the item shape changes, this fails and the cap must be re-derived
// rather than silently drifting out of step with reality.
func TestEstimatedConsolidateItemBytes_MatchesMeasurements(t *testing.T) {
	for sources, want := range map[int]int{2: 2914, 10: 10530, 100: 96210} {
		if got := EstimatedConsolidateItemBytes(sources); got != want {
			t.Errorf("EstimatedConsolidateItemBytes(%d) = %d, measured %d", sources, got, want)
		}
	}
}

// TestDefaultConsolidateCap_IsTheLargestThatComfortablyFits documents why 48 and
// not some other number, and pins that NIP-CASH's standard-path cap of 100 is
// genuinely impossible here — not merely over the configured limit, but over
// NIP-44's hard ceiling, so no envelope size could accommodate it.
func TestDefaultConsolidateCap_IsTheLargestThatComfortablyFits(t *testing.T) {
	l := DefaultLimits()

	atDefault := EstimatedConsolidateItemBytes(l.MaxConsolidateSources)
	if atDefault > l.MaxEnvelopeBytes {
		t.Fatalf("the default cap does not fit: %d bytes > %d", atDefault, l.MaxEnvelopeBytes)
	}
	t.Logf("%d sources is ~%d bytes of a %d byte envelope, leaving ~%d spare",
		l.MaxConsolidateSources, atDefault, l.MaxEnvelopeBytes, l.MaxEnvelopeBytes-atDefault)

	// NIP-CASH's standard cap cannot be encrypted at all.
	if at100 := EstimatedConsolidateItemBytes(100); at100 <= MaxNIP44Plaintext {
		t.Errorf("100 sources is %d bytes, which would fit NIP-44's %d ceiling — "+
			"the whole reason for a lower private-mode cap has gone away",
			at100, MaxNIP44Plaintext)
	}
}

// TestMaxSourcesForEnvelope_DerivesACoherentCap covers the reason the helper
// exists: the source cap and the envelope size are not independent, so a hub that
// shrinks one must get a matching value for the other without doing the
// arithmetic itself.
func TestMaxSourcesForEnvelope_DerivesACoherentCap(t *testing.T) {
	for _, envelopeBytes := range []int{8 * 1024, 16 * 1024, 32 * 1024, DefaultMaxEnvelopeBytes, MaxNIP44Plaintext} {
		got := MaxSourcesForEnvelope(envelopeBytes)

		if fits := EstimatedConsolidateItemBytes(got); fits > envelopeBytes {
			t.Errorf("MaxSourcesForEnvelope(%d) = %d, whose item is %d bytes — does not fit",
				envelopeBytes, got, fits)
		}
		// And it must be the LARGEST that fits, not merely a safe one.
		if oneMore := EstimatedConsolidateItemBytes(got + 1); oneMore <= envelopeBytes {
			t.Errorf("MaxSourcesForEnvelope(%d) = %d, but %d would also fit (%d bytes)",
				envelopeBytes, got, got+1, oneMore)
		}
		t.Logf("a %6d byte envelope affords %2d consolidate sources", envelopeBytes, got)
	}
}

// TestMaxSourcesForEnvelope_FloorsAtTheProtocolMinimum pins the honest failure
// mode: an envelope too small for two sources yields the minimum rather than
// zero, so Validate rejects the policy and the operator is told, instead of the
// hub silently forbidding consolidate.
func TestMaxSourcesForEnvelope_FloorsAtTheProtocolMinimum(t *testing.T) {
	tiny := 1024 // far too small for even two sources
	got := MaxSourcesForEnvelope(tiny)
	if got != minConsolidateSources {
		t.Fatalf("MaxSourcesForEnvelope(%d) = %d, want the %d-source floor", tiny, got, minConsolidateSources)
	}

	bad := DefaultLimits()
	bad.MaxEnvelopeBytes = tiny
	bad.PadBucketBytes = 256
	bad.MaxConsolidateSources = got
	if err := bad.Validate(); err == nil {
		t.Error("a policy whose envelope cannot hold two sources must be rejected, not accepted")
	}
}

func TestLimits_PaddedSize_RejectsOversize(t *testing.T) {
	l := DefaultLimits()

	// Exactly at the limit is fine.
	if _, err := l.PaddedSize(l.MaxEnvelopeBytes); err != nil {
		t.Errorf("PaddedSize at exactly the limit must succeed: %v", err)
	}
	// One byte over pads into the next bucket, which is over the limit.
	if _, err := l.PaddedSize(l.MaxEnvelopeBytes + 1); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("PaddedSize(limit+1) = %v, want ErrEnvelopeTooLarge", err)
	}
	// And the error must arrive locally rather than as a silent truncation.
	if _, err := l.PaddedSize(MaxNIP44Plaintext * 2); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("PaddedSize(huge) = %v, want ErrEnvelopeTooLarge", err)
	}
}

// TestLimits_PaddedSize_HonoursCustomPolicy checks the knobs are actually knobs —
// a hub configuring a tighter policy gets that policy, not the default.
func TestLimits_PaddedSize_HonoursCustomPolicy(t *testing.T) {
	// Note the consolidate cap: an 8 KiB envelope only affords 7 sources
	// (1010 + 7*952 = 7674), which is the coherence Validate enforces.
	tight := Limits{
		MaxEnvelopeBytes:      8 * 1024,
		MaxItems:              4,
		PadBucketBytes:        1024,
		MaxVerifyBudget:       10,
		MaxConsolidateSources: 7,
	}
	if err := tight.Validate(); err != nil {
		t.Fatalf("a tighter policy must be valid: %v", err)
	}
	padded, err := tight.PaddedSize(1025)
	if err != nil {
		t.Fatal(err)
	}
	if padded != 2048 {
		t.Errorf("PaddedSize(1025) = %d, want 2048 under a 1 KiB bucket", padded)
	}
	if _, err := tight.PaddedSize(9000); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("a tighter ceiling must reject 9000 bytes, got %v", err)
	}
}
