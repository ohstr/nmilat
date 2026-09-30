package transport

// Session C, Security Auditor A — the announced policy is a hostile input.
//
// ParseAnnouncement's own comment says "A hostile or misconfigured hub must not be
// able to talk a client into building something unencryptable, so the announced
// policy is validated rather than adopted." Limits.Validate checks exactly that —
// encryptability — and nothing else. It has no floor on PadBucketBytes, so the one
// announced value whose whole purpose is PRIVACY is not defended at all.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// hostilePolicy is a policy a hub can announce today. Every value is legal:
// positive, inside NIP-44's ceiling, and with a consolidate cap whose maximal
// item still fits. Only the padding bucket is degenerate.
func hostilePolicy() Limits {
	l := DefaultLimits()
	l.PadBucketBytes = 1 // "pad to a multiple of 1" — i.e. do not pad
	return l
}

// TestAuditC_SecA_AnnouncedPadBucketHasNoFloor is TestEnvelope_EncodePadsToBuckets
// re-run against a policy the hub chose. Same assertion, hostile input.
func TestAuditC_SecA_AnnouncedPadBucketHasNoFloor(t *testing.T) {
	limits := hostilePolicy()

	// ValidateAnnounced, not Validate: the floor is a constraint on a policy arriving
	// from a hub, not on policy coherence in general. Validate deliberately still
	// accepts a small bucket, because a locally-constructed policy is the caller's own
	// choice and the bucketing tests legitimately probe the maths with small numbers.
	// The boundary that matters is adoption, which is what this asserts.
	if err := limits.ValidateAnnounced(); err == nil {
		t.Errorf("AUDITC-SECA-F2 BUG PRESENT: an announced pad_bucket_bytes of %d was ACCEPTED; "+
			"it defeats padding entirely, and the sizes logged below show a relay reading the "+
			"exact batch count off the ciphertext length", limits.PadBucketBytes)
	} else {
		t.Logf("announced pad_bucket_bytes %d refused: %v", limits.PadBucketBytes, err)
	}
	if err := limits.Validate(); err != nil {
		t.Skipf("Validate now rejects a degenerate pad bucket (%v) — finding fixed", err)
	}

	sizes := map[int]struct{}{}
	for items := 1; items <= 8; items++ {
		env := newTestEnvelope(t)
		for i := 2; i <= items; i++ {
			env.Items = append(env.Items, newTestItem(t, fmt.Sprintf("%d", i), "cash_status", `{}`, env.Nonce))
		}
		plaintext, err := env.Encode(limits)
		if err != nil {
			t.Fatalf("Encode with %d items: %v", items, err)
		}
		sizes[len(plaintext)] = struct{}{}
		t.Logf("%d items -> %d bytes of plaintext", items, len(plaintext))
	}

	// This is the codebase's own privacy assertion, verbatim from
	// TestEnvelope_EncodePadsToBuckets: 1-8 small items must not each have their
	// own distinguishable size.
	if len(sizes) > 3 {
		t.Logf("AUDITC-SECA-F2 (why the floor exists): under a pad_bucket_bytes of %d, "+
			"1-8 items produce %d distinct wire sizes (the default policy collapses them to "+
			"3) — which is exactly the leak ValidateAnnounced now refuses to adopt.",
			limits.PadBucketBytes, len(sizes))
	}
}

// TestAuditC_SecA_ParseAnnouncementAcceptsNoPadding asserts the gate, not the
// consequence: the function documented as the place a hostile policy is refused
// must refuse this one.
func TestAuditC_SecA_ParseAnnouncementAcceptsNoPadding(t *testing.T) {
	nodePriv, nodeXOnly := testKeypair(t)
	_, inbox := testKeypair(t)

	content, err := json.Marshal(Announcement{
		Version: AnnouncementVersion,
		Inbox:   inbox,
		Limits:  announcedFrom(hostilePolicy()),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := nip01.NewEvent(KindHubAnnouncement, string(content))
	if err := ev.Sign(nodePriv); err != nil {
		t.Fatal(err)
	}
	_ = nodeXOnly

	got, err := ParseAnnouncement(ev, ev.PubKey)
	if err != nil {
		t.Logf("ParseAnnouncement refused it: %v — finding fixed", err)
		return
	}
	t.Errorf("AUDITC-SECA-F2 BUG PRESENT: ParseAnnouncement accepted an announced "+
		"pad_bucket_bytes of %d. The client will adopt it (BatchSession.Limits returns the "+
		"announced values verbatim) and Envelope.Encode will then pad to a multiple of 1, "+
		"which is no padding. The announced policy is validated for encryptability only; "+
		"the value whose only purpose is privacy has no floor.",
		got.Limits.PadBucketBytes)
}

// TestAuditC_SecA_ReplayedOldPadBucketReinstatesAKnownLeak needs no key compromise
// and no hostile hub. limits.go records that DefaultPadBucketBytes was RAISED from
// 4 KiB to 8 KiB because at 4 KiB "1 to 8 items fell into FOUR distinguishable
// padded sizes instead of three, so the padding had begun disclosing the batch
// count — the exact leak it exists to close."
//
// Any hub that published an announcement before that change has a validly signed
// 4 KiB announcement in existence forever. Because ParseAnnouncement checks no
// freshness (see auditC_seca_announcement_rollback_test.go), a relay can serve that
// old event and reinstate a leak this codebase already found and fixed.
func TestAuditC_SecA_ReplayedOldPadBucketReinstatesAKnownLeak(t *testing.T) {
	limits := DefaultLimits()
	limits.PadBucketBytes = 4 * 1024 // the previously shipped default

	if err := limits.Validate(); err != nil {
		t.Fatalf("the previously shipped default must still validate: %v", err)
	}

	sizes := map[int]struct{}{}
	for items := 1; items <= 8; items++ {
		env := newTestEnvelope(t)
		for i := 2; i <= items; i++ {
			env.Items = append(env.Items, newTestItem(t, fmt.Sprintf("%d", i), "cash_status", `{}`, env.Nonce))
		}
		plaintext, err := env.Encode(limits)
		if err != nil {
			t.Fatalf("Encode with %d items: %v", items, err)
		}
		sizes[len(plaintext)] = struct{}{}
	}
	t.Logf("at the retired 4 KiB bucket, 1-8 items produce %d distinct sizes", len(sizes))
	if len(sizes) > 3 {
		t.Errorf("AUDITC-SECA-F1/F2 BUG PRESENT: a relay replaying the hub's own pre-change "+
			"announcement reinstates the batch-count leak — %d distinct sizes for 1-8 items, "+
			"against 3 under the current default. No key compromise and no hostile hub: the "+
			"signature is the hub's own, and nothing checks how old it is.", len(sizes))
	}
}
