package nipIC

// NIP-IC §Verification Model step 3 and §Security Considerations
// (self-attestation, p-tag confusion, stale attestations), one guard at a time.

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// swapSource answers a Fetch for one id with another event.
type swapSource struct {
	*fakeSource
	swap map[string]*nip01.Event
}

func (s swapSource) Fetch(ctx context.Context, ref AttestationRef) (*nip01.Event, error) {
	if ev, ok := s.swap[ref.EventID]; ok {
		return ev, nil
	}
	return s.fakeSource.Fetch(ctx, ref)
}

func TestEvaluate_EachStep3Guard(t *testing.T) {
	ia1, alice, mallory := newKeypair(t), newKeypair(t), newKeypair(t)
	key, _ := NewConnectionKey("discord", evalUserID)
	now := time.Now()

	// A trusted IA attesting its own key is self-attestation, even when trusted.
	self := attest(t, ia1, ia1.pub)
	src := newSource()
	src.publish(self.Event)
	trustIA1 := func(ia string) bool { return ia == ia1.pub }
	if v := Evaluate(context.Background(), key, []*nip01.Event{claimTrusting(t, ia1, self)}, src, trustIA1, now); v[0].State != Spoofed {
		t.Errorf("self-attested by a trusted IA: %+v", v)
	}

	// A claim for another d, returned by a relay that ignores the filter, takes
	// no part: Mallory's own verified account cannot outrank Alice's.
	good := attest(t, ia1, alice.pub)
	other := resign(t, attest(t, ia1, mallory.pub, func(p *AttestationParams) { p.Evidence.UserID = "12345" }), ia1,
		func(ev *nip01.Event) { ev.CreatedAt = good.CreatedAt + 100 })
	src = newSource()
	src.publish(good.Event)
	src.publish(other.Event)
	v := Evaluate(context.Background(), key, []*nip01.Event{claim(t, alice, good), claim(t, mallory, other)}, src, trustIA1, now)
	if len(v) != 1 || v[0].State != Verified || v[0].Pubkey != alice.pub {
		t.Errorf("off-filter claim: %+v", v)
	}

	// p-tag confusion alone: no claim by Alice, Mallory points at Alice's attestation.
	src = newSource()
	src.publish(good.Event)
	v = Evaluate(context.Background(), key, []*nip01.Event{rawClaim(t, mallory, string(key), "discord", good.ID)}, src, trustIA1, now)
	if v[0].State != Spoofed || v[0].Attestation != nil {
		t.Errorf("p mismatch: %+v", v)
	}

	// Expired exactly at its expiration timestamp (NIP-40).
	atExp := resign(t, good, ia1, func(ev *nip01.Event) { setTag(ev, TagExpiration, strconv.FormatInt(now.Unix(), 10)) })
	src = newSource()
	src.publish(atExp.Event)
	at := time.Unix(now.Unix(), 0)
	if v := Evaluate(context.Background(), key, []*nip01.Event{claim(t, alice, atExp)}, src, trustIA1, at); v[0].State != Spoofed {
		t.Errorf("at expiration: %+v", v)
	}

	// A relay answering the reference with another (current) attestation that
	// names Mallory does not verify the claim that referenced a different id.
	stale := good
	cur := resign(t, good, ia1, func(ev *nip01.Event) { ev.CreatedAt++ })
	src = newSource()
	src.publish(cur.Event)
	sw := swapSource{src, map[string]*nip01.Event{stale.ID: cur.Event}}
	if v := Evaluate(context.Background(), key, []*nip01.Event{rawClaim(t, alice, string(key), "discord", stale.ID)}, sw, trustIA1, now); v[0].State != Spoofed {
		t.Errorf("relay substituted the referenced event: %+v", v)
	}

	// content naming another username than the evidence is Spoofed.
	src = newSource()
	src.publish(good.Event)
	lying := rawClaimContent(t, alice, string(key), "discord", `{"username":"bob"}`, good.ID)
	if v := Evaluate(context.Background(), key, []*nip01.Event{lying}, src, trustIA1, now); v[0].State != Spoofed {
		t.Errorf("username mismatch: %+v", v)
	}

	// The same claims without the fault verify: Alice's own claim on the
	// referenced current attestation, one second before its expiration, and
	// content naming the evidence's username.
	src = newSource()
	src.publish(good.Event)
	if v := Evaluate(context.Background(), key, []*nip01.Event{rawClaim(t, alice, string(key), "discord", good.ID)}, src, trustIA1, now); v[0].State != Verified {
		t.Errorf("Alice's own claim: %+v", v)
	}
	honest := rawClaimContent(t, alice, string(key), "discord", `{"username":"alice"}`, good.ID)
	if v := Evaluate(context.Background(), key, []*nip01.Event{honest}, src, trustIA1, now); v[0].State != Verified {
		t.Errorf("username match: %+v", v)
	}
	src = newSource()
	src.publish(atExp.Event)
	if v := Evaluate(context.Background(), key, []*nip01.Event{claim(t, alice, atExp)}, src, trustIA1, at.Add(-time.Second)); v[0].State != Verified {
		t.Errorf("one second before expiration: %+v", v)
	}
}
