package client

// Session C, Security Auditor A — forged discovery and response integrity.
//
// Attacker model: the SERVER or the TRANSPORT is adversarial. A relay that drops,
// reorders, duplicates or injects; a hub that answers but LIES. Goal: make a
// correct client accept a lie.
//
// Every test here asserts. None of them merely logs.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// hostileSession builds a BatchSession with a known policy, without any relay.
// collectReply is reachable directly, which is the whole reason the transport
// package being pure is an advantage: the hostile-hub reply path can be driven
// from a channel with no network and no timing.
func hostileSession(limits transport.Limits, inbox string) *BatchSession {
	return &BatchSession{
		hubXOnly: strings.Repeat("a", 64),
		announcement: &transport.Announcement{
			Version: transport.AnnouncementVersion,
			Inbox:   inbox,
			Limits: transport.AnnouncedLimits{
				MaxBytes:              limits.MaxEnvelopeBytes,
				MaxItems:              limits.MaxItems,
				MaxConsolidateSources: limits.MaxConsolidateSources,
				PadBucketBytes:        limits.PadBucketBytes,
				MaxVerifyBudget:       limits.MaxVerifyBudget,
			},
		},
	}
}

// sealChunk encrypts one response envelope under the reply key, exactly as a hub
// does. The event carries no kind and no signature on purpose: collectReply
// authenticates a reply by the DERIVED KEY alone, which is correct — only the
// requester and the inbox holder can compute it — so this is the genuine article
// as far as the client can tell.
func sealChunk(t *testing.T, replyKey [32]byte, limits transport.Limits, r transport.ResponseEnvelope) *nip01.Event {
	t.Helper()
	encoded, err := r.EncodeResponse(limits)
	if err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}
	sealed, err := nip44.Encrypt(string(encoded), replyKey[:])
	if err != nil {
		t.Fatalf("nip44.Encrypt: %v", err)
	}
	return &nip01.Event{Kind: transport.KindPrivateResponse, Content: sealed}
}

// --- F3: two chunks, same item id, contradictory answers -------------------
//
// DecodeResponse rejects a duplicate item id WITHIN one chunk ("duplicate result
// for %q"). collectReply merges chunks with a bare append and joinOutcomes builds
// its map with byID[r.ID] = r, which is LAST WINS. So the rule does not survive
// chunking, and which of two contradictory hub statements the client believes is
// decided by ARRIVAL ORDER — i.e. by the relay, which holds no key at all.
func TestAuditC_SecA_CrossChunkDuplicateIDs_ArrivalOrderDecides(t *testing.T) {
	limits := transport.DefaultLimits()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	p := packedEnvelope{
		Envelope: transport.Envelope{Version: transport.EnvelopeVersion, Nonce: nonce},
		ItemIDs:  []string{"bill-1"},
	}
	var replyKey [32]byte
	copy(replyKey[:], strings.Repeat("k", 32))
	s := hostileSession(limits, strings.Repeat("b", 64))

	rich := transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 1, Total: 2,
		Results: []transport.Result{{ID: "bill-1", ResultType: "cash_status",
			Result: []byte(`{"amount_millis":1000000}`)}},
	}
	gone := transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 2, Total: 2,
		Results: []transport.Result{{ID: "bill-1",
			Error: &transport.ResultError{Code: "NOT_FOUND", Message: "no such bill"}}},
	}

	run := func(first, second transport.ResponseEnvelope) ([]ItemOutcome, error) {
		ch := make(chan *nip01.Event, 2)
		ch <- sealChunk(t, replyKey, limits, first)
		ch <- sealChunk(t, replyKey, limits, second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got, err := s.collectReply(ctx, ch, replyKey, p, 0)
		return got, err
	}

	richOutcomes, richErr := run(rich, gone)
	goneOutcomes, goneErr := run(gone, rich)
	t.Logf("rich-then-gone -> err=%v outcomes=%d", richErr, len(richOutcomes))
	t.Logf("gone-then-rich -> err=%v outcomes=%d", goneErr, len(goneOutcomes))

	// The security property: a duplicate item id is malformed inside one chunk, so it
	// must be malformed across chunks of the SAME reply too.
	//
	// Asserted as a REFUSAL in both orders, not merely as order-independence. Sorting
	// by seq would also have made the outcome order-independent, and would still have
	// let the hub choose which answer won by deciding which chunk to number first — the
	// relay loses its say, the hub keeps it. Refusing leaves neither party a choice: a
	// hub that answers one item twice with different content has contradicted itself,
	// and there is no reading of that reply a client should act on.
	if richErr == nil || goneErr == nil {
		t.Errorf("AUDITC-SECA-F3 BUG PRESENT: a contradictory duplicate was ACCEPTED in at "+
			"least one arrival order (rich-first err=%v, gone-first err=%v). A relay that "+
			"reorders two chunks it cannot decrypt then chooses which answer the client "+
			"adopts, and DecodeResponse's own duplicate-id rule does not survive chunking.",
			richErr, goneErr)
		return
	}
	if !errors.Is(richErr, transport.ErrResponseMalformed) || !errors.Is(goneErr, transport.ErrResponseMalformed) {
		t.Errorf("both orders must be refused AS MALFORMED, not by some incidental failure: "+
			"rich-first=%v gone-first=%v",
			richErr, goneErr)
		return
	}
	t.Log("both arrival orders refused the contradictory duplicate as malformed, so neither " +
		"the relay nor the hub can choose which answer the client believes")
}

// --- F4: an envelope-level rejection is collected and then thrown away -----
//
// ResponseEnvelope.Error is documented as "set only for an envelope-level
// rejection, where no item ran". collectReply stores it into merged.Error and
// NOTHING EVER READS merged.Error again — joinOutcomes only walks resp.Results.
// So "no item ran" is delivered to the caller as OutcomeNotServed, whose own
// contract is the opposite: "indistinguishable from an item that executed and
// whose response was lost", and SafeToResend() == false.
//
// Direction of harm: the one signal that makes a cash_redeem SAFE to resend is
// discarded, so a hub can convert every retryable refusal into a permanent
// indeterminacy the caller is told not to resolve by retrying.
func TestAuditC_SecA_EnvelopeLevelErrorIsDiscarded(t *testing.T) {
	limits := transport.DefaultLimits()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	p := packedEnvelope{
		Envelope: transport.Envelope{Version: transport.EnvelopeVersion, Nonce: nonce},
		ItemIDs:  []string{"redeem-1", "redeem-2"},
	}
	var replyKey [32]byte
	copy(replyKey[:], strings.Repeat("q", 32))
	s := hostileSession(limits, strings.Repeat("b", 64))

	ch := make(chan *nip01.Event, 1)
	ch <- sealChunk(t, replyKey, limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 1, Total: 1,
		Error: &transport.ResultError{Code: "RATE_LIMITED", Message: "try again later"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := s.collectReply(ctx, ch, replyKey, p, 0)
	t.Logf("collectReply err=%v", err)
	for _, o := range got {
		t.Logf("  %s state=%v safeToResend=%v error=%+v", o.ID, o.State, o.SafeToResend(), o.Error)
	}

	// Assert the property, not the implementation: an envelope the hub explicitly
	// rejected wholesale MUST reach the caller as something other than silence.
	surfaced := err != nil
	for _, o := range got {
		if o.Error != nil || o.State == OutcomeError {
			surfaced = true
		}
	}
	if !surfaced {
		t.Errorf("AUDITC-SECA-F4 BUG PRESENT: the hub said RATE_LIMITED at envelope level — "+
			"no item ran — and collectReply returned err=%v with every item NotServed and "+
			"SafeToResend()=false. merged.Error is written at batch_send.go:213 and never "+
			"read. A caller cannot tell 'nothing ran, retry' from 'may have been applied, "+
			"do not retry'.", err)
	}
}

// --- F5: an overstated total has no deadline of its own --------------------
//
// collectReply's only exit for a reply that never completes is ctx.Done(). The
// envelope carries NotAfter, and once that has passed no further chunk can be
// legitimately produced — but nothing consults it. A hub that declares total: 2
// and sends one chunk therefore pins the caller's goroutine, subscription and
// relay connection for as long as the CALLER's context allows, which for a
// context without a deadline is forever.
//
// This goes past batch_e2e_test.go:471, which pins that a timeout is not read as
// completeness. The point here is that the timeout is the ONLY bound.
func TestAuditC_SecA_OverstatedTotalHasNoReplyDeadline(t *testing.T) {
	limits := transport.DefaultLimits()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	// Already expired: no honest hub can still be producing chunks for this.
	p := packedEnvelope{
		Envelope: transport.Envelope{
			Version:  transport.EnvelopeVersion,
			Nonce:    nonce,
			NotAfter: time.Now().Add(-10 * time.Minute).Unix(),
		},
		ItemIDs: []string{"x1", "x2"},
	}
	var replyKey [32]byte
	copy(replyKey[:], strings.Repeat("z", 32))
	s := hostileSession(limits, strings.Repeat("b", 64))

	ch := make(chan *nip01.Event, 1)
	ch <- sealChunk(t, replyKey, limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 1, Total: 2,
		Results: []transport.Result{{ID: "x1", Result: []byte(`{}`)}},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		//nolint:contextcheck // deliberately deadline-free: that is the finding
		_, _ = s.collectReply(context.Background(), ch, replyKey, p, 0)
	}()

	select {
	case <-done:
		t.Log("collectReply returned on its own; it has an internal bound")
	case <-time.After(2 * time.Second):
		t.Errorf("AUDITC-SECA-F5 BUG PRESENT: the envelope's not_after passed %s ago and the "+
			"hub declared 2 chunks having sent 1, yet collectReply is still waiting after 2s "+
			"on a context with no deadline. batch_send.go:191-231 has no exit but ctx.Done(), "+
			"so a lying total holds a caller for as long as its context allows.",
			time.Since(time.Unix(p.Envelope.NotAfter, 0)).Truncate(time.Second))
	}
}

// --- control / refutation: an UNDERSTATED total ----------------------------
//
// The brief asks whether a hub that understates total can make a partial reply
// look whole. It cannot, and this is the control that says so: the items in the
// chunks that never counted come back NotServed, never Succeeded. Understating
// total is exactly equivalent to omitting those items, which is a valid final
// answer in this protocol — so it is indistinguishable BY DESIGN and not a
// defect. Recorded as an assertion so a later change cannot quietly break it.
func TestAuditC_SecA_UnderstatedTotalNeverReadsAsWhole(t *testing.T) {
	limits := transport.DefaultLimits()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	p := packedEnvelope{
		Envelope: transport.Envelope{Version: transport.EnvelopeVersion, Nonce: nonce},
		ItemIDs:  []string{"a", "b", "c"},
	}
	var replyKey [32]byte
	copy(replyKey[:], strings.Repeat("u", 32))
	s := hostileSession(limits, strings.Repeat("b", 64))

	ch := make(chan *nip01.Event, 2)
	// "1 of 1", but only one of the three requested items is answered.
	ch <- sealChunk(t, replyKey, limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 1, Total: 1,
		Results: []transport.Result{{ID: "a", Result: []byte(`{}`)}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := s.collectReply(ctx, ch, replyKey, p, 0)
	if err != nil {
		t.Fatalf("collectReply: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d outcomes, want one per requested item", len(got))
	}
	for _, o := range got {
		t.Logf("  %s state=%v", o.ID, o.State)
		if o.ID != "a" && o.Succeeded() {
			t.Errorf("item %s read as success from a reply that never mentioned it", o.ID)
		}
		if o.ID != "a" && o.State != OutcomeNotServed {
			t.Errorf("item %s: state=%v, want NotServed", o.ID, o.State)
		}
	}
	if !got[0].Succeeded() {
		t.Errorf("item a: state=%v, want the one real answer to survive", got[0].State)
	}
	_ = errors.Is(err, ErrIncompleteReply)
}
