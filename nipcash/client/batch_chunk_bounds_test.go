package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// NIP-CASH §Chunked Replies: "A client MUST bound total by the number of items it
// requested." One item, a declared total of 1000 and one genuine chunk is a
// complete answer, not a wait until not_after followed by ErrIncompleteReply.
func TestCollectReply_TotalIsBoundedByItemsRequested(t *testing.T) {
	limits := transport.DefaultLimits()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	p := statusPacked(nonce, time.Now().Add(3*time.Second).Unix(), "only")
	var replyKey [32]byte
	copy(replyKey[:], strings.Repeat("t", 32))
	s := hostileSession(limits, strings.Repeat("b", 64))

	ch := make(chan *nip01.Event, 1)
	ch <- sealChunk(t, replyKey, limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 1, Total: 1000,
		Results: []transport.Result{{ID: "only", ResultType: "cash_status", Result: []byte(`{}`)}},
	})

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := s.collectReply(ctx, ch, replyKey, p, 0)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waited %s for chunks that a 1-item request cannot have", elapsed)
	}
	if err != nil {
		t.Fatalf("complete 1-item answer reported err = %v", err)
	}
	if len(got) != 1 || !got[0].Succeeded() {
		t.Fatalf("outcomes = %+v, want item answered", got)
	}
}

// §Chunked Replies: a decided refusal survives an incomplete reply. The hub's own
// NOT_FOUND must reach the single-item caller, not be replaced by "incomplete".
func TestOneItemOutcome_DecidedRefusalBeatsIncomplete(t *testing.T) {
	err := oneItemOutcome(OutcomeError,
		&transport.ResultError{Code: "NOT_FOUND", Message: "not addressed to you"},
		errors.Join(ErrIncompleteReply), "cash_redeem")
	var we *relayclient.WalletError
	if !errors.As(err, &we) || we.Code != "NOT_FOUND" {
		t.Fatalf("err = %v, want the hub's NOT_FOUND", err)
	}
}

// §Chunked Replies: a later chunk that fails to decode does not discard a decided
// outcome from an earlier one. For a carve that chunk is the only copy of a new
// bill's token.
func TestCollectReply_LaterBadChunkKeepsEarlierOutcomes(t *testing.T) {
	limits := transport.DefaultLimits()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	p := statusPacked(nonce, time.Now().Add(5*time.Second).Unix(), "x1", "x2")
	var replyKey [32]byte
	copy(replyKey[:], strings.Repeat("w", 32))
	s := hostileSession(limits, strings.Repeat("b", 64))

	ch := make(chan *nip01.Event, 2)
	ch <- sealChunk(t, replyKey, limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 1, Total: 2,
		Results: []transport.Result{{ID: "x1", ResultType: "cash_status", Result: []byte(`{"new_wallet_token":"only-copy"}`)}},
	})
	// Chunk 2 answers another request: unusable as a whole, so it decides nothing.
	other, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	ch <- sealChunk(t, replyKey, limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: other, Seq: 2, Total: 2,
		Results: []transport.Result{{ID: "x2", ResultType: "cash_status", Result: []byte(`{}`)}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := s.collectReply(ctx, ch, replyKey, p, 0)
	if err == nil {
		t.Fatal("the bad chunk must still be reported")
	}
	kept := false
	for _, o := range got {
		if o.ID == "x1" && o.Succeeded() {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("chunk 1's answer for x1 was discarded; outcomes=%+v err=%v", got, err)
	}
}
