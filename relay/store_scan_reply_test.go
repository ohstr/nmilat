package relay

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/wire"
)

// Salvaged from the branch worktree-scan-txn-repro, which never merged.
//
// That branch was the ORIGINAL report and repro for the scan-transaction stall
// (docs/relay-scan-transaction-blocks-under-load.md). main has since fixed the
// bug and carries its own regression suite in store_scan_transaction_test.go,
// whose four tests are the post-fix inversions of the branch's first three — so
// merging the branch wholesale would have reverted the doc to its pre-fix wording
// and re-added a test that now FAILS by design, because it asserts the bug is
// still present.
//
// These two are the exception: they have no counterpart in main, they are about
// the reply path rather than the stall, and they PASS against the fixed code.
// Deleting the branch without salvaging them would have lost real coverage, which
// is why they are here rather than there.
//
// Dropped from that branch, with the reason, so nobody re-salvages them:
//
//	TestScanHoldsBoltReadTransactionOpenWhileDeliveryStalls  -> inverted in main as
//	    TestScanDoesNotHoldReadTransactionAcrossDelivery
//	TestGrowingWriteBlocksBehindStalledScanTransaction       -> inverted in main as
//	    TestGrowingWriteDuringStalledScanDoesNotBlockUnrelatedReaders
//	TestNewReadsBlockBehindRemapWaitingOnStalledScan         -> covered in main by
//	    TestBoltNewReadTransactionBlocksBehindAGrowingWrite
//	TestLiveSubscriptionPinsReadTransactionWhenSocketStops   -> a demonstration the
//	    fix obsoletes; it fails against main with its own message, "the read
//	    transaction closed -- delivery to a stalled socket did not hold it open,
//	    contradicting the report". Main's
//	    TestScanDoesNotHoldReadTransactionAcrossDelivery is its inverted form.
func TestReplyBlocksInsteadOfDroppingWhenOutgoingBufferIsFull(t *testing.T) {
	r := &replyer{
		incoming: make(chan wire.SubscriptionResponse, 2),
		closeCh:  make(chan interface{}),
	}

	r.reply(&wire.EOSESubscriptionResponse{SubscriptionID: "a"})
	r.reply(&wire.EOSESubscriptionResponse{SubscriptionID: "b"})
	if len(r.incoming) != 2 {
		t.Fatalf("setup: expected 2 buffered replies, got %d", len(r.incoming))
	}

	third := make(chan struct{})
	go func() {
		defer close(third)
		r.reply(&wire.EOSESubscriptionResponse{SubscriptionID: "c"})
	}()

	select {
	case <-third:
		t.Fatal("reply returned while the outgoing buffer was full -- if it dropped the packet instead of " +
			"blocking, backpressure would never reach the scan's read transaction (but events would be lost)")
	case <-time.After(250 * time.Millisecond):
	}

	// Draining one slot lets it through: it was blocked, not dropped.
	<-r.incoming
	select {
	case <-third:
	case <-time.After(5 * time.Second):
		t.Fatal("reply stayed blocked even after the outgoing buffer drained a slot")
	}
}

// TestReplyUnblocksOnSessionClose is the escape hatch that bounds the
// above: a closed session releases a blocked reply, which is what lets
// the write-failure -> cancel path in session.go eventually unwind a
// stalled scan. It only fires once the session actually closes, which is
// the report's point about a merely slow (not yet failed) peer.
func TestReplyUnblocksOnSessionClose(t *testing.T) {
	r := &replyer{
		incoming: make(chan wire.SubscriptionResponse, 1),
		closeCh:  make(chan interface{}),
	}
	r.reply(&wire.EOSESubscriptionResponse{SubscriptionID: "a"})

	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		r.reply(&wire.EOSESubscriptionResponse{SubscriptionID: "b"})
	}()

	select {
	case <-blocked:
		t.Fatal("setup: reply should be blocked on a full buffer")
	case <-time.After(100 * time.Millisecond):
	}

	close(r.closeCh)
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("reply stayed blocked after the session closed")
	}
}

// TestLiveSubscriptionPinsReadTransactionWhenSocketStops is the
// end-to-end shape of the report: a real websocket subscriber that stops
// reading, over the real REQ path, pinning a real bbolt read transaction.
//
// It is the one test here that proves the 55 + 512 + socket-buffer slack
// documented above is actually crossable in practice rather than just in
// principle.
