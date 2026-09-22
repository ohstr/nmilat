package relay

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
)

// These tests cover the failure mode written up in
// docs/relay-scan-transaction-blocks-under-load.md: storeScan.scan used to run
// the whole collect-and-deliver loop for a REQ inside one bolt.DB.View, so the
// read transaction stayed open for as long as delivery took. bbolt cannot
// re-mmap the file while a read transaction is open, and Go's sync.RWMutex
// blocks new readers once a writer is waiting on that remap -- so one parked
// scan plus one file-growing write stalled the whole store.
//
// TestScanDoesNotHoldReadTransactionAcrossDelivery,
// TestGrowingWriteDuringStalledScanDoesNotBlockUnrelatedReaders and
// TestDeliveryLoopDoesNotDeadlockWhenAWriteGrowsTheStore assert the invariant
// the fix established: each pass is batched inside a short db.View and only
// delivered once that transaction has closed (see collectBatch and
// deliverBatch). All three failed deterministically against the old scan --
// that is how the report was reproduced -- and now guard against regressing.
//
// TestBoltNewReadTransactionBlocksBehindAGrowingWrite instead pins bbolt's own
// locking semantics, independent of this package. It passes today, and exists
// so that if any of the above ever changes behavior it is immediately clear
// which layer moved.

const (
	// A write this size cannot be absorbed by a freshly created store's
	// existing mmap, so committing it forces at least one db.mmap() -- which
	// is the operation that has to wait for every open read transaction.
	growEventCount = 32
	growEventBytes = 256 * 1024
)

// newStoreAtPath is newStore, but it also returns the database path so a test
// can stat the file and confirm a write really did grow it.
func newStoreAtPath(t testing.TB) (*EventStore, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "scan-txn-test.db")
	store, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	return store, path
}

func fileSize(t testing.TB, path string) int64 {
	t.Helper()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

// createBigEvents builds signed events with large content. CreateEvents' own
// events are a few hundred bytes each, far too small to move the store's file
// size; nothing in the store path caps content length (MaxMessageLength only
// bounds an incoming websocket frame, see session.go), so oversized content is
// the cheapest way to force a grow.
func createBigEvents(t testing.TB, count, kind, contentBytes int) []*nip01.Event {
	t.Helper()

	const privKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

	filler := strings.Repeat("x", contentBytes)
	base := uint64(time.Now().Unix())

	events := make([]*nip01.Event, 0, count)
	for i := 0; i < count; i++ {
		ev := &nip01.Event{
			PubKey:    publicKey,
			CreatedAt: base + uint64(i),
			Kind:      kind,
			Content:   fmt.Sprintf("%d-%s", i, filler),
		}
		if err := ev.Sign(privKey); err != nil {
			t.Fatalf("failed to sign big event %d: %v", i, err)
		}
		events = append(events, ev)
	}
	return events
}

// growStore submits a write large enough to force bolt to extend and re-mmap
// the file. It runs in the background and signals completion on the returned
// channel rather than blocking: the whole point is that this write can get
// stuck, so a caller must never wait on it unconditionally.
func growStore(t testing.TB, store *EventStore, kind int) <-chan struct{} {
	t.Helper()

	events := createBigEvents(t, growEventCount, kind, growEventBytes)

	done := make(chan struct{})
	go func() {
		defer close(done)

		task := NewEventInsertTask(events)
		store.Execute(context.Background(), task)
		select {
		case <-task.Completed():
		case <-task.Errors():
		}
	}()
	return done
}

// minOpenTxNOver samples bolt's count of currently open read transactions over
// d and returns the smallest value seen.
//
// The minimum, not the maximum, is what distinguishes the bug from ordinary
// background activity: a transaction that is *held* keeps the count above zero
// for the entire window, whereas an incidental short-lived read (the
// housekeeper, say) only lifts it momentarily and the minimum still reads 0.
func minOpenTxNOver(store *EventStore, d time.Duration) int {
	deadline := time.Now().Add(d)
	minimum := store.db.Stats().OpenTxN
	for time.Now().Before(deadline) {
		if n := store.db.Stats().OpenTxN; n < minimum {
			minimum = n
		}
		time.Sleep(time.Millisecond)
	}
	return minimum
}

// parkedScan is a scan deliberately stalled part-way through delivery, with
// whatever transaction state that implies still in place.
type parkedScan struct {
	outgoing chan *PotentialEvent
	cancel   context.CancelFunc
	wg       *sync.WaitGroup
	fetchErr chan error
	// released makes release idempotent: tests call it explicitly once the
	// interesting assertions are done, and again from t.Cleanup so the
	// failure path is covered too.
	released sync.Once
}

// parkScan starts a scan writing into a subscription-sized channel (see
// subscription.go's eventBufferCapacity, which is exactly what a real REQ
// gets) and returns once that channel is full -- i.e. once the scan is parked
// mid-delivery on its `potEvents <- potEvent` send.
//
// Nothing drains the channel, which is what a slow subscriber looks like from
// the store's side.
func parkScan(t *testing.T, store *EventStore, filters *nip01.SubscriptionFilterGroup) *parkedScan {
	t.Helper()

	q := CreateQueryWithFilters(t, store, filters)
	ctx, cancel := context.WithCancel(context.Background())

	ps := &parkedScan{
		outgoing: make(chan *PotentialEvent, eventBufferCapacity),
		cancel:   cancel,
		wg:       &sync.WaitGroup{},
		fetchErr: make(chan error, 1),
	}

	go func() {
		ps.fetchErr <- q.Fetch(ctx, ps.outgoing, ps.wg, false)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for len(ps.outgoing) < eventBufferCapacity {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("scan never filled the %d-event delivery buffer (got %d) -- "+
				"the store needs more events matching this filter for the scan to park",
				eventBufferCapacity, len(ps.outgoing))
		}
		time.Sleep(2 * time.Millisecond)
	}

	return ps
}

// release unwinds the parked scan. Cancelling frees its blocked send through
// the `case <-ctx.Done()` branch, so the scan returns -- which, before the fix,
// was also the only thing that closed its read transaction and let a write
// blocked on the remap proceed. Draining alongside that covers sends already
// in flight.
//
// Tests must register this before anything that waits on the store, and must
// run it on the failure path too: these tests intentionally create blocked
// goroutines, and EventStore.Close takes bolt's mmaplock and waits on
// workersWg, so it hangs if anything is still parked.
func (ps *parkedScan) release(t *testing.T) {
	t.Helper()

	ps.released.Do(func() {
		ps.cancel()

		deadline := time.Now().Add(15 * time.Second)
		for {
			select {
			case <-ps.fetchErr:
				for {
					select {
					case <-ps.outgoing:
						ps.wg.Done()
					default:
						return
					}
				}
			case <-ps.outgoing:
				ps.wg.Done()
			case <-time.After(10 * time.Millisecond):
				if time.Now().After(deadline) {
					t.Errorf("parked scan did not unwind within 15s of cancellation")
					return
				}
			}
		}
	})
}

// TestScanDoesNotHoldReadTransactionAcrossDelivery is the cheapest and most
// direct statement of the bug: no writer, no network, no timing race. It just
// parks a scan mid-delivery and asks bolt how many read transactions are open.
//
// The scan should hold a transaction only while it reads; delivery to a
// subscriber must happen with no transaction open, because delivery is
// unbounded in time (a real one goes through session.go's sendPacket, which
// blocks on conn.WriteJSON for up to DataWriteTimeout *per event*, serially).
func TestScanDoesNotHoldReadTransactionAcrossDelivery(t *testing.T) {
	store := newStoreWithEvents(t, CreateEvents(t, 200, 1))

	if baseline := minOpenTxNOver(store, 300*time.Millisecond); baseline != 0 {
		t.Fatalf("setup: store already holds %d read transaction(s) open with no scan running; "+
			"this test cannot attribute a held transaction to the scan", baseline)
	}

	ps := parkScan(t, store, CreateFilter([]int{1}, 500))
	t.Cleanup(func() { ps.release(t) })

	if held := minOpenTxNOver(store, 500*time.Millisecond); held > 0 {
		t.Fatalf("scan held %d bolt read transaction(s) open continuously for 500ms while %d "+
			"event(s) sat undelivered in the subscription buffer.\n"+
			"Delivery is running inside the scan's db.View again, so the transaction "+
			"stays open for as long as the subscriber takes to drain -- blocking bbolt "+
			"from re-mmapping the file, and so blocking every other connection on the relay.",
			held, len(ps.outgoing))
	}
}

// TestGrowingWriteDuringStalledScanDoesNotBlockUnrelatedReaders covers the
// blast radius: one stalled subscriber must not be able to stop unrelated work
// elsewhere in the process.
//
// A scan parked mid-delivery holds its read transaction; a write that needs to
// grow the file then blocks in db.mmap's mmaplock.Lock(); and from that moment
// Go's RWMutex refuses new RLock acquisitions, so every subsequent read
// transaction -- from any connection, on any filter -- blocks too. Reads and
// writes issued while some other subscriber is slow should simply complete.
func TestGrowingWriteDuringStalledScanDoesNotBlockUnrelatedReaders(t *testing.T) {
	store, dbPath := newStoreAtPath(t)
	InsertTestEvents(t, store, CreateEvents(t, 200, 1))

	startSize := fileSize(t, dbPath)

	ps := parkScan(t, store, CreateFilter([]int{1}, 500))
	t.Cleanup(func() { ps.release(t) })

	writeDone := growStore(t, store, 2)

	// Let the write reach its commit, where the remap happens.
	time.Sleep(500 * time.Millisecond)

	// A brand-new read transaction with nothing to do with the parked scan.
	// This is what every other connection's REQ, and the delivery loop's own
	// FindEventBytes call, has to get through.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = store.FindEventBytes(1)
	}()

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Errorf("an unrelated read transaction was still blocked 5s after it started, " +
			"because a stalled subscriber's scan is holding a bolt read transaction open " +
			"and a growing write is waiting to re-mmap behind it.\n" +
			"Every REQ on every other connection blocks here -- this is the relay-wide stall.")
	}

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Errorf("a file-growing write was still blocked 5s after it started, for the same " +
			"reason -- which is why new EVENT publishes fail while this is happening.")
	}

	// Unwind before asserting the write actually grew the file: on the failure
	// path above, the write has not committed yet.
	ps.release(t)

	select {
	case <-writeDone:
	case <-time.After(30 * time.Second):
		t.Fatal("write never completed even after the parked scan was released")
	}

	// Guards against this test passing vacuously. If the write never needed to
	// extend the file, no remap was required, and nothing above was actually
	// exercised.
	if endSize := fileSize(t, dbPath); endSize <= startSize {
		t.Fatalf("test is vacuous: the database file did not grow (%d -> %d bytes), so no "+
			"re-mmap was ever required; raise growEventCount/growEventBytes", startSize, endSize)
	}
}

// TestDeliveryLoopDoesNotDeadlockWhenAWriteGrowsTheStore is the sharpest form
// of the problem, and it needs no slow or half-dead peer at all.
//
// handlers.go's delivery loop calls s.store.FindEventBytes for every event it
// takes off the subscription channel, and FindEventBytes opens its *own*
// db.View -- a new read transaction. So with a growing write pending:
//
//	the scan holds transaction A open, parked on a full channel
//	-> the growing write waits on mmaplock.Lock() behind A
//	-> the delivery loop's FindEventBytes blocks starting transaction B
//	-> the loop cannot drain the channel
//	-> the scan never finishes, so A never closes
//
// That cycle is self-sustaining, and nothing times out of it: DataWriteTimeout
// only bounds conn.WriteJSON, which this never reaches, so session.go's
// write-failure cancel path never fires either.
//
// The consumer below is deliberately healthy and fast -- it mirrors
// handlers.go:153-160 and never stalls on purpose. A filter matching more than
// eventBufferCapacity events plus one concurrent growing write is the entire
// trigger.
func TestDeliveryLoopDoesNotDeadlockWhenAWriteGrowsTheStore(t *testing.T) {
	const want = 200

	store, dbPath := newStoreAtPath(t)
	InsertTestEvents(t, store, CreateEvents(t, want, 1))

	startSize := fileSize(t, dbPath)

	ps := parkScan(t, store, CreateFilter([]int{1}, 500))
	t.Cleanup(func() { ps.release(t) })

	writeDone := growStore(t, store, 2)
	time.Sleep(500 * time.Millisecond)

	// The delivery loop, as handlers.go runs it. The stop channel keeps it
	// from outliving the test and calling into the store while it closes;
	// registering it after ps.release means LIFO cleanup stops the consumer
	// first, then drains.
	stopConsumer := make(chan struct{})
	t.Cleanup(func() { close(stopConsumer) })

	delivered := make(chan uint64, want)
	go func() {
		for {
			select {
			case pe := <-ps.outgoing:
				if _, err := store.FindEventBytes(pe.Evsid); err == nil {
					select {
					case delivered <- pe.Evsid:
					default:
					}
				}
				ps.wg.Done()
			case <-stopConsumer:
				return
			}
		}
	}()

	// Stop at the first 3s gap with no delivery at all: that is the deadlock,
	// as distinct from merely slow progress.
	seen := 0
	stalled := false
	deadline := time.Now().Add(20 * time.Second)
	for seen < want && !stalled && time.Now().Before(deadline) {
		select {
		case <-delivered:
			seen++
		case <-time.After(3 * time.Second):
			stalled = true
		}
	}

	if seen < want {
		t.Errorf("delivery stopped after %d of %d events and made no further progress for 3s, "+
			"with a perfectly healthy consumer.\n"+
			"The scan's read transaction is open, a growing write is queued behind it, and the "+
			"consumer's own FindEventBytes cannot start a new read transaction -- so it cannot "+
			"drain the channel that the scan is waiting on. Nothing breaks this cycle: "+
			"DataWriteTimeout never applies, because conn.WriteJSON is never reached.",
			seen, want)
	}

	ps.release(t)

	select {
	case <-writeDone:
	case <-time.After(30 * time.Second):
		t.Fatal("write never completed even after the parked scan was released")
	}

	if endSize := fileSize(t, dbPath); endSize <= startSize {
		t.Fatalf("test is vacuous: the database file did not grow (%d -> %d bytes), so no "+
			"re-mmap was ever required; raise growEventCount/growEventBytes", startSize, endSize)
	}
}

// TestBoltNewReadTransactionBlocksBehindAGrowingWrite isolates the bbolt-level
// premise the other tests rest on, with no EventStore involved, and passes
// today. It records three things:
//
//   - starting a *write* transaction does not take mmaplock at all (beginRWTx
//     takes rwlock and metalock only), so it begins fine while a read
//     transaction is open; only the remap during its commit waits
//   - a commit that has to grow the file blocks for as long as any read
//     transaction stays open
//   - once it is waiting, brand-new read transactions block behind it, because
//     Go's RWMutex stops admitting readers once a writer is pending
func TestBoltNewReadTransactionBlocksBehindAGrowingWrite(t *testing.T) {
	bucketName := []byte("premise")

	path := filepath.Join(t.TempDir(), "premise.db")
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		return b.Put(itob(0), []byte("seed"))
	}); err != nil {
		t.Fatal(err)
	}

	held, err := db.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	releaseHeld := sync.OnceFunc(func() { _ = held.Rollback() })
	t.Cleanup(releaseHeld)

	// A write transaction's Begin is not gated on mmaplock, so this succeeds
	// immediately despite `held` being open.
	rw, err := db.Begin(true)
	if err != nil {
		t.Fatalf("starting a write transaction blocked while a read transaction was open: %v", err)
	}
	if err := rw.Rollback(); err != nil {
		t.Fatal(err)
	}

	// The commit is where it waits: this write cannot fit in the current mmap.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_ = db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketName)
			val := bytes.Repeat([]byte("x"), 64*1024)
			for i := 1; i <= 128; i++ {
				if err := b.Put(itob(uint64(i)), val); err != nil {
					return err
				}
			}
			return nil
		})
	}()

	select {
	case <-writeDone:
		t.Fatal("the write finished without ever needing to grow the file, so this test " +
			"proved nothing; increase the volume written above")
	case <-time.After(750 * time.Millisecond):
	}

	newRead := make(chan struct{})
	go func() {
		defer close(newRead)
		tx, err := db.Begin(false)
		if err == nil {
			_ = tx.Rollback()
		}
	}()

	select {
	case <-newRead:
		t.Fatal("expected a new read transaction to block behind the growing write; bbolt's " +
			"locking behavior has changed and the relay-wide stall analysis needs revisiting")
	case <-time.After(500 * time.Millisecond):
	}

	// Dropping the held read transaction lets the remap, and therefore both
	// waiters, through.
	releaseHeld()

	select {
	case <-writeDone:
	case <-time.After(30 * time.Second):
		t.Fatal("growing write never completed after the held read transaction was released")
	}
	select {
	case <-newRead:
	case <-time.After(30 * time.Second):
		t.Fatal("new read transaction never started after the held read transaction was released")
	}
}
