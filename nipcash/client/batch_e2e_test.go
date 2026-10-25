package client

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// fakeHub is the thin wrapper these tests have always used around the shared fake
// Hub, internal/cashtest.FakeHub. The fields keep their old meaning and are read
// when the Hub starts; the hub half (decrypt, decide per item, reply in chunks
// under the derived reply key) is cashtest's, so every E2E test exercises the same
// fake the conformance suite runs against.
type fakeHub struct {
	hubPriv, hubXOnly     string
	inboxPriv, inboxXOnly string
	limits                transport.Limits

	// decide says how to answer one item. Returning nil OMITS it, which is how a real
	// hub answers an item it cannot serve.
	decide func(item transport.Item) *transport.Result

	// chunkSize, when > 0, splits the reply into events of that many results.
	// dropChunk, when > 0, is a seq the hub declines to publish.
	chunkSize int
	dropChunk int

	once sync.Once
	core *cashtest.FakeHub

	mu   sync.Mutex
	subs []chan *nip01.Event
}

// hub starts the shared fake on first use, with this wrapper's settings.
func (h *fakeHub) hub(t *testing.T, relays ...*cashtest.Relay) *cashtest.FakeHub {
	h.once.Do(func() {
		opts := []cashtest.Option{
			cashtest.WithKeys(h.hubPriv, h.inboxPriv),
			cashtest.WithLimits(h.limits),
			cashtest.WithChunks(h.chunkSize, h.dropChunk),
			cashtest.WithDecide(func(c cashtest.ItemCtx) *transport.Result { return h.decide(c.Item) }),
		}
		if len(relays) > 0 {
			opts = append(opts, cashtest.WithRelays(relays...))
		}
		h.core = cashtest.NewFakeHub(t, opts...)
	})
	return h.core
}

// register and broadcast serve tests that run their own relay server and call
// handleRequest themselves.
func (h *fakeHub) register(ch chan *nip01.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs = append(h.subs, ch)
}

func (h *fakeHub) broadcast(ev *nip01.Event) {
	h.mu.Lock()
	subs := append([]chan *nip01.Event(nil), h.subs...)
	h.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (h *fakeHub) envelopes() []transport.Envelope {
	if h.core == nil {
		return nil
	}
	return h.core.Envelopes()
}

// handleRequest is the hub half, for a test's own relay server.
func (h *fakeHub) handleRequest(t *testing.T, ev *nip01.Event) {
	t.Helper()
	for _, out := range h.hub(t).Serve(ev) {
		h.broadcast(out)
	}
}

// startFakeHub serves the hub on one in-process relay and returns its URL.
func startFakeHub(t *testing.T, h *fakeHub) string {
	t.Helper()
	relay := cashtest.NewRelay(t)
	h.hub(t, relay)
	return relay.URL()
}

// alwaysSucceed answers every item with an empty successful result.
func alwaysSucceed(item transport.Item) *transport.Result {
	return &transport.Result{ID: item.ID, ResultType: item.Method, Result: json.RawMessage(`{}`)}
}

// TestBatch_EndToEnd_ManyBillsInOneEvent is the claim the whole transport rests on.
//
// Twelve bills, each a different wallet with its own key, read in ONE relay event — and
// the assertion is not just that it works but that the hub saw exactly one envelope. On
// the standard transport this is twelve p-tagged events, which publishes how many bills
// the holder has and ties them together by timing.
func TestBatch_EndToEnd_ManyBillsInOneEvent(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	relay := startFakeHub(t, hub)

	items := make([]BatchStatus, 0, 12)
	for i := 0; i < 12; i++ {
		priv, target := sessionKeypair(t)
		items = append(items, BatchStatus{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)})
	}

	ctx, cancel := e2eContext(t)
	defer cancel()

	c := &Client{}
	s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("NewBatchSession() error = %v", err)
	}

	outcomes, err := s.StatusMany(ctx, items)
	if err != nil {
		t.Fatalf("StatusMany() error = %v", err)
	}
	if len(outcomes) != len(items) {
		t.Fatalf("got %d outcomes, want %d", len(outcomes), len(items))
	}
	for _, o := range outcomes {
		if !o.Succeeded() {
			t.Errorf("item %s: state = %v, want result", o.ID, o.State)
		}
	}

	if got := len(hub.envelopes()); got != 1 {
		t.Errorf("hub received %d envelopes; 12 bills must travel as ONE event", got)
	}
}

// TestBatch_EndToEnd_OmissionSurvivesTheRoundTrip: a hub that omits an item must produce
// OutcomeNotServed at the caller, distinct from both success and error. This is the
// property that keeps batching from becoming an existence oracle, and it has to hold
// across the whole wire, not just in the join function.
func TestBatch_EndToEnd_OmissionSurvivesTheRoundTrip(t *testing.T) {
	var omitted string
	hub := newTestHub(t, func(item transport.Item) *transport.Result {
		if item.ID == omitted {
			return nil // the hub says nothing at all about this one
		}
		if item.ID == "refused" {
			return &transport.Result{ID: item.ID, Error: &transport.ResultError{Code: "RATE_LIMITED"}}
		}
		return alwaysSucceed(item)
	})
	relay := startFakeHub(t, hub)

	mk := func(id string) BatchStatus {
		priv, target := sessionKeypair(t)
		return BatchStatus{ID: id, Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)}
	}
	omitted = "silent"
	items := []BatchStatus{mk("ok"), mk("silent"), mk("refused")}

	ctx, cancel := e2eContext(t)
	defer cancel()

	c := &Client{}
	s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatal(err)
	}
	outcomes, err := s.StatusMany(ctx, items)
	if err != nil {
		t.Fatal(err)
	}

	byID := map[string]StatusOutcome{}
	for _, o := range outcomes {
		byID[o.ID] = o
	}

	if got := byID["ok"].State; got != OutcomeResult {
		t.Errorf("ok: state = %v, want result", got)
	}
	if got := byID["silent"].State; got != OutcomeNotServed {
		t.Errorf("silent: state = %v, want NOT SERVED — the hub omitted it", got)
	}
	if byID["silent"].Error != nil {
		t.Error("silent: an omission must not arrive as an error")
	}
	if byID["silent"].SafeToResend() {
		t.Error("silent: an omission is never safe to resend; it may have executed")
	}
	if got := byID["refused"].State; got != OutcomeError {
		t.Errorf("refused: state = %v, want error", got)
	}
	if !byID["refused"].SafeToResend() {
		t.Error("refused: an explicit refusal IS safe to resend")
	}
}

// TestBatch_EndToEnd_SplitsAcrossEnvelopesWhenNeeded: when a batch exceeds the hub's
// ANNOUNCED limits the SDK splits rather than failing, and every item still comes back
// exactly once.
func TestBatch_EndToEnd_SplitsAcrossEnvelopesWhenNeeded(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	hub.limits.MaxItems = 4 // announced, so the client must respect it
	relay := startFakeHub(t, hub)

	items := make([]BatchStatus, 0, 10)
	for i := 0; i < 10; i++ {
		priv, target := sessionKeypair(t)
		items = append(items, BatchStatus{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)})
	}

	ctx, cancel := e2eContext(t)
	defer cancel()

	c := &Client{}
	s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Limits().MaxItems; got != 4 {
		t.Fatalf("session limits MaxItems = %d, want the announced 4", got)
	}

	outcomes, err := s.StatusMany(ctx, items)
	if err != nil {
		t.Fatalf("StatusMany() error = %v", err)
	}
	if len(outcomes) != 10 {
		t.Fatalf("got %d outcomes, want 10", len(outcomes))
	}

	envs := hub.envelopes()
	if len(envs) != 3 {
		t.Errorf("hub received %d envelopes; 10 items at 4 per envelope needs 3", len(envs))
	}
	for i, e := range envs {
		if len(e.Items) > 4 {
			t.Errorf("envelope %d carries %d items, over the announced limit", i, len(e.Items))
		}
	}

	seenEnvelopeIndexes := map[int]bool{}
	for _, o := range outcomes {
		seenEnvelopeIndexes[o.Envelope] = true
		if !o.Succeeded() {
			t.Errorf("item %s: state = %v", o.ID, o.State)
		}
	}
	if len(seenEnvelopeIndexes) < 2 {
		t.Error("outcomes must record which envelope carried them, so a split is attributable")
	}
}

func newTestHub(t *testing.T, decide func(transport.Item) *transport.Result) *fakeHub {
	t.Helper()
	hubPriv, hubXOnly := sessionKeypair(t)
	inboxPriv, inboxXOnly := sessionKeypair(t)
	return &fakeHub{
		hubPriv: hubPriv, hubXOnly: hubXOnly,
		inboxPriv: inboxPriv, inboxXOnly: inboxXOnly,
		limits: transport.DefaultLimits(),
		decide: decide,
	}
}

// TestBatch_EndToEnd_ChunkedReplyReassembles: a hub that answers in several events must
// be invisible to the caller. Same call, same outcomes, one per item.
func TestBatch_EndToEnd_ChunkedReplyReassembles(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	hub.chunkSize = 2 // 9 items -> 5 reply events
	relay := startFakeHub(t, hub)

	items := make([]BatchStatus, 0, 9)
	for i := 0; i < 9; i++ {
		priv, target := sessionKeypair(t)
		items = append(items, BatchStatus{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)})
	}

	ctx, cancel := e2eContext(t)
	defer cancel()

	c := &Client{}
	s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatal(err)
	}

	outcomes, err := s.StatusMany(ctx, items)
	if err != nil {
		t.Fatalf("StatusMany() error = %v; a chunked reply must be reassembled transparently", err)
	}
	if len(outcomes) != 9 {
		t.Fatalf("got %d outcomes, want 9", len(outcomes))
	}
	for _, o := range outcomes {
		if !o.Succeeded() {
			t.Errorf("item %s: state = %v, want result", o.ID, o.State)
		}
	}
	// Still one request, however many replies it took.
	if got := len(hub.envelopes()); got != 1 {
		t.Errorf("hub received %d envelopes, want 1", got)
	}
}

// TestBatch_EndToEnd_LostChunkIsIncompleteNotOmitted is the property that protects money.
//
// With 2 of 3 chunks received, reporting the missing items as omissions would claim the
// hub said nothing about work it may well have performed. For cash_redeem that is a
// redemption the caller is told nothing about — and since an omission is never safe to
// resend, they would be stuck. So the answers that arrived are kept, the rest are
// unanswered, and ErrIncompleteReply says plainly that this is ignorance rather than the
// hub's final word.
func TestBatch_EndToEnd_LostChunkIsIncompleteNotOmitted(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	hub.chunkSize = 2 // 6 items -> 3 chunks
	hub.dropChunk = 2 // the middle one never arrives
	relay := startFakeHub(t, hub)

	items := make([]BatchStatus, 0, 6)
	for i := 0; i < 6; i++ {
		priv, target := sessionKeypair(t)
		items = append(items, BatchStatus{ID: "b" + strconv.Itoa(i), Bill: mustBill(t, target),
			Credential: nipcash.BySigning(priv)})
	}

	// Short deadline: the missing chunk is what we are waiting on, and it never comes.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c := &Client{}
	s, err := c.NewBatchSession(context.Background(), hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatal(err)
	}

	outcomes, err := s.StatusMany(ctx, items)
	if !errors.Is(err, ErrIncompleteReply) {
		t.Fatalf("StatusMany() error = %v, want ErrIncompleteReply", err)
	}

	// Outcomes must NOT be discarded just because the reply was partial.
	if len(outcomes) != 6 {
		t.Fatalf("got %d outcomes, want one per requested item even when incomplete", len(outcomes))
	}
	served, unknown := 0, 0
	for _, o := range outcomes {
		switch o.State {
		case OutcomeResult:
			served++
		case OutcomeUnanswered:
			unknown++
		}
	}
	if served == 0 {
		t.Error("every answer was discarded; the chunks that DID arrive carry real results")
	}
	if unknown == 0 {
		t.Error("the dropped chunk's items must be unanswered, neither successful nor omitted")
	}
	if served+unknown != 6 {
		t.Errorf("served=%d unknown=%d, want 6 total", served, unknown)
	}
}

// mustBill pairs a test bill's target with its deterministic connection secret.
// Bill's halves cannot be set independently, which is the point of the type — so a
// test builds one the same way production does.
func mustBill(t *testing.T, target string) Bill {
	t.Helper()
	b, err := BillFromParts(target, connSecretFor(target))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
