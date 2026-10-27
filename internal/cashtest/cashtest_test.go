package cashtest_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/wire"
)

type sent struct {
	ev       *nip01.Event
	replyKey [32]byte
	env      transport.Envelope
}

// request builds one valid kind-23190 to h, of one cash_status item.
func request(t *testing.T, h *cashtest.FakeHub, notAfter time.Time) sent {
	t.Helper()
	nonce, _ := transport.NewNonce()
	replyTo, _ := transport.NewNonce()
	signer, _ := cashtest.Keypair(t)
	billSecret, _ := cashtest.Keypair(t)
	_, target := cashtest.Keypair(t)
	params := json.RawMessage(`{}`)
	hash, err := transport.CanonicalParamsHash(params)
	if err != nil {
		t.Fatal(err)
	}
	b := transport.ProofBinding{Target: target, HubXOnly: h.NodeXOnly(), Method: "cash_status",
		ParamsHash: hash, Nonce: nonce, NotAfter: notAfter.Unix()}
	proof, err := transport.BuildItemProof(signer, b)
	if err != nil {
		t.Fatal(err)
	}
	billProof, err := transport.BuildBillProof(billSecret, b)
	if err != nil {
		t.Fatal(err)
	}
	env := transport.Envelope{Version: transport.EnvelopeVersion, Nonce: nonce, ReplyTo: replyTo,
		NotAfter: notAfter.Unix(), Items: []transport.Item{{ID: "1", Target: target, Method: "cash_status",
			Params: params, Proof: proof, BillProof: billProof}}}
	plaintext, err := env.Encode(h.Limits)
	if err != nil {
		t.Fatal(err)
	}
	ev, ck, err := transport.WrapRequest(plaintext, h.InboxXOnly())
	if err != nil {
		t.Fatal(err)
	}
	key, err := transport.DeriveReplyKey(ck, replyTo)
	if err != nil {
		t.Fatal(err)
	}
	return sent{ev: ev, replyKey: key, env: env}
}

func open(t *testing.T, s sent, ev *nip01.Event) *transport.DecodedChunk {
	t.Helper()
	pt, err := nip44.Decrypt(ev.Content, s.replyKey[:])
	if err != nil {
		t.Fatal(err)
	}
	c, err := transport.DecodeResponseChunk([]byte(pt), s.env.Nonce, []string{"1"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func answerAll(c cashtest.ItemCtx) *transport.Result {
	return &transport.Result{Result: json.RawMessage(`{}`)}
}

// T02-02: the ManualClock drives the Hub's decisions: an envelope is served before
// its not_after and dropped once the clock passes it; a stalled commit resumes
// only when the clock reaches its time, and is refused BAD_REQUEST when that is
// past not_after.
func TestT02_02_ManualClockDrivesDecisions(t *testing.T) {
	clock := cashtest.NewManualClock(time.Now())
	h := cashtest.NewFakeHub(t, cashtest.WithClock(clock), cashtest.WithDecide(answerAll))
	if got := h.Serve(request(t, h, clock.Now().Add(time.Minute)).ev); len(got) != 1 {
		t.Fatalf("%d chunks before not_after, want 1", len(got))
	}
	late := request(t, h, clock.Now().Add(time.Minute))
	clock.Advance(2 * time.Minute)
	if got := h.Serve(late.ev); got != nil {
		t.Fatalf("served after not_after on the Hub's clock")
	}

	until := clock.Now().Add(30 * time.Second)
	h.Fault = func(cashtest.ItemCtx) cashtest.Fault { return cashtest.FaultStallUntil(until) }
	r := request(t, h, clock.Now().Add(time.Minute))
	done := make(chan []*nip01.Event, 1)
	go func() { done <- h.Serve(r.ev) }()
	select {
	case <-done:
		t.Fatal("a stalled commit returned before the clock moved")
	case <-time.After(50 * time.Millisecond):
	}
	clock.Advance(31 * time.Second)
	select {
	case got := <-done:
		if len(got) != 1 {
			t.Fatalf("%d chunks after the stall, want 1", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stall did not resume when the clock reached it")
	}

	// A commit resumed past not_after is refused BAD_REQUEST, nothing committed.
	r = request(t, h, clock.Now().Add(10*time.Second))
	until = clock.Now().Add(time.Minute)
	committed := len(h.Committed())
	go func() { done <- h.Serve(r.ev) }()
	time.Sleep(20 * time.Millisecond)
	clock.Advance(2 * time.Minute)
	wantStalledRefused(t, r, <-done)
	if len(h.Committed()) != committed {
		t.Fatal("a commit resumed past not_after was committed")
	}
}

// wantStalledRefused checks a reply of one chunk answering item 1 BAD_REQUEST.
func wantStalledRefused(t *testing.T, r sent, got []*nip01.Event) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("%d chunks for a commit resumed past not_after, want 1", len(got))
	}
	c := open(t, r, got[0])
	if len(c.Results) != 1 || c.Results[0].Error == nil || c.Results[0].Error.Code != nipcash.ErrCodeBadRequest {
		t.Fatalf("a commit resumed past not_after answered %+v, want BAD_REQUEST", c.Results)
	}
}

// FaultStallCommit holds a commit while the hook answers it; released before
// not_after it commits, released after it is refused BAD_REQUEST.
func TestFaultStallCommit(t *testing.T) {
	clock := cashtest.NewManualClock(time.Now())
	h := cashtest.NewFakeHub(t, cashtest.WithClock(clock), cashtest.WithDecide(answerAll))
	var stalled atomic.Bool
	h.Fault = func(cashtest.ItemCtx) cashtest.Fault {
		if stalled.Load() {
			return cashtest.FaultStallCommit
		}
		return cashtest.FaultNone
	}
	serve := func(r sent) chan []*nip01.Event {
		done := make(chan []*nip01.Event, 1)
		go func() { done <- h.Serve(r.ev) }()
		select {
		case <-done:
			t.Fatal("a stalled commit returned before it was released")
		case <-time.After(50 * time.Millisecond):
		}
		return done
	}

	stalled.Store(true)
	done := serve(request(t, h, clock.Now().Add(time.Minute)))
	stalled.Store(false)
	if got := <-done; len(got) != 1 || len(h.Committed()) != 1 {
		t.Fatalf("released in time: %d chunks, %d committed", len(got), len(h.Committed()))
	}

	stalled.Store(true)
	r := request(t, h, clock.Now().Add(time.Minute))
	done = serve(r)
	clock.Advance(2 * time.Minute)
	stalled.Store(false)
	wantStalledRefused(t, r, <-done)
	if len(h.Committed()) != 1 {
		t.Fatal("a commit released past not_after was committed")
	}
	if !cashtest.FaultStallCommit.Is(cashtest.FaultStallCommit) || cashtest.FaultStallCommit.String() != "stall commit" {
		t.Fatal("FaultStallCommit's identity")
	}
}

// T02-03: the reply goes to the arrival relay only; when that relay refuses it, to
// the others.
func TestT02_03_ReplyOnArrivalRelay(t *testing.T) {
	h := cashtest.NewFakeHub(t, cashtest.WithDecide(answerAll))
	r0, r1 := h.Relays[0], h.Relays[1]
	replies := func(r *cashtest.Relay) int {
		n := 0
		for _, ev := range r.Accepted() {
			if ev.Kind == transport.KindPrivateResponse {
				n++
			}
		}
		return n
	}
	waitFor := func(cond func() bool) bool {
		for range 200 {
			if cond() {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	r1.Publish(request(t, h, time.Now().Add(time.Minute)).ev)
	if !waitFor(func() bool { return replies(r1) == 1 }) || replies(r0) != 0 {
		t.Fatalf("replies r0=%d r1=%d, want only the arrival relay", replies(r0), replies(r1))
	}
	r1.RefuseFrom(func(ev *nip01.Event) bool { return ev.Kind == transport.KindPrivateResponse })
	r1.Publish(request(t, h, time.Now().Add(time.Minute)).ev)
	if !waitFor(func() bool { return replies(r0) == 1 }) {
		t.Fatal("a reply refused by the arrival relay did not go to the other relay")
	}
}

// T02-04: Drop, Duplicate and Reorder are deterministic; Duplicate reaches
// OnEvent listeners twice too.
func TestT02_04_RelayHooks(t *testing.T) {
	r := cashtest.NewRelay(t)
	events := make([]*nip01.Event, 3)
	for i := range events {
		priv, _ := cashtest.Keypair(t)
		ev := nip01.NewEvent(1, string(rune('a'+i)))
		if err := ev.Sign(priv); err != nil {
			t.Fatal(err)
		}
		events[i] = ev
	}
	sub := subscribe(t, r)

	r.Reorder(3)
	for _, ev := range events {
		r.Publish(ev)
	}
	got := sub.take(t, 3)
	for i, ev := range got {
		if ev.ID != events[2-i].ID {
			t.Fatalf("reorder: position %d is %s, want newest first", i, ev.Content)
		}
	}

	r.Reorder(0)
	var heardMu sync.Mutex
	heard := map[string]int{}
	r.OnEvent(func(_ *cashtest.Relay, ev *nip01.Event) {
		heardMu.Lock()
		heard[ev.ID]++
		heardMu.Unlock()
	})
	r.Duplicate(func(ev *nip01.Event) bool { return ev.ID == events[0].ID })
	r.Drop(func(ev *nip01.Event) bool { return ev.ID == events[1].ID })
	r.Publish(events[0])
	r.Publish(events[1])
	r.Publish(events[2])
	got = sub.take(t, 3)
	if got[0].ID != events[0].ID || got[1].ID != events[0].ID || got[2].ID != events[2].ID {
		t.Fatalf("duplicate/drop: got %s %s %s", got[0].Content, got[1].Content, got[2].Content)
	}
	// Listeners see a duplicated event twice, a dropped one still once.
	waitFor := func(cond func() bool) bool {
		for range 200 {
			if cond() {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	want := map[string]int{events[0].ID: 2, events[1].ID: 1, events[2].ID: 1}
	if !waitFor(func() bool {
		heardMu.Lock()
		defer heardMu.Unlock()
		for id, n := range want {
			if heard[id] != n {
				return false
			}
		}
		return true
	}) {
		heardMu.Lock()
		defer heardMu.Unlock()
		t.Fatalf("listeners heard %v, want %v", heard, want)
	}
}

type subscriber struct{ ch chan *nip01.Event }

func subscribe(t *testing.T, r *cashtest.Relay) *subscriber {
	t.Helper()
	u, _ := url.Parse(r.URL())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn, err := relayclient.Connect(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	id := uuid.NewString()
	conn.SubscribeWithID(id, nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}}))
	s := &subscriber{ch: make(chan *nip01.Event, 16)}
	ready := make(chan struct{})
	go func() {
		for msg := range conn.Read() {
			switch m := msg.(type) {
			case *wire.EOSESubscriptionResponse:
				close(ready)
			case *wire.EventSubscriptionResponse:
				s.ch <- m.Event
			}
		}
	}()
	<-ready
	return s
}

func (s *subscriber) take(t *testing.T, n int) []*nip01.Event {
	t.Helper()
	var out []*nip01.Event
	for len(out) < n {
		select {
		case ev := <-s.ch:
			out = append(out, ev)
		case <-time.After(5 * time.Second):
			t.Fatalf("got %d of %d events", len(out), n)
		}
	}
	select {
	case ev := <-s.ch:
		t.Fatalf("unexpected extra event %s", ev.Content)
	case <-time.After(50 * time.Millisecond):
	}
	return out
}

// E-LK-01 (23194 half), T02-06: the Cash Hub connection answers get_info with the node identity and
// refuses the bill methods and cash_lookup on kind 23194 with NOT_IMPLEMENTED.
func TestT02_06_FakeNWC(t *testing.T) {
	h := cashtest.NewFakeHub(t)
	conn, err := nipcash.DecodeCashHubConnection(h.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	nwc, err := relayclient.NewNWCClient(context.Background(), &nip47.PairingInfo{
		WalletPubkey: conn.Pubkey, RelayURLs: conn.Relays, Secret: conn.Secret}, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatal(err)
	}
	defer nwc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info, err := nwc.GetInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Pubkey != h.NodeXOnly() || info.Network != cashtest.FakeNetwork || info.Chain != cashtest.FakeChain {
		t.Errorf("get_info pubkey %s network %s", info.Pubkey, info.Network)
	}
	for _, m := range []string{"cash_status", "cash_redeem", "cash_transfer", "cash_consolidate", "cash_lookup", "mint_cash"} {
		resp, err := nwc.Call(ctx, m, map[string]any{})
		var we *relayclient.WalletError
		switch {
		case errors.As(err, &we):
			if we.Code != "NOT_IMPLEMENTED" {
				t.Errorf("%s: %s, want NOT_IMPLEMENTED", m, we.Code)
			}
		case err != nil:
			t.Errorf("%s: %v", m, err)
		case resp.Error == nil || resp.Error.Code != "NOT_IMPLEMENTED":
			t.Errorf("%s: %+v, want NOT_IMPLEMENTED", m, resp.Response)
		}
	}
}

// T02-07: drop before commit, commit then drop reply, stall (T02-02), break
// signer.
func TestT02_07_Faults(t *testing.T) {
	var fault cashtest.Fault
	h := cashtest.NewFakeHub(t, cashtest.WithDecide(answerAll),
		cashtest.WithFault(func(cashtest.ItemCtx) cashtest.Fault { return fault }))

	fault = cashtest.FaultDropBeforeCommit
	r := request(t, h, time.Now().Add(time.Minute))
	if h.Serve(r.ev) != nil || len(h.Committed()) != 0 {
		t.Fatal("drop before commit replied or committed")
	}
	fault = cashtest.FaultNone
	if got := h.Serve(r.ev); len(got) != 1 {
		t.Fatal("the nonce of an envelope dropped before commit was consumed")
	}

	fault = cashtest.FaultCommitThenDropReply
	if h.Serve(request(t, h, time.Now().Add(time.Minute)).ev) != nil || len(h.Committed()) != 2 {
		t.Fatalf("commit then drop reply: committed %d", len(h.Committed()))
	}

	fault = cashtest.FaultBreakSigner
	r = request(t, h, time.Now().Add(time.Minute))
	got := h.Serve(r.ev)
	if len(got) != 1 {
		t.Fatal("no reply under a broken signer")
	}
	c := open(t, r, got[0])
	if len(c.Results) != 1 || c.Results[0].Error == nil || c.Results[0].Error.Code != "INTERNAL" {
		t.Fatalf("broken signer: %+v", c.Results)
	}
	if len(h.Committed()) != 2 {
		t.Fatal("a broken signer committed")
	}
}

// Every result carries result_type equal to its item's method (CASH-RESP-04), and
// the fake's defaults are the spec's reasonable ones.
func TestFakeHub_ResultTypeAndDefaults(t *testing.T) {
	h := cashtest.NewFakeHub(t, cashtest.WithDecide(answerAll))
	r := request(t, h, time.Now().Add(time.Minute))
	got := h.Serve(r.ev)
	if len(got) != 1 {
		t.Fatal("no reply")
	}
	if c := open(t, r, got[0]); c.Results[0].ResultType != "cash_status" {
		t.Errorf("result_type %q", c.Results[0].ResultType)
	}
	if h.TombstoneWindow != 1296000*time.Second {
		t.Errorf("TombstoneWindow %s", h.TombstoneWindow)
	}
}

// T08-03: CallWithOptions carries the expiration through to the wallet service.
func TestT08_03_CallWithOptions(t *testing.T) {
	h := cashtest.NewFakeHub(t)
	conn, _ := nipcash.DecodeCashHubConnection(h.CashHubConnection())
	nwc, err := relayclient.NewNWCClient(context.Background(), &nip47.PairingInfo{
		WalletPubkey: conn.Pubkey, RelayURLs: conn.Relays, Secret: conn.Secret}, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatal(err)
	}
	defer nwc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := nwc.CallWithOptions(ctx, "get_info", nil, nip47.WithExpiration(time.Now().Add(time.Minute).Unix()))
	if err != nil || resp.Error != nil {
		t.Fatalf("CallWithOptions: %v %+v", err, resp)
	}
}
