package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/wire"
)

// fakeHub is a relay that also behaves like a hub: it serves its own announcement, and
// answers any kind-23190 it receives by doing what a real hub does — decrypt with the
// inbox key, decode the envelope, decide per item, and publish a kind-23191 p-tagged
// with the envelope's reply_to, encrypted under the derived reply key.
//
// Small, but it exercises the entire client path for real: announcement fetch and
// signature check, packing, wrapping, publish, subscribe, reply-key derivation, decode
// and demux. Everything below the SDK's own API is the genuine article.
type fakeHub struct {
	hubPriv, hubXOnly     string
	inboxPriv, inboxXOnly string
	limits                transport.Limits

	// decide says how to answer one item. Returning nil OMITS it, which is how a real
	// hub answers an item it cannot serve.
	decide func(item transport.Item) *transport.Result

	mu   sync.Mutex
	subs []chan *nip01.Event
	// seen records the envelopes received, so a test can assert how many events a batch
	// actually became.
	seen []transport.Envelope
}

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
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]transport.Envelope(nil), h.seen...)
}

// handleRequest is the hub half: unwrap, decide per item, reply.
func (h *fakeHub) handleRequest(t *testing.T, ev *nip01.Event) {
	t.Helper()

	conversationKey, err := transport.ConversationKeyFor(ev.PubKey, h.inboxPriv)
	if err != nil {
		t.Errorf("hub: conversation key: %v", err)
		return
	}
	plaintext, err := nip44.Decrypt(ev.Content, conversationKey[:])
	if err != nil {
		t.Errorf("hub: decrypt: %v", err)
		return
	}
	env, err := transport.Decode([]byte(plaintext), h.limits)
	if err != nil {
		t.Errorf("hub: decode: %v", err)
		return
	}

	h.mu.Lock()
	h.seen = append(h.seen, *env)
	h.mu.Unlock()

	resp := transport.ResponseEnvelope{Version: transport.EnvelopeVersion, ReqNonce: env.Nonce}
	for _, item := range env.Items {
		if r := h.decide(item); r != nil {
			resp.Results = append(resp.Results, *r)
		}
	}

	encoded, err := resp.EncodeResponse(h.limits)
	if err != nil {
		t.Errorf("hub: encode response: %v", err)
		return
	}
	replyKey, err := transport.DeriveReplyKey(conversationKey, env.ReplyTo)
	if err != nil {
		t.Errorf("hub: reply key: %v", err)
		return
	}
	sealed, err := nip44.Encrypt(string(encoded), replyKey[:])
	if err != nil {
		t.Errorf("hub: encrypt response: %v", err)
		return
	}

	out := nip01.NewEvent(transport.KindPrivateResponse, sealed)
	// Addressed by the envelope's reply_to, per NIP-CASH §Addressing the Response.
	out.Tags = [][]string{{"p", env.ReplyTo}}
	if err := out.Sign(h.hubPriv); err != nil {
		t.Errorf("hub: sign response: %v", err)
		return
	}
	h.broadcast(out)
}

func startFakeHub(t *testing.T, h *fakeHub) string {
	t.Helper()
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		var writeMu sync.Mutex
		writeMsg := func(v json.Marshaler) bool {
			b, err := v.MarshalJSON()
			if err != nil {
				return false
			}
			writeMu.Lock()
			defer writeMu.Unlock()
			return conn.WriteMessage(websocket.TextMessage, b) == nil
		}

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var payload wire.RelayPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				continue
			}

			switch p := payload.Packet.(type) {
			case *wire.RequestPacket:
				subID := p.SubscriptionID
				wantsAnnouncement := false
				for _, f := range p.Filters.GetAll() {
					for _, k := range f.Kinds {
						if k == transport.KindHubAnnouncement {
							wantsAnnouncement = true
						}
					}
				}
				if wantsAnnouncement {
					ann := signedAnnouncement(t, h.hubPriv, h.hubXOnly, h.inboxXOnly, h.limits, nil)
					b, err := json.Marshal(ann)
					if err != nil {
						return
					}
					if !writeMsg(&wire.EventSubscriptionResponse{SubscriptionID: subID, EventBytes: b}) {
						return
					}
					_ = writeMsg(&wire.EOSESubscriptionResponse{SubscriptionID: subID})
					continue
				}

				// A reply subscription: forward anything the hub publishes.
				ch := make(chan *nip01.Event, 4)
				h.register(ch)
				go func() {
					for ev := range ch {
						b, err := json.Marshal(ev)
						if err != nil {
							return
						}
						if !writeMsg(&wire.EventSubscriptionResponse{SubscriptionID: subID, EventBytes: b}) {
							return
						}
					}
				}()

			case *wire.EventPacket:
				_ = writeMsg(&wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: true})
				if p.Event.Kind == transport.KindPrivateRequest {
					go h.handleRequest(t, p.Event)
				}
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
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
		items = append(items, BatchStatus{Target: target, Credential: nipcash.BySigning(priv)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		return BatchStatus{ID: id, Target: target, Credential: nipcash.BySigning(priv)}
	}
	omitted = "silent"
	items := []BatchStatus{mk("ok"), mk("silent"), mk("refused")}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		items = append(items, BatchStatus{Target: target, Credential: nipcash.BySigning(priv)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
