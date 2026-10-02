package client

// Audit C, SDK-abstraction role. A hub that LIES about its chunk `total`.
//
// Session A filed `oneItemOutcome` returning sendErr ahead of a successful outcome as
// "latent but unreachable", reasoning that a 1-item reply returns via len(seen)==total
// first. That reasoning holds only for a hub whose `total` is HONEST. `total` is
// hub-supplied and unbounded above (transport/response.go:116 refuses only Total<1 and
// Seq>Total), so a hostile hub sends Seq=1 Total=2 with the real answer in chunk 1 and
// never sends chunk 2.
//
// The result: collectReply returns the genuine SUCCESS outcome AND ErrIncompleteReply;
// sendBatch passes both up; and the single-item wrappers (CashStatus / CashRedeem /
// CashTransfer / CashConsolidate) throw the success away and return the error.

import (
	"context"
	"encoding/json"
	"errors"
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

// lyingHub answers one item with one real result, but declares `total` chunks and
// publishes only the first `publish` of them.
type lyingHub struct {
	hubPriv, hubXOnly     string
	inboxPriv, inboxXOnly string
	limits                transport.Limits

	declaredTotal int // what the reply CLAIMS
	publishChunks int // how many it actually sends

	decide func(transport.Item) *transport.Result

	mu   sync.Mutex
	subs []chan *nip01.Event
}

func (h *lyingHub) register(ch chan *nip01.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs = append(h.subs, ch)
}

func (h *lyingHub) broadcast(ev *nip01.Event) {
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

func (h *lyingHub) handleRequest(t *testing.T, ev *nip01.Event) {
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
	replyKey, err := transport.DeriveReplyKey(conversationKey, env.ReplyTo)
	if err != nil {
		t.Errorf("hub: reply key: %v", err)
		return
	}

	var results []transport.Result
	for _, item := range env.Items {
		if r := h.decide(item); r != nil {
			results = append(results, *r)
		}
	}

	for seq := 1; seq <= h.publishChunks; seq++ {
		part := transport.ResponseEnvelope{
			Version: transport.EnvelopeVersion, ReqNonce: env.Nonce,
			Seq: seq, Total: h.declaredTotal,
		}
		if seq == 1 {
			part.Results = results // the whole truth, in chunk 1
		}
		encoded, err := part.EncodeResponse(h.limits)
		if err != nil {
			t.Errorf("hub: encode chunk %d: %v", seq, err)
			return
		}
		sealed, err := nip44.Encrypt(string(encoded), replyKey[:])
		if err != nil {
			t.Errorf("hub: encrypt chunk %d: %v", seq, err)
			return
		}
		out := nip01.NewEvent(transport.KindPrivateResponse, sealed)
		out.Tags = [][]string{{"p", env.ReplyTo}}
		if err := out.Sign(h.hubPriv); err != nil {
			t.Errorf("hub: sign chunk %d: %v", seq, err)
			return
		}
		h.broadcast(out)
	}
}

func startLyingHub(t *testing.T, h *lyingHub) string {
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

func newLyingHub(t *testing.T, declaredTotal, publishChunks int, decide func(transport.Item) *transport.Result) *lyingHub {
	t.Helper()
	hubPriv, hubXOnly := sessionKeypair(t)
	inboxPriv, inboxXOnly := sessionKeypair(t)
	return &lyingHub{
		hubPriv: hubPriv, hubXOnly: hubXOnly,
		inboxPriv: inboxPriv, inboxXOnly: inboxXOnly,
		limits:        transport.DefaultLimits(),
		declaredTotal: declaredTotal, publishChunks: publishChunks,
		decide: decide,
	}
}

// clientOnLyingHub builds a Client whose bill session points at h, with the session
// pre-opened so no mint provenance is needed — billSession() short-circuits on a
// non-nil session, which is exactly what production reaches after the first call.
func clientOnLyingHub(t *testing.T, h *lyingHub, relay, target string) *Client {
	t.Helper()
	c := &Client{walletPubkey: target, connSecret: connSecretFor(target)}
	s, err := c.NewBatchSession(context.Background(), h.hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("NewBatchSession() error = %v", err)
	}
	c.session = s
	return c
}

// TestAuditC_LyingTotal_SingleItemDiscardsARealResult is the finding.
//
// The hub serves the item for real — a successful cash_transfer carrying a NEW WALLET
// TOKEN, the one value a caller can never recover afterwards — and then declares two
// chunks while sending one. The batch layer keeps the answer. The single-bill wrapper
// does not.
func TestAuditC_LyingTotal_SingleItemDiscardsARealResult(t *testing.T) {
	const newToken = "lokicash1qqsauditcnewwallettoken"
	// Wire field names, because that is what a hub actually sends. A cash-mode
	// credential's delivery decrypt is a pass-through (nipcash/proof.go:132), so the
	// carved token travels as itself inside the already-encrypted envelope — the
	// exact shape cashctl's auto-protect chain uses.
	body := json.RawMessage(`{"amount_millis":7000,"identity_type":"cash",` +
		`"new_wallet_pubkey":"` + strings.Repeat("ab", 32) + `","new_wallet_token":"` + newToken + `"}`)

	hub := newLyingHub(t, 2, 1, func(item transport.Item) *transport.Result {
		return &transport.Result{ID: item.ID, ResultType: item.Method, Result: body}
	})
	relay := startLyingHub(t, hub)

	_, target := sessionKeypair(t)
	c := clientOnLyingHub(t, hub, relay, target)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// CONTROL, same hub, same lie: the BATCH layer keeps the result and reports the
	// incompleteness alongside it. So the loss below is the wrapper's, not the wire's.
	bill, err := BillFromParts(target, connSecretFor(target))
	if err != nil {
		t.Fatal(err)
	}
	batchOut, batchErr := c.session.TransferMany(ctx, []BatchTransfer{{ID: "1", Bill: bill,
		Params: nipcash.CashTransferParams{To: nipcash.Pubkey(target), Credential: nipcash.BySecret(connSecretFor(target)), CurrentAmount: 7000}}})
	if !errors.Is(batchErr, ErrIncompleteReply) {
		t.Fatalf("control: TransferMany err = %v, want ErrIncompleteReply", batchErr)
	}
	if len(batchOut) != 1 || batchOut[0].State != OutcomeResult || batchOut[0].Result == nil {
		t.Fatalf("control: batch layer lost the result: %+v", batchOut)
	}
	if batchOut[0].Result.NewWalletToken != newToken {
		t.Fatalf("control: new wallet token = %q, want %q", batchOut[0].Result.NewWalletToken, newToken)
	}
	t.Logf("control: batch layer kept the transfer result (new_wallet_token=%q) and also said %v",
		batchOut[0].Result.NewWalletToken, batchErr)

	// THE BUG: the identical reply through the single-bill wrapper.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	res, err := c.CashTransfer(ctx2, nipcash.CashTransferParams{
		To: nipcash.Pubkey(target), Credential: nipcash.BySecret(connSecretFor(target)), CurrentAmount: 7000,
	})
	t.Logf("CashTransfer -> result=%v err=%v", res, err)

	if res == nil {
		t.Fatalf("BUG PRESENT: the transfer SUCCEEDED and the hub said so, but CashTransfer "+
			"returned nil with err=%v; the new wallet token is unrecoverable and the old bill is gone", err)
	}
	if res.NewWalletToken != newToken {
		t.Errorf("new wallet token = %q, want %q", res.NewWalletToken, newToken)
	}

	// This test originally also required ErrIncompleteReply to survive alongside the
	// result. That was the right instinct and the wrong conclusion, and the reasoning is
	// worth keeping because it is what the fix turns on.
	//
	// A single-item wrapper returns (result, error). There is no third slot, and every
	// caller checks the error first — that IS the bug being fixed here. So signalling
	// envelope-level incompleteness through `err` cannot coexist with handing back the
	// answer; one of the two has to win, and for a ONE-item call the answer must.
	//
	// It is also not a lie to call it complete. The caller asked one question and the hub
	// answered it. Whatever the phantom second chunk was supposed to contain, it was not
	// this item's outcome, because this item already has one. Envelope-level completeness
	// is the batch API's concern, and there the *Many wrappers still return outcomes AND
	// ErrIncompleteReply together, because with N items an absent chunk really may hold
	// an answer the caller is still missing.
	//
	// What must NOT happen is a contradictory duplicate quietly winning — the same item
	// answered twice across chunks. That is a real hazard and a separate finding
	// (chunks are deduped on seq but never sorted by it); it is not this one, and fixing
	// it here would have hidden it.
	if err != nil {
		t.Errorf("a decided single-item outcome must be returned as a clean success; got err=%v", err)
	}
}

// TestAuditC_LyingTotal_StatusAlsoDiscarded pins the same loss on the read path,
// because that is what a caller is told to use to RECOVER from an omission.
func TestAuditC_LyingTotal_StatusAlsoDiscarded(t *testing.T) {
	body, err := json.Marshal(nipcash.CashStatusResult{
		Recipients: []nipcash.RecipientStatus{{AmountMillis: 4242}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hub := newLyingHub(t, 3, 1, func(item transport.Item) *transport.Result {
		return &transport.Result{ID: item.ID, ResultType: item.Method, Result: body}
	})
	relay := startLyingHub(t, hub)

	priv, target := sessionKeypair(t)
	c := clientOnLyingHub(t, hub, relay, target)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := c.CashStatus(ctx, nipcash.BySigning(priv), nipcash.ScopeMine)
	t.Logf("CashStatus -> result=%v err=%v", res, err)
	if res == nil {
		t.Errorf("BUG PRESENT: the hub answered cash_status in full and the answer was discarded (err=%v). "+
			"This is the very call cashctl tells a user to run after an ambiguous redeem.", err)
	}
}
