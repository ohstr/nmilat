package conformance

import (
	"context"
	"encoding/json"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// heard is one reply event, with the index of the relay it came from.
type heard struct {
	relay int
	ev    *nip01.Event
}

// listener collects the kind-23191 events p-tagged with one reply_to on a set of
// relays, subscribed before anything is published.
type listener struct {
	mu   sync.Mutex
	got  []heard
	wake chan struct{}
}

func (s *suite) listen(t *testing.T, replyTo string) *listener {
	t.Helper()
	return s.listenKind(t, transport.KindPrivateResponse, replyTo)
}

// listenKind collects the events of kind p-tagged with p on every relay.
func (s *suite) listenKind(t *testing.T, kind int, p string) *listener {
	t.Helper()
	l := &listener{wake: make(chan struct{}, 1)}
	filter := nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{kind},
		Tags:  map[string][]string{"p": {p}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for i, raw := range s.relays {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("relay %q: %v", raw, err)
		}
		conn, err := relayclient.Connect(ctx, u)
		if err != nil {
			t.Fatalf("relay %q: %v", raw, err)
		}
		t.Cleanup(conn.Close)
		subID := uuid.NewString()
		if !conn.SubscribeWithID(subID, filter) {
			t.Fatalf("relay %q: subscription not sent", raw)
		}
		ready := make(chan struct{})
		var once sync.Once
		go func() {
			defer once.Do(func() { close(ready) })
			for {
				select {
				case msg, ok := <-conn.Read():
					if !ok {
						return
					}
					switch m := msg.(type) {
					case *wire.EOSESubscriptionResponse:
						if m.SubscriptionID == subID {
							once.Do(func() { close(ready) })
						}
					case *wire.EventSubscriptionResponse:
						if m.SubscriptionID == subID && m.Event != nil {
							l.mu.Lock()
							l.got = append(l.got, heard{relay: i, ev: m.Event})
							l.mu.Unlock()
							select {
							case l.wake <- struct{}{}:
							default:
							}
						}
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatalf("relay %q: no EOSE for the reply subscription", raw)
		}
	}
	return l
}

// wait returns what was heard once n distinct events arrived or d passed.
func (l *listener) wait(n int, d time.Duration) []heard {
	deadline := time.After(d)
	for {
		l.mu.Lock()
		out := distinct(l.got)
		l.mu.Unlock()
		if len(out) >= n {
			return out
		}
		select {
		case <-l.wake:
		case <-deadline:
			return out
		}
	}
}

func distinct(hs []heard) []heard {
	seen := map[string]bool{}
	var out []heard
	for _, h := range hs {
		if !seen[h.ev.ID] {
			seen[h.ev.ID] = true
			out = append(out, h)
		}
	}
	return out
}

// request is one hand-built kind-23190 event and what reading its reply needs.
type request struct {
	ev       *nip01.Event
	replyKey [32]byte
	replyTo  string
	nonce    string
}

// envelope is a request plaintext, built as a map so a case can send shapes the
// SDK's own encoder refuses.
type envelope map[string]any

func (s *suite) newEnvelope(t *testing.T, items ...transport.Item) (envelope, string, string, int64) {
	t.Helper()
	nonce := mustNonce(t)
	replyTo := mustNonce(t)
	notAfter := time.Now().Add(60 * time.Second).Unix()
	return envelope{
		"nonce": nonce, "reply_to": replyTo,
		"not_after": notAfter, "items": items,
	}, nonce, replyTo, notAfter
}

// wrap encrypts plaintext to the Hub's inbox (or to inbox, when set).
func (s *suite) wrap(t *testing.T, e envelope, inbox string) request {
	t.Helper()
	plaintext, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if inbox == "" {
		inbox = s.inbox
	}
	ev, conversationKey, err := transport.WrapRequest(plaintext, inbox)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	r := request{ev: ev}
	r.replyTo, _ = e["reply_to"].(string)
	r.nonce, _ = e["nonce"].(string)
	if k, err := transport.DeriveReplyKey(conversationKey, r.replyTo); err == nil {
		r.replyKey = k
	}
	return r
}

// publish sends ev to the relay at index i and fails the case unless accepted.
func (s *suite) publish(t *testing.T, i int, ev *nip01.Event) {
	t.Helper()
	u, err := url.Parse(s.relays[i])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ok, err := relayclient.PublishEventToRelay(ctx, u, ev)
	if err != nil {
		t.Fatalf("publish to %s: %v", s.relays[i], err)
	}
	if !ok.Accepted {
		t.Fatalf("publish to %s refused: %s", s.relays[i], ok.Message)
	}
}

// open decrypts a reply chunk and returns its JSON object, raw.
func (r request) open(t *testing.T, ev *nip01.Event) map[string]json.RawMessage {
	t.Helper()
	plaintext, err := nip44.Decrypt(ev.Content, r.replyKey[:])
	if err != nil {
		t.Fatalf("reply does not decrypt under the reply key: %v", err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(plaintext), &out); err != nil {
		t.Fatalf("reply is not a JSON object: %v", err)
	}
	return out
}

// omittedItem is a cash_status item whose proofs verify, on a target no Hub
// holds: every Hub omits it (I2).
func (s *suite) omittedItem(t *testing.T, id, nonce string, notAfter int64) transport.Item {
	t.Helper()
	signer := mustKey(t)
	billSecret := mustKey(t)
	target, err := utils.GetPublicKey(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{}`)
	hash, err := transport.CanonicalParamsHash(params)
	if err != nil {
		t.Fatal(err)
	}
	binding := transport.ProofBinding{Target: target, HubXOnly: s.nodeXOnly, Method: "cash_status",
		ParamsHash: hash, Nonce: nonce, NotAfter: notAfter}
	proof, err := transport.BuildItemProof(signer, binding)
	if err != nil {
		t.Fatal(err)
	}
	billProof, err := transport.BuildBillProof(billSecret, binding)
	if err != nil {
		t.Fatal(err)
	}
	return transport.Item{ID: id, Target: target, Method: "cash_status", Params: params, Proof: proof, BillProof: billProof}
}

func mustNonce(t *testing.T) string {
	t.Helper()
	n, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// mustKey is a fresh private key, hex.
func mustKey(t *testing.T) string { return mustNonce(t) }

func keypair(t *testing.T) (privHex, xonlyHex string) {
	t.Helper()
	priv := mustKey(t)
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}
