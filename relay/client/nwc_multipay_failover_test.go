package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
)

// multiWallet is a fake wallet relay for multi_pay_invoice and multi_pay_keysend that answers the item ids in answer
// (each with preimage tag+"-"+id), and records the request event ids it got.
type multiWallet struct {
	url string
	mu  sync.Mutex
	ids []string
	n   atomic.Int32
}

func (w *multiWallet) eventIDs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.ids...)
}

func newMultiWallet(t *testing.T, tag string, answer ...string) *multiWallet {
	w := &multiWallet{}
	srv := newFakeWalletServer(t, func(reqEvent *nip01.Event) []*nip01.Event {
		w.n.Add(1)
		w.mu.Lock()
		w.ids = append(w.ids, reqEvent.ID)
		w.mu.Unlock()
		req, err := nip47.ParseRequestEvent(reqEvent, testWalletPrivKey)
		if err != nil {
			t.Errorf("ParseRequestEvent: %v", err)
			return nil
		}
		var out []*nip01.Event
		for _, id := range answer {
			var result any = nip47.PayInvoiceResult{Preimage: tag + "-" + id}
			if req.Method == nip47.MethodMultiPayKeysend {
				result = nip47.PayKeysendResult{Preimage: tag + "-" + id}
			}
			ev, err := nip47.NewResponseEvent(testWalletPrivKey, reqEvent.PubKey, req.Method, result, reqEvent,
				nip47.EncryptionNIP44V2, []string{"d", id})
			if err == nil {
				err = ev.Sign(testWalletPrivKey)
			}
			if err != nil {
				t.Errorf("response: %v", err)
				return nil
			}
			out = append(out, ev)
		}
		return out
	})
	w.url = wsOf(srv.URL)
	return w
}

// multiPay runs MultiPayInvoice or MultiPayKeysend for items a and b and returns each id's preimage.
func multiPay(ctx context.Context, c *NWCClient, keysend bool) (map[string]string, error) {
	got := map[string]string{}
	if keysend {
		res, err := c.MultiPayKeysend(ctx, nip47.MultiPayKeysendParams{Keysends: []nip47.MultiPayKeysendItem{
			{PayKeysendParams: nip47.PayKeysendParams{Amount: 1000, Pubkey: "02aa"}, Id: "a"},
			{PayKeysendParams: nip47.PayKeysendParams{Amount: 2000, Pubkey: "02bb"}, Id: "b"},
		}})
		for _, r := range res {
			if r.Result != nil {
				got[r.Id] = r.Result.Preimage
			}
		}
		return got, err
	}
	res, err := c.MultiPayInvoice(ctx, nip47.MultiPayInvoiceParams{Invoices: []nip47.MultiPayInvoiceItem{
		{PayInvoiceParams: nip47.PayInvoiceParams{Invoice: "lnfc1..."}, Id: "a"},
		{PayInvoiceParams: nip47.PayInvoiceParams{Invoice: "lnfc2..."}, Id: "b"},
	}})
	for _, r := range res {
		if r.Result != nil {
			got[r.Id] = r.Result.Preimage
		}
	}
	return got, err
}

func multiClient(t *testing.T, ctx context.Context, opts []NWCOption, urls ...string) *NWCClient {
	t.Helper()
	p := *newTestPairing(t, nil)
	p.RelayURLs = urls
	c, err := NewNWCClient(ctx, &p, nip47.EncryptionNIP44V2, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// NIP-CASH §Multiple Relay Hints for the fan-out methods: a silent first hint is followed by the next with the same
// signed request (one event id, so the wallet pays each item once); the first answer per item wins; a first hint
// that answers every item is the only one contacted.
func TestNWCClient_MultiPaySilentRelayFailsOverToTheNext(t *testing.T) {
	for _, keysend := range []bool{false, true} {
		name := "multi_pay_invoice"
		if keysend {
			name = "multi_pay_keysend"
		}
		t.Run(name, func(t *testing.T) {
			for _, c := range []struct {
				name                  string
				firstAnswers          []string
				opts                  []NWCOption
				want                  map[string]string
				wantFirst, wantSecond int32
			}{
				{"silent first, wait shared from the deadline", nil, nil,
					map[string]string{"a": "second-a", "b": "second-b"}, 1, 1},
				{"silent first, a set wait", nil, []NWCOption{WithAnswerWait(200 * time.Millisecond)},
					map[string]string{"a": "second-a", "b": "second-b"}, 1, 1},
				{"first answers one item, then is silent", []string{"a"}, []NWCOption{WithAnswerWait(200 * time.Millisecond)},
					map[string]string{"a": "first-a", "b": "second-b"}, 1, 1},
				{"the first answers every item", []string{"a", "b"}, []NWCOption{WithAnswerWait(200 * time.Millisecond)},
					map[string]string{"a": "first-a", "b": "first-b"}, 1, 0},
			} {
				t.Run(c.name, func(t *testing.T) {
					first := newMultiWallet(t, "first", c.firstAnswers...)
					second := newMultiWallet(t, "second", "a", "b")
					ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
					defer cancel()
					client := multiClient(t, ctx, c.opts, first.url, second.url)
					start := time.Now()
					got, err := multiPay(ctx, client, keysend)
					if err != nil {
						t.Fatalf("multi pay: %v", err)
					}
					if d := time.Since(start); d > 3*time.Second {
						t.Errorf("answered after %v", d)
					}
					for id, pre := range c.want {
						if got[id] != pre {
							t.Errorf("item %s: preimage %q, want %q", id, got[id], pre)
						}
					}
					time.Sleep(300 * time.Millisecond) // let a stray resend surface
					if first.n.Load() != c.wantFirst || second.n.Load() != c.wantSecond {
						t.Errorf("requests: first %d, second %d; want %d, %d", first.n.Load(), second.n.Load(), c.wantFirst, c.wantSecond)
					}
					if ids := append(first.eventIDs(), second.eventIDs()...); len(ids) == 2 && ids[0] != ids[1] {
						t.Errorf("the hints got different request events %s and %s", ids[0], ids[1])
					}
				})
			}
		})
	}
}

// A first hint that closes the fan-out's subscription is a failure, so the request goes on to the next hint.
func TestNWCClient_MultiPayClosedSubscriptionFailsOverToTheNext(t *testing.T) {
	closing := newFakeClosingWalletServer(t, "auth-required: no", nil)
	second := newMultiWallet(t, "second", "a", "b")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	client := multiClient(t, ctx, nil, wsOf(closing.URL), second.url)
	got, err := multiPay(ctx, client, false)
	if err != nil || len(got) != 2 || second.n.Load() != 1 {
		t.Fatalf("multi pay: %v, %v, %d requests on the second hint", got, err, second.n.Load())
	}
}

// Every hint silent: each gets the request once, and the call ends with its context with nothing collected.
func TestNWCClient_MultiPayEveryRelaySilentTriesEachOnce(t *testing.T) {
	var urls []string
	var wallets []*multiWallet
	for range 3 {
		w := newMultiWallet(t, "w")
		urls, wallets = append(urls, w.url), append(wallets, w)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := multiClient(t, ctx, nil, urls...)
	got, err := multiPay(ctx, client, true)
	if !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 {
		t.Fatalf("multi pay: %v, %v; want nothing and the deadline", got, err)
	}
	for i, w := range wallets {
		if w.n.Load() != 1 {
			t.Errorf("hint %d got %d requests, want 1", i, w.n.Load())
		}
	}
}
