package client

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
)

func wsOf(url string) string { return strings.Replace(url, "http", "ws", 1) }

// countingWallet is a fake wallet relay that answers pay_invoice when answer is set, and counts the requests it got.
func countingWallet(t *testing.T, answer bool) (string, *atomic.Int32) {
	var n atomic.Int32
	srv := newFakeWalletServer(t, func(req *nip01.Event) []*nip01.Event {
		n.Add(1)
		if !answer {
			return nil
		}
		return []*nip01.Event{signedPayInvoiceResponse(t, req, "deadbeef")}
	})
	return wsOf(srv.URL), &n
}

// NIP-CASH §Multiple Relay Hints: a first hint that is up but never answers, as one the wallet stopped reading, is
// followed by the next; the first that answers serves the call, and a hint that answers is the only one contacted.
func TestNWCClient_SilentRelayFailsOverToTheNext(t *testing.T) {
	for _, c := range []struct {
		name                    string
		firstAnswers            bool
		opts                    []NWCOption
		wantFirst, wantSecond   int32
		timeout, answeredWithin time.Duration
	}{
		{"silent first, wait shared from the deadline", false, nil, 1, 1, 4 * time.Second, 3 * time.Second},
		{"silent first, a set wait", false, []NWCOption{WithAnswerWait(200 * time.Millisecond)}, 1, 1, 4 * time.Second, time.Second},
		{"the first answers", true, []NWCOption{WithAnswerWait(200 * time.Millisecond)}, 1, 0, 4 * time.Second, time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			first, firstN := countingWallet(t, c.firstAnswers)
			second, secondN := countingWallet(t, true)
			p := *newTestPairing(t, nil)
			p.RelayURLs = []string{first, second}
			ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
			defer cancel()
			client, err := NewNWCClient(ctx, &p, nip47.EncryptionNIP44V2, c.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			start := time.Now()
			if _, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."}); err != nil {
				t.Fatalf("PayInvoice: %v", err)
			}
			if d := time.Since(start); d > c.answeredWithin {
				t.Errorf("answered after %v", d)
			}
			// A call the first relay answered is never sent on; let a stray resend surface.
			time.Sleep(300 * time.Millisecond)
			if firstN.Load() != c.wantFirst || secondN.Load() != c.wantSecond {
				t.Errorf("requests: first %d, second %d; want %d, %d", firstN.Load(), secondN.Load(), c.wantFirst, c.wantSecond)
			}
		})
	}
}

// A relay that closes the call's subscription is a failure, so the call goes on to the next hint; with no hint left
// the closure is the call's error, as before.
func TestNWCClient_ClosedSubscriptionFailsOverToTheNext(t *testing.T) {
	closing := newFakeClosingWalletServer(t, "auth-required: no", nil)
	second, secondN := countingWallet(t, true)
	p := *newTestPairingWithServer(t, closing)
	p.RelayURLs = []string{wsOf(closing.URL), second}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	client, err := NewNWCClient(ctx, &p, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."}); err != nil || secondN.Load() != 1 {
		t.Fatalf("PayInvoice: %v, %d requests on the second hint", err, secondN.Load())
	}

	only := *newTestPairingWithServer(t, newFakeClosingWalletServer(t, "auth-required: no", nil))
	alone, err := NewNWCClient(ctx, &only, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatal(err)
	}
	defer alone.Close()
	var closed *SubscriptionClosedError
	if _, err := alone.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."}); !errors.As(err, &closed) {
		t.Fatalf("one closing hint: %v, want SubscriptionClosedError", err)
	}
}

// Every hint silent: each gets the call once, and the call ends with its context, never before a hint was tried.
func TestNWCClient_EveryRelaySilentTriesEachOnce(t *testing.T) {
	var urls []string
	var counts []*atomic.Int32
	for range 3 {
		u, n := countingWallet(t, false)
		urls, counts = append(urls, u), append(counts, n)
	}
	p := *newTestPairing(t, nil)
	p.RelayURLs = urls
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := NewNWCClient(ctx, &p, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PayInvoice: %v, want the deadline", err)
	}
	for i, n := range counts {
		if n.Load() != 1 {
			t.Errorf("hint %d got %d requests, want 1", i, n.Load())
		}
	}
}
