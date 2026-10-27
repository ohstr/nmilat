package client

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// redeemInvoice is a real BOLT11 invoice for 5000 millis (nip57's decode fixture).
const redeemInvoice = "lnfc50n1p5hxs4npp5smus34m4mzd2jk7gepqkx9j89w2ukrjfajrvevwgslklzgt8l4zsdqqcqzvsxqyz5vqrzjqwz8th0q6p25q5wcvxh2s75n960tm3tung3vc7lmmmcdltt98pjs9apyqqqqqqqqqyqqqqlgqqqqqeqpjqrzjqtnr4hly8edgpl5wvcx86ekcc2rezdnq2calx5xpwk92l50qscwteapyqqqqqqqqquqqqqlgqqqqqeqpjqrzjqwz8th0q6p25q5wcvxh2s75n960tm3tung3vc7lmmmcdltt98pjs9apyqqqqqqqqqgqqqqlgqqqqqeqpjqsp5ge3wl84an6d34x6r7hm82thlg7vgwdffec5xnut90uwj3fvtaqjs9qxpqysgq6rp4rv2lgkffvd239dmj4ehg7vfxuuulu2amjpjf3rrhjhyay0djvjj8hn95rlz9g2kudqmqhw49urrxm6fhnzx6htwpjv6hj3k53hcq7qxkwk"

// redeemHub answers cash_status with one row of 5000 (net 4850) for the
// signer's key and records every cash_redeem it is sent.
type redeemHub struct {
	*fakeHub
	mu      sync.Mutex
	redeems []nipcash.CashRedeemRequest
}

func newRedeemHub(t *testing.T, me string) *redeemHub {
	h := &redeemHub{}
	h.fakeHub = newTestHub(t, func(item transport.Item) *transport.Result {
		switch item.Method {
		case nipcash.MethodCashStatus:
			return &transport.Result{ID: item.ID, ResultType: item.Method, Result: json.RawMessage(`{"recipients":[{"identity_type":"pubkey","identity_value":"` +
				me + `","amount_millis":5000,"claimed":false,"redeem_fee_millis":150,"net_redeemable_millis":4850,"min_transfer_millis":0}]}`)}
		case nipcash.MethodCashRedeem:
			var r nipcash.CashRedeemRequest
			_ = json.Unmarshal(item.Params, &r)
			h.mu.Lock()
			h.redeems = append(h.redeems, r)
			h.mu.Unlock()
			return &transport.Result{ID: item.ID, ResultType: item.Method, Result: json.RawMessage(`{"preimage":"` + strings.Repeat("ab", 32) + `","fees_paid":0}`)}
		}
		return nil
	})
	return h
}

func (h *redeemHub) sent() []nipcash.CashRedeemRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]nipcash.CashRedeemRequest(nil), h.redeems...)
}

func redeemClient(t *testing.T) (*Client, *redeemHub, string) {
	t.Helper()
	priv, me := sessionKeypair(t)
	hub := newRedeemHub(t, me)
	s, _ := openTestSession(t, hub.fakeHub)
	_, target := sessionKeypair(t)
	return &Client{walletPubkey: target, connSecret: connSecretFor(target), session: s}, hub, priv
}

// stubInvoice makes every invoice decode as amountless for the test.
func stubAmountless(t *testing.T) {
	t.Helper()
	orig := nip57.DecodeBolt11
	nip57.DecodeBolt11 = func(string) (*nip57.Invoice, error) {
		return &nip57.Invoice{Currency: "fc", PaymentHash: strings.Repeat("12", 32)}, nil
	}
	t.Cleanup(func() { nip57.DecodeBolt11 = orig })
}

// T11 (Redeem follow-up): with AutoAmount the redeem pays what
// RedeemInvoiceMillis says, and an invoice for another amount is refused before
// anything is sent.
func TestCashRedeemWith_AutoAmount(t *testing.T) {
	ctx, cancel := e2eContext(t)
	defer cancel()

	t.Run("same node: the invoice's full amount matches", func(t *testing.T) {
		c, hub, priv := redeemClient(t)
		r, err := c.CashRedeemWith(ctx, nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: nipcash.BySigning(priv)},
			RedeemOptions{AutoAmount: true, Payee: c.session.HubIdentity()})
		if err != nil || r == nil {
			t.Fatalf("(%v, %v)", r, err)
		}
		if got := hub.sent(); len(got) != 1 || got[0].Amount != nil {
			t.Fatalf("sent %+v, want one redeem without an amount param", got)
		}
	})
	t.Run("another node: net amount differs, nothing sent", func(t *testing.T) {
		c, hub, priv := redeemClient(t)
		_, err := c.CashRedeemWith(ctx, nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: nipcash.BySigning(priv)},
			RedeemOptions{AutoAmount: true})
		if !errors.Is(err, ErrInvoiceAmount) {
			t.Fatalf("err = %v, want ErrInvoiceAmount", err)
		}
		if n := len(hub.sent()); n != 0 {
			t.Fatalf("%d redeems sent", n)
		}
	})
	t.Run("amountless invoice takes the amount", func(t *testing.T) {
		stubAmountless(t)
		c, hub, priv := redeemClient(t)
		if _, err := c.CashRedeemWith(ctx, nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: nipcash.BySigning(priv)},
			RedeemOptions{AutoAmount: true}); err != nil {
			t.Fatal(err)
		}
		if got := hub.sent(); len(got) != 1 || got[0].Amount == nil || *got[0].Amount != 4850 {
			t.Fatalf("sent %+v, want amount 4850", got)
		}
	})
	t.Run("amountless invoice with a wrong amount param", func(t *testing.T) {
		stubAmountless(t)
		c, hub, priv := redeemClient(t)
		wrong := uint64(5000)
		_, err := c.CashRedeemWith(ctx, nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: nipcash.BySigning(priv), Amount: &wrong},
			RedeemOptions{AutoAmount: true})
		if !errors.Is(err, ErrInvoiceAmount) || len(hub.sent()) != 0 {
			t.Fatalf("err = %v, sent %d; want ErrInvoiceAmount and nothing sent", err, len(hub.sent()))
		}
	})
	t.Run("without AutoAmount nothing is read or checked", func(t *testing.T) {
		c, hub, priv := redeemClient(t)
		if _, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: nipcash.BySigning(priv)}); err != nil {
			t.Fatal(err)
		}
		if n := len(hub.sent()); n != 1 {
			t.Fatalf("%d redeems sent, want 1", n)
		}
		for _, e := range hub.envelopes() {
			for _, it := range e.Items {
				if it.Method == nipcash.MethodCashStatus {
					t.Fatal("a plain CashRedeem read cash_status")
				}
			}
		}
	})
}

func TestRedeemAmount(t *testing.T) {
	five := uint64(5000)
	for _, tc := range []struct {
		name    string
		invoice uint64
		param   *uint64
		want    uint64
		wantErr bool
		wantSet bool
	}{
		{"invoice matches", 5000, nil, 5000, false, false},
		{"invoice differs", 5000, nil, 4850, true, false},
		{"amountless takes it", 0, nil, 4850, false, true},
		{"amountless param matches", 0, &five, 5000, false, true},
		{"amountless param differs", 0, &five, 4850, true, false},
		{"nothing to pay out", 0, nil, 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := redeemAmount(nipcash.CashRedeemParams{Amount: tc.param}, int64(tc.invoice), tc.want)
			if tc.wantErr {
				if !errors.Is(err, ErrInvoiceAmount) {
					t.Fatalf("err = %v, want ErrInvoiceAmount", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantSet != (p.Amount != nil) || (p.Amount != nil && *p.Amount != tc.want) {
				t.Fatalf("Amount = %v", p.Amount)
			}
		})
	}
}
