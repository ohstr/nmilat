package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// consolidateOK is a cash_consolidate success the client can parse.
func consolidateOK(item transport.Item) *transport.Result {
	return &transport.Result{ID: item.ID, ResultType: item.Method,
		Result: json.RawMessage(`{"amount_millis":3000,"new_wallet_pubkey":"` + strings.Repeat("cd", 32) + `"}`)}
}

// consolidateItem is a two-source consolidate on fresh bills, with the marks given.
func consolidateItem(t *testing.T, id string, marks ...bool) BatchConsolidate {
	t.Helper()
	sources := make([]nipcash.Source, len(marks))
	for i, m := range marks {
		priv, wallet := sessionKeypair(t)
		sources[i] = nipcash.Source{WalletPubkey: wallet, Amount: 1000, Credential: nipcash.BySigning(priv), Ordered: m}
	}
	_, to := sessionKeypair(t)
	return BatchConsolidate{ID: id, Bill: mustBill(t, sources[0].WalletPubkey),
		Params: nipcash.CashConsolidateParams{Sources: sources, To: nipcash.Pubkey(to)}}
}

func openTestSession(t *testing.T, hub *fakeHub) (*BatchSession, *cashtest.Relay) {
	t.Helper()
	relay := cashtest.NewRelay(t)
	hub.hub(t, relay)
	ctx, cancel := e2eContext(t)
	defer cancel()
	s, err := OpenBatchSession(ctx, hub.hubXOnly, []string{relay.URL()})
	if err != nil {
		t.Fatalf("OpenBatchSession: %v", err)
	}
	return s, relay
}

// T11 (ordered bills): sources whose ordered marks differ are refused locally,
// nothing written and nothing sent; uniform marks go out and the merged bill
// keeps the mark.
func TestConsolidateMany_MixedOrderedRefusedLocally(t *testing.T) {
	ctx, cancel := e2eContext(t)
	defer cancel()

	t.Run("mixed source marks", func(t *testing.T) {
		s, relay := openTestSession(t, newTestHub(t, consolidateOK))
		j := newTestJournal()
		ok := consolidateItem(t, "ok", false, false)
		mixed := consolidateItem(t, "mixed", true, false)
		out, err := s.ConsolidateMany(ctx, []BatchConsolidate{ok, mixed}, j, "d")
		if !errors.Is(err, ErrMixedOrdered) || out != nil {
			t.Fatalf("(%v, %v), want ErrMixedOrdered and no outcomes", out, err)
		}
		if len(j.all()) != 0 || len(requestsOn(relay)) != 0 {
			t.Fatal("something was written or published")
		}
	})
	t.Run("bill mark against an unmarked source", func(t *testing.T) {
		s, relay := openTestSession(t, newTestHub(t, consolidateOK))
		j := newTestJournal()
		it := consolidateItem(t, "1", false, false)
		it.Bill.Ordered = true // the bill is Sources[0]: ordered, Sources[1] not
		if _, err := s.ConsolidateMany(ctx, []BatchConsolidate{it}, j, "d"); !errors.Is(err, ErrMixedOrdered) {
			t.Fatalf("err = %v, want ErrMixedOrdered", err)
		}
		if len(j.all()) != 0 || len(requestsOn(relay)) != 0 {
			t.Fatal("something was written or published")
		}
	})
	t.Run("all ordered", func(t *testing.T) {
		s, _ := openTestSession(t, newTestHub(t, consolidateOK))
		it := consolidateItem(t, "1", false, true)
		it.Bill.Ordered = true
		out, err := s.ConsolidateMany(ctx, []BatchConsolidate{it, consolidateItem(t, "2", false, false)}, newTestJournal(), "d")
		if err != nil || len(out) != 2 {
			t.Fatalf("(%v, %v)", out, err)
		}
		if !out[0].Succeeded() || !out[0].Ordered {
			t.Errorf("all-ordered item: state %v, Ordered %v; want a result marked ordered", out[0].State, out[0].Ordered)
		}
		if !out[1].Succeeded() || out[1].Ordered {
			t.Errorf("unordered item: state %v, Ordered %v; want a result not marked", out[1].State, out[1].Ordered)
		}
	})
}

// A transfer's bills keep the source bill's mark.
func TestTransferMany_CarriesOrderedMark(t *testing.T) {
	ctx, cancel := e2eContext(t)
	defer cancel()
	w := newWATransfer(t, newTestHub(t, answerTransfer))
	w.item.Bill.Ordered = true
	out, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, newTestJournal(), "d")
	if err != nil || len(out) != 1 || !out[0].Succeeded() || !out[0].Ordered {
		t.Fatalf("(%+v, %v), want one result marked ordered", out, err)
	}
}

// The single-call CashConsolidate goes through the same check.
func TestCashConsolidate_MixedOrderedRefused(t *testing.T) {
	hub := newTestHub(t, consolidateOK)
	s, relay := openTestSession(t, hub)
	it := consolidateItem(t, "1", true, false)
	c := &Client{walletPubkey: it.Params.Sources[0].WalletPubkey, connSecret: connSecretFor(it.Params.Sources[0].WalletPubkey), session: s}
	ctx, cancel := e2eContext(t)
	defer cancel()
	j := newTestJournal()
	if _, err := c.CashConsolidate(ctx, it.Params, j, "d"); !errors.Is(err, ErrMixedOrdered) {
		t.Fatalf("err = %v, want ErrMixedOrdered", err)
	}
	if len(j.all()) != 0 || len(requestsOn(relay)) != 0 {
		t.Fatal("something was written or published")
	}
}

// The composites refuse a mix before their first call, and mark what they build.
func TestComposites_OrderedMarks(t *testing.T) {
	ctx := context.Background()
	src := func(wallet string, ordered bool) nipcash.Source {
		return nipcash.Source{WalletPubkey: wallet, Amount: 1000, Credential: nipcash.BySigning(strings.Repeat("a1", 32)), Ordered: ordered}
	}
	newFake := func() *fakeTransferConsolidater {
		return &fakeTransferConsolidater{
			transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
				return &nipcash.CashTransferResult{AmountMillis: 1000, NewWalletPubkey: "tw", NewWalletToken: "t"}, nil
			},
			consolidateFunc: func(nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
				return &nipcash.CashConsolidateResult{AmountMillis: 2000, NewWalletToken: "c", NewWalletPubkey: "w"}, nil
			},
		}
	}

	t.Run("TransferFromSources mixed", func(t *testing.T) {
		f := newFake()
		_, err := transferFromSources(ctx, f, TransferFromSourcesParams{
			Sources: []nipcash.Source{src("w1", true), src("w2", false)}, Amount: 1500, To: nipcash.Pubkey(strings.Repeat("ee", 32)),
			InterimIdentity: nipcash.Pubkey(strings.Repeat("ef", 32)),
		})
		if !errors.Is(err, ErrMixedOrdered) || len(f.consolidateCalls)+len(f.transferCalls) != 0 {
			t.Fatalf("err %v, calls %d/%d; want ErrMixedOrdered and no call", err, len(f.consolidateCalls), len(f.transferCalls))
		}
	})
	t.Run("TransferFromSources all ordered", func(t *testing.T) {
		r, err := transferFromSources(ctx, newFake(), TransferFromSourcesParams{
			Sources: []nipcash.Source{src("w1", true), src("w2", true)}, Amount: 1500, To: nipcash.Pubkey(strings.Repeat("ee", 32)),
			InterimIdentity: nipcash.Pubkey(strings.Repeat("ef", 32)),
		})
		if err != nil || !r.Ordered {
			t.Fatalf("(%+v, %v), want Ordered", r, err)
		}
	})
	t.Run("TransferFromSources one ordered source", func(t *testing.T) {
		r, err := transferFromSources(ctx, newFake(), TransferFromSourcesParams{
			Sources: []nipcash.Source{src("w1", true)}, Amount: 500, To: nipcash.Pubkey(strings.Repeat("ee", 32)),
		})
		if err != nil || !r.Ordered {
			t.Fatalf("(%+v, %v), want Ordered", r, err)
		}
	})
	t.Run("RekeyCashSlice mixed", func(t *testing.T) {
		f := newFake()
		cash := nipcash.Source{WalletPubkey: "w0", Amount: 1000, Credential: nipcash.BySecret("old"), Ordered: true}
		_, err := rekeyCashSlice(ctx, f, RekeyCashSliceParams{
			CashSlice: cash, ConsolidateWith: []nipcash.Source{src("w1", false)},
			InterimIdentity: nipcash.Pubkey(strings.Repeat("ef", 32)), InterimCredential: nipcash.BySigning(strings.Repeat("a1", 32)),
			NewTarget: mustCashTarget(t),
		})
		if !errors.Is(err, ErrMixedOrdered) || len(f.transferCalls) != 0 {
			t.Fatalf("err %v, transfers %d; want ErrMixedOrdered before the interim transfer", err, len(f.transferCalls))
		}
	})
	t.Run("RekeyCashSlice ordered", func(t *testing.T) {
		f := newFake()
		cash := nipcash.Source{WalletPubkey: "w0", Amount: 1000, Credential: nipcash.BySecret("old"), Ordered: true}
		r, err := rekeyCashSlice(ctx, f, RekeyCashSliceParams{
			CashSlice: cash, ConsolidateWith: []nipcash.Source{src("w1", true)},
			InterimIdentity: nipcash.Pubkey(strings.Repeat("ef", 32)), InterimCredential: nipcash.BySigning(strings.Repeat("a1", 32)),
			NewTarget: mustCashTarget(t),
		})
		if err != nil || !r.Ordered {
			t.Fatalf("(%+v, %v), want Ordered", r, err)
		}
		if len(f.consolidateCalls) != 1 || !f.consolidateCalls[0].Sources[0].Ordered {
			t.Fatal("the interim source must keep the cash slice's mark")
		}
		r, err = rekeyCashSlice(ctx, newFake(), RekeyCashSliceParams{CashSlice: cash, NewTarget: mustCashTarget(t)})
		if err != nil || !r.Ordered {
			t.Fatalf("in place: (%+v, %v), want Ordered", r, err)
		}
	})
}
