package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// T11-36, T11-53, T11-54 (partial).
// ConnectCashHub + Info run the online check and read the announcement; a mint
// is written ahead and, answered with a code other than BAD_REQUEST (the fake
// serves no mint_cash), is pending with LastCode set.
func TestHubClient_InfoAndMintWriteAhead(t *testing.T) {
	hub := cashtest.NewFakeHub(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	h, err := ConnectCashHub(ctx, hub.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	info, err := h.Info(ctx)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !info.Verified || info.IdentityXOnly != hub.NodeXOnly() || info.Chain != cashtest.FakeChain ||
		!info.LookupOffered || info.MaxRequestAge != transport.DefaultMaxRequestAge || !info.TestNetwork() {
		t.Errorf("info = %+v", info)
	}

	j := newTestJournal()
	target := mustCashTarget(t)
	_, err = h.MintCash(ctx, nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(target, 1000)}}, j, "dev")
	var ie *IndeterminateError
	if !errors.As(err, &ie) || ie.Call.LastCode != "NOT_IMPLEMENTED" {
		t.Fatalf("err = %v, want an IndeterminateError with LastCode NOT_IMPLEMENTED", err)
	}
	calls := j.all()
	if len(calls) != 1 {
		t.Fatalf("%d calls written", len(calls))
	}
	pc := calls[0]
	if pc.Method != nipcash.MethodMintCash || pc.Amount != 1000 || pc.Device != "dev" || pc.Chain != cashtest.FakeChain ||
		len(pc.Secrets) != 1 || pc.Secrets[0].Secret != target.Secret() || pc.HubIdentity != hub.NodeXOnly() {
		t.Errorf("written call = %+v", pc)
	}
	if strings.Contains(string(pc.Params), target.Secret()) {
		t.Error("Params carry the cash secret")
	}
	if _, err := h.MintCash(ctx, nipcash.MintCashParams{}, nil, "dev"); !errors.Is(err, ErrNoJournal) {
		t.Errorf("no journal: %v", err)
	}
}

// T11-18.
func TestConnect_RefusesACashHubString(t *testing.T) {
	hub := cashtest.NewFakeHub(t)
	if _, err := Connect(context.Background(), hub.CashHubConnection()); !errors.Is(err, ErrCashHubConnection) {
		t.Fatalf("err = %v, want ErrCashHubConnection", err)
	}
}

// T11-15.
// A bearer lookup goes without the cash secret first, and with it only after
// UNAUTHORIZED.
func TestLookupTransfer_BearerRetry(t *testing.T) {
	var sawWithout, sawWith int
	hub := newTestHub(t, func(item transport.Item) *transport.Result {
		var p nipcash.CashLookupRequest
		_ = json.Unmarshal(item.Params, &p)
		if p.CashSecret == "" {
			sawWithout++
			return &transport.Result{ID: item.ID, ResultType: item.Method, Error: &transport.ResultError{Code: nipcash.ErrCodeUnauthorized}}
		}
		sawWith++
		return &transport.Result{ID: item.ID, ResultType: item.Method, Result: json.RawMessage(`{"status":"done","result":{"amount_millis":1}}`)}
	})
	relay := startFakeHub(t, hub)
	_, target := sessionKeypair(t)
	c := &Client{walletPubkey: target, connSecret: connSecretFor(target)}
	ctx, cancel := e2eContext(t)
	defer cancel()
	s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatal(err)
	}
	c.session = s
	secret := mustCashTarget(t).Secret()
	pc := nipcash.PendingCall{RequestID: testRequestID, Deadline: 1_900_000_000, SourceSecret: secret, Method: nipcash.MethodCashTransfer}
	lo, err := c.LookupTransfer(ctx, pc, nipcash.BySecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	if lo.Status != nipcash.LookupDone || sawWithout != 1 || sawWith != 1 {
		t.Fatalf("lookup %+v; without %d, with %d", lo, sawWithout, sawWith)
	}

	act, err := Recover(ctx, pc, func(ctx context.Context, pc nipcash.PendingCall) (LookupOutcome, error) {
		return c.LookupTransfer(ctx, pc, nipcash.BySecret(secret))
	}, "", nowForTest())
	if err != nil || act.Kind != ActionClose {
		t.Fatalf("Recover = %+v, %v", act, err)
	}
}

// E-LK-04.
// A lookup answer that does not have the spec's shape is Malformed, never unknown.
func TestLookup_MalformedIsNotUnknown(t *testing.T) {
	hub := newTestHub(t, func(item transport.Item) *transport.Result {
		return &transport.Result{ID: item.ID, ResultType: item.Method, Result: json.RawMessage(`{"status":"gone"}`)}
	})
	relay := startFakeHub(t, hub)
	priv, target := sessionKeypair(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	s, err := OpenBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatal(err)
	}
	lo, err := s.lookup(ctx, mustBill(t, target), nipcash.BySigning(priv), nipcash.PendingCall{RequestID: testRequestID, Deadline: 1_900_000_000}, "")
	if err != nil || !lo.Malformed || lo.Status != "" {
		t.Fatalf("lookup = %+v, %v", lo, err)
	}
}

// T11-24.
func TestCashSecretCredential_RefusesTheConnectionSecret(t *testing.T) {
	_, target := sessionKeypair(t)
	c := &Client{walletPubkey: target, connSecret: connSecretFor(target)}
	if _, err := c.CashSecretCredential(connSecretFor(target)); !errors.Is(err, ErrSecretIsConnectionSecret) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.CashSecretCredential(mustCashTarget(t).Secret()); err != nil {
		t.Fatal(err)
	}
}

// T11-22.
func TestZapBill_NeedsItsContext(t *testing.T) {
	tok := nipcash.Token{Scheme: nipcash.SchemeZapV1}
	c := &Client{token: &tok}
	if _, err := c.billSession(context.Background()); !errors.Is(err, ErrZapContextRequired) {
		t.Fatalf("err = %v", err)
	}
	if _, err := SelectVerifiedCopy([]nipcash.Token{tok}, nil, strings.Repeat("ab", 32)); !errors.Is(err, ErrZapContextRequired) {
		t.Fatalf("SelectVerifiedCopy err = %v", err)
	}
}

// The publish hooks apply to a mint, a NIP-47 call: the after hook fires once
// the request is sent, and a filtered request is lost, leaving the call pending.
func TestHubClient_MintPublishHooks(t *testing.T) {
	hub := cashtest.NewFakeHub(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	h, err := ConnectCashHub(ctx, hub.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p := nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(mustCashTarget(t), 1000)}}

	fired := 0
	if _, err := h.MintCash(WithAfterPublish(ctx, func() { fired++ }), p, newTestJournal(), "dev"); err == nil {
		t.Fatal("the fake serves no mint_cash")
	}
	if fired != 1 {
		t.Fatalf("after-publish hook fired %d times, want 1", fired)
	}

	short, cancelShort := context.WithTimeout(ctx, 2*time.Second)
	defer cancelShort()
	short = WithPublishFilter(short, func(ev *nip01.Event) bool { return ev.Kind != 23194 })
	_, err = h.MintCash(short, p, newTestJournal(), "dev")
	var ie *IndeterminateError
	if !errors.As(err, &ie) || ie.Call.LastCode != "" {
		t.Fatalf("a lost mint request: %v, want a pending call with no code", err)
	}
}
