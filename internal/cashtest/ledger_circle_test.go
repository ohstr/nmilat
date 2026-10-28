package cashtest_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip47"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcw"
	cwclient "github.com/ohstr/nmilat/nipcw/client"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

type joinJournal struct {
	mu      sync.Mutex
	written []cwclient.PendingJoin
}

func (j *joinJournal) WriteAhead(_ context.Context, p cwclient.PendingJoin) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.written = append(j.written, p)
	return nil
}

func newCircleLedger(t *testing.T) (*cashtest.FakeHub, *cashtest.WithdrawLedger) {
	t.Helper()
	h := cashtest.NewFakeHub(t, cashtest.WithCircleHub(), cashtest.WithClock(cashtest.RealClock{}))
	return h, h.ServeWithdrawals(t, nil)
}

func joinParams(priv string) nipcw.CreateCircleWalletParams {
	return nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(priv), MaxAmountMillis: 100_000,
		MaxReceiveMillis: 200_000, BudgetRenewal: nipcw.RenewalMonthly}
}

func walletCall(t *testing.T, w nipcw.WalletConnection, method string) (*nip47.ResponseEvent, error) {
	t.Helper()
	nwc, err := relayclient.NewNWCClient(spendCtx(t), &nip47.PairingInfo{WalletPubkey: w.WalletPubkey, RelayURLs: w.Relays, Secret: w.Secret},
		nip47.EncryptionNIP44V2)
	if err != nil {
		return nil, err
	}
	defer nwc.Close()
	return nwc.Call(spendCtx(t), method, struct{}{})
}

// The ledger's circle: a member joins, a non-member is RESTRICTED, a second
// join WALLET_EXISTS; the wallet answers on its own connection; the lookup is
// done; a rotation is pending, then done with the new key; a deleted wallet
// frees the member.
func TestLedgerCircle(t *testing.T) {
	h, l := newCircleLedger(t)
	ctx := spendCtx(t)
	cl, err := cwclient.Connect(ctx, h.CircleHubConnection(), cwclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cl.Close)
	priv, pub := cashtest.Keypair(t)
	var we *relayclient.WalletError
	if _, err := cl.Join(ctx, joinParams(priv), cwclient.JoinOptions{}, &joinJournal{}); !errors.As(err, &we) || we.Code != nipcw.ErrRestricted {
		t.Fatalf("a non-member: %v, want RESTRICTED", err)
	}
	h.AddMember(t, pub, true)
	j := &joinJournal{}
	res, err := cl.Join(ctx, joinParams(priv), cwclient.JoinOptions{}, j)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if res.RotationDelaySecs == nil || res.MaxAmountMillis != 100_000 || len(res.LeakedFields) != 0 {
		t.Fatalf("details %+v", res.CreateCircleWalletResponse)
	}
	if _, err := cl.Join(ctx, joinParams(priv), cwclient.JoinOptions{}, &joinJournal{}); !errors.As(err, &we) || we.Code != nipcw.ErrWalletExists {
		t.Fatalf("a second join: %v, want WALLET_EXISTS", err)
	}
	w := res.Wallet()
	if resp, err := walletCall(t, w, "get_balance"); err != nil || resp.Error != nil {
		t.Fatalf("get_balance: %+v %v", resp, err)
	}
	pj := j.written[0]
	act, err := cl.LookupJoin(ctx, pj, nipcw.BySigning(priv))
	if err != nil || act.Kind != cwclient.JoinClose || act.Response.WalletPubkey != w.WalletPubkey {
		t.Fatalf("lookup: %+v %v", act, err)
	}

	newKey, err := nipcw.NewConnectionKey()
	if err != nil {
		t.Fatal(err)
	}
	req, err := nipcw.NewMemberRequest(priv, h.CirclePubkey(), nipcw.ActionRotate, w.WalletPubkey, newKey.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.MemberRequest(req); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	var mre *cashtest.MemberRequestError
	if err := l.MemberRequest(req); !errors.As(err, &mre) || mre.Code != nipcw.ErrRequestReused {
		t.Fatalf("the same member request again: %v", err)
	}
	rotated := pj
	rotated.ConnectionPubkey = newKey.Pubkey()
	if act, err := cl.LookupJoin(ctx, rotated, nipcw.BySigning(priv)); err != nil || act.Kind != cwclient.JoinWait || act.Until == 0 {
		t.Fatalf("pending rotation: %+v %v", act, err)
	}
	l.Advance(cashtest.CircleRotationDelaySecs * time.Second)
	act, err = cl.LookupJoin(ctx, rotated, nipcw.BySigning(priv))
	if err != nil || act.Kind != cwclient.JoinClose || act.Response.ConnectionPubkey != newKey.Pubkey() {
		t.Fatalf("completed rotation: %+v %v", act, err)
	}
	w.Secret = newKey.Secret()
	if err := cwclient.DeleteWallet(ctx, w, func(context.Context) bool { return true }); err != nil {
		t.Fatalf("delete with the new key: %v", err)
	}
}

// A second connection of the circle joins; once revoked, its bill proofs
// verify nothing and the join is omitted; closed, the circle refuses joins.
func TestLedgerCircleConnections(t *testing.T) {
	h, l := newCircleLedger(t)
	ctx := spendCtx(t)
	second, err := l.AddCircleConnection()
	if err != nil {
		t.Fatal(err)
	}
	cl, err := cwclient.Connect(ctx, second, cwclient.Options{})
	if err != nil {
		t.Fatalf("connect with the second connection: %v", err)
	}
	t.Cleanup(cl.Close)
	pa, xa := cashtest.Keypair(t)
	pb, xb := cashtest.Keypair(t)
	h.AddMember(t, xa, true)
	h.AddMember(t, xb, true)
	if _, err := cl.Join(ctx, joinParams(pa), cwclient.JoinOptions{}, &joinJournal{}); err != nil {
		t.Fatalf("join over the second connection: %v", err)
	}
	if err := l.RevokeCircleConnection(second); err != nil {
		t.Fatal(err)
	}
	conn, err := nipcw.DecodeCircleHubConnection(second)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := cashclient.BillFromParts(conn.Pubkey, conn.Secret)
	if err != nil {
		t.Fatal(err)
	}
	s, err := cashclient.OpenBatchSession(ctx, h.NodeXOnly(), h.RelayURLs())
	if err != nil {
		t.Fatal(err)
	}
	k, _ := nipcw.NewConnectionKey()
	p := joinParams(pb)
	p.Connection = k
	prepared, err := p.Prepare(conn.Pubkey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	outs, _ := s.CreateCircleWalletMany(ctx, []cashclient.BatchCircleJoin{{ID: "1", Hub: hub, Join: prepared}})
	if len(outs) != 1 || outs[0].State == cashclient.OutcomeError || outs[0].Succeeded() {
		t.Fatalf("join over a revoked connection: %+v, want it omitted", outs)
	}
	l.SetCircleAccepting(false)
	first, err := cwclient.Connect(ctx, h.CircleHubConnection(), cwclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Close)
	if _, err := first.Join(ctx, joinParams(pb), cwclient.JoinOptions{}, &joinJournal{}); !errors.Is(err, cwclient.ErrNotAccepting) {
		t.Fatalf("a closed circle: %v", err)
	}
}
