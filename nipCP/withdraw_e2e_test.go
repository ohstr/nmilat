package nipCP

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
)

// E-WD-14: a withdrawal through a PocketJournal against the fake Hub's bill
// ledger, its answers applied with ApplyWithdraw.

// checkedJournal is a PocketJournal that, at each write-ahead, reads the
// pending entry back from the pocket and checks that nothing was published to
// the Hub yet.
type checkedJournal struct {
	*PocketJournal
	t     *testing.T
	m     *memRelays
	h     *cashtest.FakeHub
	sent  int
	calls []nipcash.PendingCall
}

func (j *checkedJournal) WriteAhead(ctx context.Context, calls []nipcash.PendingCall) error {
	if err := j.PocketJournal.WriteAhead(ctx, calls); err != nil {
		return err
	}
	if n := len(j.h.Envelopes()); n != j.sent {
		j.t.Errorf("the withdrawal reached the Hub before its pending entry was written (%d envelopes, %d before)", n, j.sent)
	}
	w := pocket(j.t, j.m, j.Relays, j.UserPriv)
	for _, pc := range calls {
		e, ok := w[pc.RequestID]
		if !ok || e.State != StatePending || e.Quote == "" || e.Address == "" || e.Target != pc.Target {
			j.t.Errorf("the pending entry read back: %+v (%v)", e, ok)
		}
	}
	j.calls = append(j.calls, calls...)
	return nil
}

// pocket syncs the pocket and resolves it.
func pocket(t *testing.T, m *memRelays, relays []string, userPriv string) map[string]Entry {
	t.Helper()
	user, _ := keyPub(t, userPriv)
	s, err := Sync(context.Background(), m, relays, userPriv, FullSyncFilter(user), nil)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	w, _ := Resolve(s.Entries)
	return w
}

// store writes entries to the pocket as one batch.
func store(t *testing.T, j *checkedJournal, entries ...Entry) {
	t.Helper()
	for _, e := range entries {
		wrap, _, err := Seal(e, j.UserPriv)
		if err != nil {
			t.Fatalf("seal %+v: %v", e, err)
		}
		if _, err := Store(context.Background(), j.m, j.Relays, wrap); err != nil {
			t.Fatalf("store: %v", err)
		}
	}
}

type wdE2E struct {
	h *cashtest.FakeHub
	l *cashtest.WithdrawLedger
	j *checkedJournal
}

func newWDE2E(t *testing.T) *wdE2E {
	t.Helper()
	h := cashtest.NewFakeHub(t)
	m := newMem()
	pj, _ := journal(t, m, newDevice(t))
	return &wdE2E{h: h, l: h.ServeWithdrawals(t, nil), j: &checkedJournal{PocketJournal: pj, t: t, m: m, h: h}}
}

func e2eCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// withdraw mints tok's bill entry into the pocket, quotes and withdraws it
// through the journal, and returns the client, the call, its payout and the
// source entry.
func (e *wdE2E) withdraw(t *testing.T, tok string, cred nipcash.Credential, id EntryIdentity, secrets []nipcash.PendingSecret) (*client.Client, nipcash.PendingCall, *nipcash.Payout, Entry) {
	t.Helper()
	ctx := e2eCtx(t)
	c, err := client.Connect(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	src := Entry{W: c.WalletPubkey(), Rev: 1, Cash: tok, Amount: 21_000_000, Chain: "bitcoin", Identity: id, Secrets: secrets,
		State: StateLive, CheckedAt: time.Now().Unix()}
	store(t, e.j, src)
	q, err := c.QuoteWithdraw(ctx, nipcash.CashWithdrawQuoteParams{Address: cashtest.ExternalAddress(nipcash.ScriptType{Version: 0, ProgramLen: 20}), Credential: cred})
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	e.j.sent = len(e.h.Envelopes())
	dev, _ := e.j.Device.DeviceID(ctx)
	p, err := c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: q, Credential: cred}, e.j, dev)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if len(e.j.calls) == 0 {
		t.Fatal("nothing written ahead")
	}
	return c, e.j.calls[len(e.j.calls)-1], p, src
}

// applyFirst applies the reply: the entry with its receipt and the source
// spent, in one batch, read back.
func (e *wdE2E) applyFirst(t *testing.T, pc nipcash.PendingCall, p *nipcash.Payout, src Entry) (Entry, Entry) {
	t.Helper()
	entry := pocket(t, e.j.m, e.j.Relays, e.j.UserPriv)[pc.RequestID]
	writes, done, err := ApplyWithdraw(entry, src, p, e.h.NodeXOnly())
	if err != nil || done != nil || len(writes) != 2 {
		t.Fatalf("the reply applied: %+v %+v %v", writes, done, err)
	}
	store(t, e.j, writes...)
	w := pocket(t, e.j.m, e.j.Relays, e.j.UserPriv)
	got, spent := w[pc.RequestID], w[src.W]
	if got.State != StatePending || got.Receipt == "" || got.Receipt != p.Receipt {
		t.Fatalf("the entry after the receipt: %+v", got)
	}
	if spent.State != StateSpent || spent.Cash != src.Cash || len(spent.Secrets) != len(src.Secrets) {
		t.Fatalf("the source after the receipt: %+v, want spent keeping its token and secret", spent)
	}
	return got, spent
}

// E-WD-14, cancelled: a cash-mode slice whose payout is cancelled (no
// about-to-sign record a day after sent_by): the re-minted bill is added with
// the remint secret, then the entry is done.
func TestEWD14_PocketJournalCancelled(t *testing.T) {
	e := newWDE2E(t)
	target, err := nipcash.NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "cash", IdentityValue: target.Commitment(), AmountMillis: 21_000_000})
	e.l.InjectFault(cashtest.FaultHoldSign)
	cred := nipcash.BySecret(target.Secret())
	c, pc, p, src := e.withdraw(t, tok, cred, EntryIdentity{Type: IdentityCash}, []nipcash.PendingSecret{{Secret: target.Secret()}})
	entry, spent := e.applyFirst(t, pc, p, src)

	e.l.Advance(26 * time.Hour)
	ctx := e2eCtx(t)
	_, p, err = c.LookupWithdraw(ctx, pc, cred)
	if err != nil || p == nil || p.State != nipcash.PayoutCancelled {
		t.Fatalf("a day after sent_by: %+v %v, want cancelled", p, err)
	}
	writes, done, err := ApplyWithdraw(entry, spent, p, e.h.NodeXOnly())
	if err != nil || len(writes) != 1 || done == nil || done.State != StateDone {
		t.Fatalf("cancelled applied: %+v %+v %v", writes, done, err)
	}
	store(t, e.j, writes...)
	var remint string
	for _, s := range pc.Secrets {
		if s.Role == SecretRoleRemint {
			remint = s.Secret
		}
	}
	rb := pocket(t, e.j.m, e.j.Relays, e.j.UserPriv)[p.NewWalletPubkey]
	if rb.State != StateLive || rb.Cash != p.NewWalletToken.Token || rb.Amount != 21_000_000 || rb.Identity.Type != IdentityCash ||
		len(rb.Secrets) != 1 || rb.Secrets[0].Secret != remint || remint == "" {
		t.Fatalf("the re-minted bill read back: %+v, want it live with the remint secret", rb)
	}
	store(t, e.j, *done)
	if got := pocket(t, e.j.m, e.j.Relays, e.j.UserPriv)[pc.RequestID]; got.State != StateDone {
		t.Fatalf("the entry after the re-mint: %+v, want done", got)
	}
	nc, err := client.Connect(ctx, rb.Cash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	if st, err := nc.CashStatus(ctx, nipcash.BySecret(rb.Secrets[0].Secret), nipcash.ScopeMine); err != nil || st.Tombstone != nil || st.Recipients[0].Claimed {
		t.Fatalf("the re-minted bill's secret: %+v %v, want its live slice", st, err)
	}
}

// E-WD-14, final: a pubkey slice whose payout reaches final: done, then
// rewritten without address, quote and receipt.
func TestEWD14_PocketJournalFinal(t *testing.T) {
	e := newWDE2E(t)
	priv, pub := key(t)
	tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: 21_000_000})
	cred := nipcash.BySigning(priv)
	c, pc, p, src := e.withdraw(t, tok, cred, EntryIdentity{Type: IdentityPubkey, Value: pub}, nil)
	entry, spent := e.applyFirst(t, pc, p, src)

	ctx := e2eCtx(t)
	for range 40 {
		var err error
		if _, p, err = c.LookupWithdraw(ctx, pc, cred); err != nil || p == nil {
			t.Fatalf("lookup: %+v %v", p, err)
		}
		if p.State == nipcash.PayoutFinal {
			break
		}
		if w, d, err := ApplyWithdraw(entry, spent, p, e.h.NodeXOnly()); err != nil || w != nil || d != nil {
			t.Fatalf("%s applied: %+v %+v %v, want nothing written", p.State, w, d, err)
		}
		e.l.Chain().Mine(1)
	}
	if p.State != nipcash.PayoutFinal {
		t.Fatalf("the payout never reached final: %s", p.State)
	}
	writes, done, err := ApplyWithdraw(entry, spent, p, e.h.NodeXOnly())
	if err != nil || writes != nil || done == nil || done.State != StateDone {
		t.Fatalf("final applied: %+v %+v %v", writes, done, err)
	}
	store(t, e.j, *done)
	rw, err := WithdrawDoneRewrite(*done)
	if err != nil {
		t.Fatal(err)
	}
	store(t, e.j, rw)
	got := pocket(t, e.j.m, e.j.Relays, e.j.UserPriv)[pc.RequestID]
	if got.State != StateDone || got.Rev != rw.Rev || got.Address != "" || got.Quote != "" || got.Receipt != "" ||
		got.RequestID != pc.RequestID || got.Target != src.W || got.Notify != pc.Notify {
		t.Fatalf("the done entry rewritten: %+v", got)
	}
}
