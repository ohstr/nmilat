package nipCZ

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// memJournal writes calls ahead in memory.
type memJournal struct {
	mu    sync.Mutex
	calls map[string]nipcash.PendingCall
}

func (j *memJournal) WriteAhead(_ context.Context, calls []nipcash.PendingCall) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range calls {
		j.calls[c.RequestID] = c
	}
	return nil
}
func (j *memJournal) RecordDerived(context.Context, string, int64) error  { return nil }
func (j *memJournal) DerivedPlaced(context.Context, string) (bool, error) { return false, nil }

// T14-16: a zap transfer through the fake Hub carries a 23198 claim proof with
// ["m", "cash_transfer"] signed by the bill's bound pubkey, a 23192 item proof
// by the same key, zap_target and a request_id (CZ-SEND-04).
func TestZapTransfer_ThroughFakeHub(t *testing.T) {
	f := newFx(t)
	type seen struct {
		claim, proof *nip01.Event
		req          nipcash.CashTransferRequest
	}
	var mu sync.Mutex
	var got []seen
	hub := cashtest.NewFakeHub(t, cashtest.WithDecide(func(c cashtest.ItemCtx) *transport.Result {
		var s seen
		_ = json.Unmarshal(c.Item.Params, &s.req)
		s.claim, s.proof = &nip01.Event{}, &nip01.Event{}
		_ = json.Unmarshal([]byte(s.req.IdentityEvent), s.claim)
		_ = json.Unmarshal(c.Item.Proof, s.proof)
		mu.Lock()
		got = append(got, s)
		mu.Unlock()
		res, _ := json.Marshal(map[string]any{"amount_millis": 21000, "identity_type": "pubkey", "identity_value": f.recip})
		return &transport.Result{ID: c.Item.ID, ResultType: c.Item.Method, Result: res}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := client.OpenBatchSession(ctx, hub.NodeXOnly(), hub.RelayURLs())
	if err != nil {
		t.Fatal(err)
	}
	_, billWallet := cashtest.Keypair(t)
	secret, _ := cashtest.Keypair(t)
	bill, err := client.BillFromParts(billWallet, secret)
	if err != nil {
		t.Fatal(err)
	}
	params, err := ZapTransfer(nipcash.BySigning(f.senderPriv), true, Identity{Value: f.recip}, "", 21000, f.note)
	if err != nil {
		t.Fatal(err)
	}
	j := &memJournal{calls: map[string]nipcash.PendingCall{}}
	out, err := s.TransferMany(ctx, []client.BatchTransfer{{ID: "1", Bill: bill, Params: params}}, j, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Result == nil {
		t.Fatalf("%+v", out)
	}
	if _, ok := j.calls[params.RequestID]; !ok {
		t.Fatal("the zap transfer was not written ahead under its request_id")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("hub saw %d items", len(got))
	}
	g := got[0]
	if g.req.RequestID != params.RequestID || g.req.ZapTarget == nil || *g.req.ZapTarget != f.note.ID || *g.req.AmountMillis != 21000 {
		t.Fatalf("%+v", g.req)
	}
	if g.claim.Kind != nipcash.KindClaimProof || g.claim.PubKey != f.sender {
		t.Fatalf("claim proof kind %d by %s", g.claim.Kind, g.claim.PubKey)
	}
	if m := g.claim.GetTag("m"); len(m) != 1 || m[0] != nipcash.MethodCashTransfer {
		t.Fatalf("claim proof m tag %v", m)
	}
	if g.proof.Kind != transport.KindItemProof || g.proof.PubKey != f.sender {
		t.Fatalf("item proof kind %d by %s", g.proof.Kind, g.proof.PubKey)
	}
}
