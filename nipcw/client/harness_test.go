package client

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

func testContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	if d, ok := t.Deadline(); ok {
		return context.WithDeadline(context.Background(), d.Add(-10*time.Second))
	}
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

// circle is a fake Circle Wallet Hub that checks a join the way NIP-CW §Private
// Join says: the bill proof by one of its live connection secrets, the item proof
// by the request's pubkey, then VerifyJoinProof. joinAnswer and lookupAnswer
// override what it answers.
type circle struct {
	*cashtest.FakeHub
	t *testing.T

	mu           sync.Mutex
	used         map[string]bool
	joins        map[string]string // connection_pubkey -> the reply
	members      map[string]bool
	joinAnswer   func(req nipcw.CreateCircleWalletRequest) *transport.Result
	lookupAnswer func(signer string, req nipcash.CashLookupRequest) *transport.Result
	itemSigners  []string
}

func newCircle(t *testing.T, opts ...cashtest.Option) *circle {
	t.Helper()
	c := &circle{t: t, used: map[string]bool{}, joins: map[string]string{}, members: map[string]bool{}}
	c.FakeHub = cashtest.NewFakeHub(t, append([]cashtest.Option{cashtest.WithCircleHub(), cashtest.WithDecide(c.decide)}, opts...)...)
	return c
}

func (c *circle) admit(pub string) { c.mu.Lock(); c.members[pub] = true; c.mu.Unlock() }

func (c *circle) setJoinAnswer(f func(nipcw.CreateCircleWalletRequest) *transport.Result) {
	c.mu.Lock()
	c.joinAnswer = f
	c.mu.Unlock()
}

func (c *circle) setLookupAnswer(f func(signer string, req nipcash.CashLookupRequest) *transport.Result) {
	c.mu.Lock()
	c.lookupAnswer = f
	c.mu.Unlock()
}

func (c *circle) lastSigner() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.itemSigners[len(c.itemSigners)-1]
}

func (c *circle) decide(ctx cashtest.ItemCtx) *transport.Result {
	item := ctx.Item
	hash, err := transport.CanonicalParamsHash(item.Params)
	if err != nil || item.Target != c.CirclePubkey() {
		return nil
	}
	want := transport.ProofBinding{Target: item.Target, HubXOnly: c.NodeXOnly(), Method: item.Method, ParamsHash: hash,
		Nonce: ctx.Envelope.Nonce, NotAfter: ctx.Envelope.NotAfter}
	secretPub, _ := utils.GetPublicKey(c.CircleSecret())
	if _, err := transport.VerifyBillProofAny(item.BillProof, want, ctx.Now, []string{secretPub}); err != nil {
		return nil // omitted
	}
	signer, itemErr := transport.VerifyItemProof(item.Proof, want, ctx.Now)
	c.mu.Lock()
	c.itemSigners = append(c.itemSigners, signer)
	c.mu.Unlock()
	refuse := func(code string) *transport.Result {
		return &transport.Result{Error: &transport.ResultError{Code: code, Message: code}}
	}
	switch item.Method {
	case nipcw.MethodCreateCircleWallet:
		req, err := nipcw.ParseCreateCircleWalletRequest(item.Params)
		if err != nil {
			return refuse(nipcw.ErrBadRequest)
		}
		if itemErr != nil || signer != req.Pubkey {
			return refuse(nipcw.ErrUnauthorized)
		}
		c.mu.Lock()
		answer := c.joinAnswer
		c.mu.Unlock()
		if answer != nil {
			return answer(req)
		}
		_, err = nipcw.VerifyJoinProof(req, c.CirclePubkey(), ctx.Now, func(id string) bool {
			c.mu.Lock()
			defer c.mu.Unlock()
			seen := c.used[id]
			c.used[id] = true
			return seen
		})
		if err != nil {
			var pe *nipcw.JoinProofError
			if errors.As(err, &pe) {
				return refuse(pe.Code)
			}
			return refuse(nipcw.ErrUnauthorized)
		}
		c.mu.Lock()
		member := c.members[req.Pubkey]
		c.mu.Unlock()
		if !member {
			return refuse(nipcw.ErrRestricted)
		}
		reply := c.details(req.Pubkey, req.ConnectionPubkey, req.MaxAmount, req.MaxReceive, req.BudgetRenewal)
		c.mu.Lock()
		c.joins[req.ConnectionPubkey] = reply
		c.mu.Unlock()
		return &transport.Result{Result: json.RawMessage(reply)}
	case nipcash.MethodCashLookup:
		var req nipcash.CashLookupRequest
		if err := json.Unmarshal(item.Params, &req); err != nil {
			return refuse(nipcw.ErrBadRequest)
		}
		if itemErr != nil {
			return refuse(nipcw.ErrUnauthorized)
		}
		c.mu.Lock()
		answer := c.lookupAnswer
		reply, ok := c.joins[req.ConnectionPubkey]
		c.mu.Unlock()
		if answer != nil {
			return answer(signer, req)
		}
		if ok {
			return &transport.Result{Result: json.RawMessage(`{"status":"done","result":` + reply + `}`)}
		}
		return &transport.Result{Result: json.RawMessage(`{"status":"unknown"}`)}
	}
	return nil
}

// details is a full reply for member and connection.
func (c *circle) details(member, connection string, maxAmount, maxReceive uint64, renewal string) string {
	rot := uint64(432000)
	s, err := nipcw.EncryptDetails(c.CirclePriv(), member, nipcw.CircleWalletDetails{
		WalletPubkey: walletPubkey, ConnectionPubkey: connection, Relays: []string{"wss://wallet.example"},
		MaxAmount: maxAmount, MaxReceive: maxReceive, ExpiresAt: 1720000000, FeesPpm: 0, DustThresholdMillis: 1000,
		RotationDelaySecs: &rot, BudgetRenewal: renewal,
	})
	if err != nil {
		c.t.Errorf("details: %v", err)
	}
	return s
}

const walletPubkey = "abababababababababababababababababababababababababababababababab"

// journal records what Join writes ahead, and how many envelopes the Hub had
// seen at that moment.
type journal struct {
	mu      sync.Mutex
	written []PendingJoin
	before  []int
	hub     *circle
	fail    error
}

func (j *journal) WriteAhead(_ context.Context, p PendingJoin) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fail != nil {
		return j.fail
	}
	j.written = append(j.written, p)
	if j.hub != nil {
		j.before = append(j.before, len(j.hub.Envelopes()))
	}
	return nil
}

func (j *journal) all() []PendingJoin {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]PendingJoin(nil), j.written...)
}

func keypair(t *testing.T) (string, string) {
	t.Helper()
	return cashtest.Keypair(t)
}

func connect(t *testing.T, ctx context.Context, c *circle) *Client {
	t.Helper()
	cl, err := Connect(ctx, c.CircleHubConnection(), Options{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(cl.Close)
	return cl
}
