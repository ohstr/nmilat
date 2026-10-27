package client

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

// joinFixture is a Circle Wallet Hub that admits every join whose proofs verify
// against the envelope that carried it.
type joinFixture struct {
	hub     *fakeHub
	hubConn Bill
	hubPub  string
}

func newJoinFixture(t *testing.T, maxItems int) *joinFixture {
	t.Helper()
	hubWalletPriv, hubWalletPub := sessionKeypair(t)
	hubSecret, _ := sessionKeypair(t)
	hubSecretPub, err := utils.GetPublicKey(hubSecret)
	if err != nil {
		t.Fatal(err)
	}
	f := &joinFixture{hubPub: hubWalletPub}
	f.hub = newTestHub(t, func(item transport.Item) *transport.Result {
		var req nipcw.CreateCircleWalletRequest
		if json.Unmarshal(item.Params, &req) != nil {
			return nil
		}
		hash, err := transport.CanonicalParamsHash(item.Params)
		if err != nil {
			return nil
		}
		env := f.hub.envelopes()
		want := transport.ProofBinding{
			Target: hubWalletPub, HubXOnly: f.hub.hubXOnly, Method: nipcw.MethodCreateCircleWallet,
			ParamsHash: hash, Nonce: env[len(env)-1].Nonce, NotAfter: env[len(env)-1].NotAfter,
		}
		if signer, err := transport.VerifyItemProof(item.Proof, want, time.Now()); err != nil || signer != req.Pubkey {
			return nil
		}
		if signer, err := transport.VerifyBillProof(item.BillProof, want, time.Now()); err != nil || signer != hubSecretPub {
			return nil
		}
		details := `{"wallet_pubkey":"` + strings.Repeat("ab", 32) + `","connection_pubkey":"` + req.ConnectionPubkey +
			`","relays":["wss://w"],"max_amount":1000,"max_receive":0,"expires_at":1,"fees_ppm":0,"dust_threshold_millis":0,"budget_renewal":"never"}`
		body, _ := json.Marshal(map[string]string{"encrypted_details": encryptFrom(t, hubWalletPriv, req.Pubkey, details)})
		return &transport.Result{ID: item.ID, ResultType: item.Method, Result: body}
	})
	f.hub.limits.MaxItems = maxItems
	f.hubConn, err = BillFromParts(hubWalletPub, hubSecret)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *joinFixture) join(t *testing.T, id string) BatchCircleJoin {
	t.Helper()
	priv, _ := sessionKeypair(t)
	key, err := nipcw.NewConnectionKey()
	if err != nil {
		t.Fatal(err)
	}
	j, err := nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(priv), Connection: key, MaxAmountMillis: 1000}.Prepare(f.hubPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return BatchCircleJoin{ID: id, Hub: f.hubConn, Join: j}
}

// Joins that spill into later envelopes are built there and answered: every
// join gets an outcome.
func TestCreateCircleWalletMany_SpillsAcrossEnvelopes(t *testing.T) {
	f := newJoinFixture(t, 2)
	s, _ := openTestSession(t, f.hub)
	ctx, cancel := e2eContext(t)
	defer cancel()
	joins := []BatchCircleJoin{f.join(t, "a"), f.join(t, "b"), f.join(t, "c"), f.join(t, "d"), f.join(t, "e")}
	out, err := s.CreateCircleWalletMany(ctx, joins)
	if err != nil {
		t.Fatalf("CreateCircleWalletMany: %v", err)
	}
	if len(out) != len(joins) {
		t.Fatalf("%d outcomes, want %d", len(out), len(joins))
	}
	for i, o := range out {
		if o.ID != joins[i].ID || !o.Succeeded() || o.Result == nil {
			t.Errorf("join %s: id %s state %v error %+v", joins[i].ID, o.ID, o.State, o.Error)
		}
	}
	if n := len(f.hub.envelopes()); n != 3 {
		t.Fatalf("%d envelopes, want 3", n)
	}
}

// A batch that stops before an envelope goes out still gives every join an
// outcome: OutcomeNotSent for each join of the unsent envelopes.
func TestCreateCircleWalletMany_UnsentJoinsHaveAnOutcome(t *testing.T) {
	f := newJoinFixture(t, 1)
	s, _ := openTestSession(t, f.hub)
	ctx, cancel := e2eContext(t)
	defer cancel()
	used := f.join(t, "used")
	// Item claims the prepared join first, whatever the binding.
	_, _ = used.Join.Item("x", strings.Repeat("11", 32), nipcash.ItemBinding{})
	joins := []BatchCircleJoin{f.join(t, "a"), used, f.join(t, "c")}
	out, err := s.CreateCircleWalletMany(ctx, joins)
	if !errors.Is(err, nipcw.ErrPreparedJoinUsed) {
		t.Fatalf("err = %v, want ErrPreparedJoinUsed", err)
	}
	if len(out) != 3 {
		t.Fatalf("%d outcomes, want 3", len(out))
	}
	if !out[0].Succeeded() {
		t.Errorf("a: state %v", out[0].State)
	}
	for _, o := range out[1:] {
		if o.State != OutcomeNotSent || o.SafeToResend() || o.NeedsLookup() {
			t.Errorf("%s: state %v, want not sent", o.ID, o.State)
		}
	}
	if OutcomeNotSent.String() != "not sent" {
		t.Error(OutcomeNotSent.String())
	}
}

// A join that is malformed is refused before anything is built or sent: no
// prepared join is used up.
func TestCreateCircleWalletMany_RefusedBeforeBuilding(t *testing.T) {
	f := newJoinFixture(t, 4)
	s, relay := openTestSession(t, f.hub)
	ctx, cancel := e2eContext(t)
	defer cancel()
	good := f.join(t, "good")
	other := f.join(t, "other")
	other.Join.HubPubkey = strings.Repeat("ee", 32)
	if out, err := s.CreateCircleWalletMany(ctx, []BatchCircleJoin{good, other}); err == nil || out != nil {
		t.Fatalf("(%v, %v), want a refusal and no outcomes", out, err)
	}
	if len(requestsOn(relay)) != 0 {
		t.Fatal("something was published")
	}
	if _, err := good.Join.Item("x", strings.Repeat("11", 32), nipcash.ItemBinding{}); errors.Is(err, nipcw.ErrPreparedJoinUsed) {
		t.Fatal("the good join was used up")
	}
}
