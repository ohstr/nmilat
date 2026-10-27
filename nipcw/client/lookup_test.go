package client

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
)

func result(s string) *transport.Result { return &transport.Result{Result: json.RawMessage(s)} }

// T12-08, T12-09, T12-24 (S-CW-20, 22, 133): what each lookup answer means; the
// lookup is signed by the join's key and still works while the Hub is closed.
func TestLookupJoin(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	hub := newCircle(t)
	memberPriv, memberPub := keypair(t)
	hub.admit(memberPub)
	cl := connect(t, ctx, hub)
	j := &journal{}
	res, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, j)
	if err != nil {
		t.Fatal(err)
	}
	pj := j.all()[0]
	cred := nipcw.BySigning(memberPriv)

	// T12-24: closed to joins, the earlier join is still looked up.
	block := cashtest.DefaultCircleWallet(hub.NodeXOnly())
	block["accepting"] = false
	hub.SetCircleWallet(block)
	if _, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, &journal{}); !errors.Is(err, ErrNotAccepting) {
		t.Fatalf("closed circle: %v", err)
	}
	act, err := cl.LookupJoin(ctx, pj, cred)
	if err != nil || act.Kind != JoinClose || act.Response.WalletPubkey != res.WalletPubkey || act.Response.ConnectionPubkey != pj.ConnectionPubkey {
		t.Fatalf("done: %+v %v", act, err)
	}
	if signer := hub.lastSigner(); signer != memberPub {
		t.Fatalf("lookup item proof signed by %s", signer)
	}

	_, newKey := keypair(t)
	var sawKey string
	cases := []struct {
		name   string
		answer *transport.Result
		kind   JoinActionKind
		until  int64
		reason string
	}{
		{"pending", result(`{"status":"pending","retry_after":1720000301}`), JoinWait, 1720000301, ""},
		{"unknown", result(`{"status":"unknown"}`), JoinMayRejoin, 0, ""},
		{"expired", result(`{"status":"expired"}`), JoinShow, 0, "join_expired"},
		{"omitted", nil, JoinWait, 0, ""},
		{"unauthorized", &transport.Result{Error: &transport.ResultError{Code: nipcw.ErrUnauthorized}}, JoinShow, 0, "lookup_unauthorized"},
		{"malformed", result(`{"status":"gone"}`), JoinShow, 0, "lookup_malformed"},
		{"done, other key", result(`{"status":"done","result":` + hub.details(memberPub, newKey, 1, 1, "never") + `}`), JoinShow, 0, "lookup_undecodable"},
	}
	for _, tc := range cases {
		answer := tc.answer
		hub.setLookupAnswer(func(_ string, req nipcash.CashLookupRequest) *transport.Result {
			sawKey = req.ConnectionPubkey
			return answer
		})
		act, err := cl.LookupJoin(ctx, pj, cred)
		if err != nil || act.Kind != tc.kind || act.Until != tc.until || act.Reason != tc.reason {
			t.Errorf("%s: %+v %v", tc.name, act, err)
		}
		if tc.answer != nil && sawKey != pj.ConnectionPubkey {
			t.Errorf("%s: looked up %s", tc.name, sawKey)
		}
	}

	// T12-09: after a rotation, the lookup names the new key: pending until
	// completes_at, then done with connection_pubkey = the new key.
	rotated := pj
	rotated.ConnectionPubkey = newKey
	hub.setLookupAnswer(func(_ string, req nipcash.CashLookupRequest) *transport.Result {
		return result(`{"status":"pending","retry_after":1720432000}`)
	})
	if act, err := cl.LookupJoin(ctx, rotated, cred); err != nil || act.Kind != JoinWait || act.Until != 1720432000 {
		t.Fatalf("rotation pending: %+v %v", act, err)
	}
	hub.setLookupAnswer(func(_ string, req nipcash.CashLookupRequest) *transport.Result {
		return result(`{"status":"done","result":` + hub.details(memberPub, req.ConnectionPubkey, 1, 1, "never") + `}`)
	})
	if act, err := cl.LookupJoin(ctx, rotated, cred); err != nil || act.Kind != JoinClose || act.Response.ConnectionPubkey != newKey {
		t.Fatalf("rotation done: %+v %v", act, err)
	}

	// A lookup signed by another key: the fake refuses it UNAUTHORIZED after the
	// bill proof verified; final, never Wait.
	otherPriv, _ := keypair(t)
	hub.setLookupAnswer(func(signer string, _ nipcash.CashLookupRequest) *transport.Result {
		if signer != memberPub {
			return &transport.Result{Error: &transport.ResultError{Code: nipcw.ErrUnauthorized}}
		}
		return result(`{"status":"unknown"}`)
	})
	if _, err := cl.LookupJoin(ctx, pj, nipcw.BySigning(otherPriv)); !errors.Is(err, ErrJoinSigner) {
		t.Fatalf("other signer: %v, want ErrJoinSigner before sending", err)
	}
	unsigned := pj // a pending join that did not record its signer
	unsigned.Pubkey = ""
	if act, _ := cl.LookupJoin(ctx, unsigned, nipcw.BySigning(otherPriv)); act.Kind != JoinShow || act.Reason != "lookup_unauthorized" {
		t.Fatalf("other signer: %+v", act)
	}
	other := pj
	other.HubPubkey = newKey
	if _, err := cl.LookupJoin(ctx, other, cred); err == nil {
		t.Fatal("a pending join of another Hub was looked up here")
	}
}
