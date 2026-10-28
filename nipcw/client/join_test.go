package client

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func params(t *testing.T, priv string) nipcw.CreateCircleWalletParams {
	t.Helper()
	return nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(priv), MaxAmountMillis: 100000,
		MaxReceiveMillis: 200000, BudgetRenewal: nipcw.RenewalMonthly}
}

// T12-10, T12-20, T12-25 (S-CW-40, 119, 120, 121, 125): a private join end to end.
// The identity comes from get_info after the online check, the journal is written
// before anything is sent, the item proof is the member's, the bill proof the
// Hub connection secret's, and the wallet is wallet_pubkey + relays + the
// journalled secret.
func TestJoin_EndToEnd(t *testing.T) {
	hub := newCircle(t)
	memberPriv, memberPub := keypair(t)
	hub.admit(memberPub)
	ctx, cancel := testContext(t)
	defer cancel()
	cl := connect(t, ctx, hub)
	if !cl.Verified() {
		t.Fatal("the fake's string is signed by its node; Verified() is false")
	}
	j := &journal{hub: hub}
	res, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, j)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	written := j.all()
	if len(written) != 1 || j.before[0] != 0 {
		t.Fatalf("journal %+v, envelopes before the write %v", written, j.before)
	}
	pj := written[0]
	if pj.HubPubkey != hub.CirclePubkey() || pj.Pubkey != memberPub || pj.ConnectionPubkey != res.ConnectionPubkey ||
		len(pj.ConnectionSecret) != 64 || pj.Deadline < time.Now().Unix()+290 {
		t.Fatalf("pending join %+v", pj)
	}
	w := res.Wallet()
	if w.WalletPubkey != walletPubkey || !slices.Equal(w.Relays, []string{"wss://wallet.example"}) || w.Secret != pj.ConnectionSecret {
		t.Fatalf("wallet %+v", w)
	}
	if res.MaxAmountMillis != 100000 || res.CapsRaised || res.MissingTerms != nil || res.LeakedFields != nil {
		t.Fatalf("response %+v", res.CreateCircleWalletResponse)
	}
	envs := hub.Envelopes()
	if len(envs) != 1 || len(envs[0].Items) != 1 {
		t.Fatalf("envelopes %+v", envs)
	}
	item := envs[0].Items[0]
	if item.Target != hub.CirclePubkey() || item.Method != nipcw.MethodCreateCircleWallet || strings.Contains(string(item.Params), pj.ConnectionSecret) {
		t.Fatalf("item %+v", item)
	}
	if s := hub.lastSigner(); s != memberPub {
		t.Fatalf("item proof signed by %s", s)
	}
}

// T12-23 (E-CSIG-01..03): the online check with circle_wallet.identity; nothing is
// sent on failure; an unverified string connects with Verified false.
func TestConnect_OnlineCheck(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	hub := newCircle(t)
	block := cashtest.DefaultCircleWallet("02" + hub.NodeXOnly())
	hub.SetCircleWallet(block)
	if _, err := Connect(ctx, hub.CircleHubConnection(), Options{}); err != nil {
		t.Fatalf("66-hex identity: %v", err)
	}
	_, other := keypair(t)
	hub.SetCircleWallet(cashtest.DefaultCircleWallet(other))
	if _, err := Connect(ctx, hub.CircleHubConnection(), Options{}); !errors.Is(err, nipcash.ErrHubIdentityMismatch) {
		t.Fatalf("another identity: %v", err)
	}
	hub.SetCircleWallet(cashtest.DefaultCircleWallet(hub.NodeXOnly()))
	hub.SetCircleChain("litecoin")
	if _, err := Connect(ctx, hub.CircleHubConnection(), Options{}); !errors.Is(err, nipcash.ErrChainMismatch) {
		t.Fatalf("chain mismatch: %v", err)
	}
	hub.SetCircleWallet(nil)
	hub.SetCircleChain(cashtest.FakeChain)
	if _, err := Connect(ctx, hub.CircleHubConnection(), Options{}); !errors.Is(err, ErrHubNonConforming) {
		t.Fatalf("no circle_wallet: %v", err)
	}
	if n := len(hub.Envelopes()); n != 0 {
		t.Fatalf("%d envelopes sent", n)
	}

	hub.SetCircleWallet(cashtest.DefaultCircleWallet(hub.NodeXOnly()))
	conn, _ := nipcw.DecodeCircleHubConnection(hub.CircleHubConnection())
	otherPriv, _ := keypair(t)
	sign, _ := nipcash.LocalChainSigner(otherPriv, cashtest.FakeChain)
	text, _ := nipcash.ConnSignedText(conn.Fields())
	conn.Signature, _ = sign(text)
	s, err := nipcw.EncodeCircleHubConnection(conn)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := Connect(ctx, s, Options{})
	if err != nil {
		t.Fatalf("unverified string: %v", err)
	}
	defer cl.Close()
	if cl.Verified() {
		t.Fatal("Verified() true for a string signed by another key")
	}
	if _, err := Connect(ctx, "nostr+walletconnect://"+hub.CirclePubkey()+"?relay=wss://x&secret="+hub.CircleSecret(), Options{}); err == nil {
		t.Fatal("a URI form was accepted")
	}
}

// T12-19, T12-21, T12-24, T12-10 (S-CW-25, 96, 105, 115; CW-GI-02, CW-ACC-01,
// CW-PAIR-01): everything refused before sending wraps ErrJoinNotSent, writes
// nothing ahead and sends nothing.
func TestJoin_NothingSent(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	hub := newCircle(t)
	memberPriv, memberPub := keypair(t)
	hub.admit(memberPub)
	cl := connect(t, ctx, hub)
	base := func() map[string]any { return cashtest.DefaultCircleWallet(hub.NodeXOnly()) }
	with := func(k string, v any) map[string]any { b := base(); b[k] = v; return b }
	without := func(k string) map[string]any { b := base(); delete(b, k); return b }
	warned := 0
	yes := func(context.Context) bool { warned++; return true }
	no := func(context.Context) bool { warned++; return false }

	cases := []struct {
		name  string
		block map[string]any
		p     func(*nipcw.CreateCircleWalletParams)
		o     JoinOptions
		want  error
	}{
		{"available_millis -1", with("available_millis", -1), nil, JoinOptions{}, ErrHubNonConforming},
		{"accepting false", with("accepting", false), nil, JoinOptions{}, ErrNotAccepting},
		{"over per_wallet_max_millis", with("per_wallet_max_millis", 99999), nil, JoinOptions{}, ErrOverHubLimit},
		{"over per_wallet_max_receive_millis", with("per_wallet_max_receive_millis", 199999), nil, JoinOptions{}, ErrOverHubLimit},
		{"under min_budget_renewal", with("min_budget_renewal", "yearly"), nil, JoinOptions{}, ErrOverHubLimit},
		{"over max_exp_secs", base(), func(p *nipcw.CreateCircleWalletParams) { p.Expiry = 2592001 * time.Second }, JoinOptions{}, ErrOverHubLimit},
		{"no rotation, no warning", without("rotation_delay_secs"), nil, JoinOptions{}, ErrRotationWarningRequired},
		{"no rotation, declined", without("rotation_delay_secs"), nil, JoinOptions{WarnNoRotation: no}, ErrJoinDeclined},
		{"bad renewal", base(), func(p *nipcw.CreateCircleWalletParams) { p.BudgetRenewal = "Monthly" }, JoinOptions{}, ErrOverHubLimit},
	}
	for _, k := range []string{"available_millis", "max_exp_secs", "fees_ppm", "fee_reserve", "dust_threshold_millis", "circle_policy", "accepting"} {
		cases = append(cases, struct {
			name  string
			block map[string]any
			p     func(*nipcw.CreateCircleWalletParams)
			o     JoinOptions
			want  error
		}{"missing " + k, without(k), nil, JoinOptions{}, ErrHubNonConforming})
	}
	for _, tc := range cases {
		hub.SetCircleWallet(tc.block)
		p := params(t, memberPriv)
		if tc.p != nil {
			tc.p(&p)
		}
		j := &journal{}
		_, err := cl.Join(ctx, p, tc.o, j)
		if !errors.Is(err, tc.want) || !errors.Is(err, ErrJoinNotSent) {
			t.Errorf("%s: %v, want %v (an ErrJoinNotSent)", tc.name, err, tc.want)
		}
		if len(j.all()) != 0 || len(hub.Envelopes()) != 0 {
			t.Errorf("%s: journal %d, envelopes %d", tc.name, len(j.all()), len(hub.Envelopes()))
		}
	}
	// A missing identity fails the online check itself.
	hub.SetCircleWallet(without("identity"))
	if _, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, &journal{}); !errors.Is(err, nipcash.ErrHubIdentityMismatch) || !errors.Is(err, ErrJoinNotSent) {
		t.Errorf("missing identity: %v", err)
	}
	if _, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, nil); !errors.Is(err, ErrNoJoinJournal) {
		t.Errorf("no journal: %v", err)
	}
	hub.SetCircleWallet(base())
	if _, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, &journal{fail: errors.New("disk full")}); !errors.Is(err, ErrJoinNotSent) {
		t.Errorf("failed write-ahead: %v", err)
	}
	if warned != 1 || len(hub.Envelopes()) != 0 {
		t.Fatalf("warned %d, envelopes %d", warned, len(hub.Envelopes()))
	}
	// fees_ppm 0 present passes; a warned and accepted join goes out.
	hub.SetCircleWallet(without("rotation_delay_secs"))
	if _, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{WarnNoRotation: yes}, &journal{}); err != nil {
		t.Fatalf("warned join: %v", err)
	}
	if warned != 2 {
		t.Fatalf("WarnNoRotation called %d times", warned)
	}
}

// T12-10, E-JOIN-11: without a verified announcement there is no join and no
// prompt, and nothing goes over the standard transport.
func TestJoin_NoAnnouncement(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	hub := newCircle(t)
	memberPriv, memberPub := keypair(t)
	hub.admit(memberPub)
	block := cashtest.DefaultCircleWallet(hub.NodeXOnly())
	delete(block, "rotation_delay_secs")
	hub.SetCircleWallet(block)
	// A newer kind-11190 under the node's key with a broken signature replaces the
	// real one: nothing verifies.
	fake := *hub.Announcement()
	fake.CreatedAt++
	fake.Sig = strings.Repeat("00", 64)
	for _, r := range hub.Relays {
		r.Publish(&fake)
	}
	cl := connect(t, ctx, hub)
	asked := false
	j := &journal{}
	_, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{WarnNoRotation: func(context.Context) bool { asked = true; return true }}, j)
	if !errors.Is(err, ErrNoAnnouncement) || !errors.Is(err, ErrJoinNotSent) {
		t.Fatalf("err = %v, want ErrNoAnnouncement", err)
	}
	if asked || len(j.all()) != 0 || len(hub.Envelopes()) != 0 {
		t.Fatalf("asked %v, journal %d, envelopes %d", asked, len(j.all()), len(hub.Envelopes()))
	}
	for _, r := range hub.Relays {
		for _, ev := range r.Accepted() {
			if ev.Kind == 23194 && strings.Contains(string(mustJSON(t, ev)), nipcw.MethodCreateCircleWallet) {
				t.Fatal("a join went over the standard transport")
			}
		}
	}
}

func mustJSON(t *testing.T, ev *nip01.Event) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// T12-06 (S-CW-11, 13, 14, 23, 36, 38, 116, 121) and T12-21's stale terms: what a
// sent join's answer means.
func TestJoin_Answers(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	hub := newCircle(t)
	memberPriv, memberPub := keypair(t)
	hub.admit(memberPub)
	cl := connect(t, ctx, hub)
	code := func(c string) func(nipcw.CreateCircleWalletRequest) *transport.Result {
		return func(nipcw.CreateCircleWalletRequest) *transport.Result {
			return &transport.Result{Error: &transport.ResultError{Code: c, Message: c}}
		}
	}
	for _, c := range []string{nipcw.ErrBadRequest, nipcw.ErrUnauthorized, nipcw.ErrNotReady, nipcw.ErrRateLimited, nipcw.ErrLimitExceeded,
		nipcw.ErrInsufficientCapacity, nipcw.ErrRestricted, nipcw.ErrWalletExists, nipcw.ErrNotImplemented} {
		hub.setJoinAnswer(code(c))
		_, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, &journal{})
		var we *relayclient.WalletError
		var ie *JoinIndeterminateError
		if !errors.As(err, &we) || we.Code != c || errors.As(err, &ie) || errors.Is(err, ErrJoinNotSent) {
			t.Errorf("%s: %v, want a final WalletError", c, err)
		}
	}
	indeterminate := map[string]func(nipcw.CreateCircleWalletRequest) *transport.Result{
		"REQUEST_REUSED": code(nipcw.ErrRequestReused),
		"omission":       func(nipcw.CreateCircleWalletRequest) *transport.Result { return nil },
		"old reply": func(req nipcw.CreateCircleWalletRequest) *transport.Result {
			_, otherConn := keypair(t)
			return &transport.Result{Result: json.RawMessage(hub.details(req.Pubkey, otherConn, 1, 1, "never"))}
		},
	}
	for name, a := range indeterminate {
		hub.setJoinAnswer(a)
		j := &journal{}
		_, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, j)
		var ie *JoinIndeterminateError
		if !errors.As(err, &ie) || ie.Pending != j.all()[0] {
			t.Errorf("%s: %v, want a JoinIndeterminateError carrying the journalled join", name, err)
		}
		if name == "REQUEST_REUSED" && ie != nil && ie.Code != nipcw.ErrRequestReused {
			t.Errorf("code %q", ie.Code)
		}
	}
	// A refusal after stale terms: the next Join re-reads get_info and signs a new
	// proof, never resending the refused one.
	hub.setJoinAnswer(nil)
	before := len(hub.Committed())
	hub.SetCircleWallet(cashtest.DefaultCircleWallet(hub.NodeXOnly()))
	if _, err := cl.Join(ctx, params(t, memberPriv), JoinOptions{}, &journal{}); err != nil {
		t.Fatalf("join after refusals: %v", err)
	}
	proofs := map[string]bool{}
	for _, ic := range hub.Committed()[:before+1] {
		var req nipcw.CreateCircleWalletRequest
		_ = json.Unmarshal(ic.Item.Params, &req)
		if proofs[req.IdentityEvent] {
			t.Fatal("a proof was sent twice")
		}
		proofs[req.IdentityEvent] = true
	}
}
