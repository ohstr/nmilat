package conformance

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// The join kit (NIP-CW §Private Join, §Lost Join Reply): joins and join
// lookups sent to the Hub's Circle Wallet Hub connection over the private
// transport, hand-built so a case can send what the SDK refuses.

// circleConn is the Hub's Circle Wallet Hub connection; the case skips when the
// Hub has none.
func (s *suite) circleConn(t *testing.T) nipcw.CircleHubConnection {
	t.Helper()
	raw := s.h.CircleHubConnection()
	if raw == "" {
		t.Skip("the Hub has no Circle Wallet Hub connection")
	}
	c, err := nipcw.DecodeCircleHubConnection(raw)
	if err != nil {
		t.Fatalf("the Hub's circlehub1 string does not decode: %v", err)
	}
	return c
}

// nwcTo opens an NWC connection to wallet with secret.
func nwcTo(t *testing.T, wallet, secret string, relays []string) *relayclient.NWCClient {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	nwc, err := relayclient.NewNWCClient(ctx, &nip47.PairingInfo{WalletPubkey: wallet, RelayURLs: relays, Secret: secret},
		nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("open the connection to %s: %v", wallet, err)
	}
	t.Cleanup(nwc.Close)
	return nwc
}

// circleInfo is get_info on the Circle Wallet Hub connection.
func (s *suite) circleInfo(t *testing.T, c nipcw.CircleHubConnection) *nip47.GetInfoResult {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	gi, err := nwcTo(t, c.Pubkey, c.Secret, c.Relays).GetInfo(ctx)
	if err != nil {
		t.Fatalf("get_info on the Circle Wallet Hub connection: %v", err)
	}
	if gi.CircleWallet == nil {
		t.Fatalf("the Circle Wallet Hub connection's get_info has no circle_wallet block")
	}
	return gi
}

// member is a fresh key the Hub admits to its circle.
func (s *suite) member(t *testing.T) (priv, pub string) {
	t.Helper()
	priv, pub = keypair(t)
	s.h.AddMember(t, pub, true)
	return priv, pub
}

// prepared is one signed join and the connection key it names.
type prepared struct {
	*nipcw.PreparedJoin
	key  nipcw.ConnectionKey
	priv string
}

// prepareJoin signs a join by priv for the Hub c at now: max_amount 100000,
// max_receive 200000, monthly, a fresh connection key unless key is set.
func prepareJoin(t *testing.T, c nipcw.CircleHubConnection, priv string, key *nipcw.ConnectionKey, mut func(*nipcw.CreateCircleWalletParams)) prepared {
	t.Helper()
	p := nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(priv), MaxAmountMillis: 100000, MaxReceiveMillis: 200000,
		BudgetRenewal: nipcw.RenewalMonthly}
	if key != nil {
		p.Connection = *key
	} else {
		k, err := nipcw.NewConnectionKey()
		if err != nil {
			t.Fatal(err)
		}
		p.Connection = k
	}
	if mut != nil {
		mut(&p)
	}
	j, err := p.Prepare(c.Pubkey, time.Now())
	if err != nil {
		t.Fatalf("prepare a join: %v", err)
	}
	return prepared{PreparedJoin: j, key: p.Connection, priv: priv}
}

// params is the join's request as a map a case can spoil.
func (j prepared) params(t *testing.T) map[string]any {
	t.Helper()
	raw, err := json.Marshal(j.Request)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// circleItem is one item on the circle: target the Hub connection, bill proof
// by secret, item proof by signer ("" for none).
func (s *suite) circleItem(t *testing.T, c nipcw.CircleHubConnection, secret, id, method string, params any, signer, nonce string, notAfter int64) transport.Item {
	t.Helper()
	cred := nipcash.BySecret(mustKey(t))
	if signer != "" {
		cred = nipcash.BySigning(signer)
	}
	it, err := nipcash.BuildItem(id, c.Pubkey, secret, method, params, cred,
		nipcash.ItemBinding{HubXOnly: s.nodeXOnly, Nonce: nonce, NotAfter: notAfter})
	if err != nil {
		t.Fatal(err)
	}
	return it
}

// itemBuilder builds one item of an envelope.
type itemBuilder func(nonce string, notAfter int64) transport.Item

// sendLater publishes one envelope of items and returns a wait for the
// results by item id: nil when no reply came.
func (s *suite) sendLater(t *testing.T, builders ...itemBuilder) func() map[string]map[string]json.RawMessage {
	t.Helper()
	e, nonce, replyTo, notAfter := s.newEnvelope(t)
	items := make([]transport.Item, len(builders))
	for i, b := range builders {
		items[i] = b(nonce, notAfter)
	}
	e["items"] = items
	l := s.listen(t, replyTo)
	r := s.wrap(t, e, "")
	s.publish(t, 0, r.ev)
	return func() map[string]map[string]json.RawMessage {
		got := l.wait(1, s.quiet())
		if len(got) == 0 {
			return nil
		}
		var results []map[string]json.RawMessage
		if err := json.Unmarshal(r.open(t, got[0].ev)["results"], &results); err != nil {
			t.Fatalf("results: %v", err)
		}
		out := map[string]map[string]json.RawMessage{}
		for _, res := range results {
			var id string
			_ = json.Unmarshal(res["id"], &id)
			out[id] = res
		}
		return out
	}
}

// sendItems sends one envelope and waits for its results.
func (s *suite) sendItems(t *testing.T, builders ...itemBuilder) map[string]map[string]json.RawMessage {
	t.Helper()
	got := s.sendLater(t, builders...)()
	if got == nil {
		t.Fatalf("no reply to the envelope")
	}
	return got
}

// joinWith sends one join: params signed (item proof) by signer, bill proof by
// secret. It returns the item's result, nil when omitted.
func (s *suite) joinWith(t *testing.T, c nipcw.CircleHubConnection, secret string, params any, signer string) map[string]json.RawMessage {
	t.Helper()
	return s.sendItems(t, func(nonce string, notAfter int64) transport.Item {
		return s.circleItem(t, c, secret, "1", nipcw.MethodCreateCircleWallet, params, signer, nonce, notAfter)
	})["1"]
}

// join sends j as prepared, signed by its member.
func (s *suite) join(t *testing.T, c nipcw.CircleHubConnection, j prepared) map[string]json.RawMessage {
	t.Helper()
	return s.joinWith(t, c, c.Secret, j.params(t), j.priv)
}

// joinOK joins and checks the reply as a client must.
func (s *suite) joinOK(t *testing.T, c nipcw.CircleHubConnection, j prepared) *nipcw.CreateCircleWalletResponse {
	t.Helper()
	res := s.join(t, c, j)
	if res == nil || res["result"] == nil {
		t.Fatalf("join refused or omitted: %s", res["error"])
	}
	d, err := j.ParseResult(res["result"])
	if err != nil {
		t.Fatalf("the join's reply fails its checks: %v", err)
	}
	return d
}

// joinLookup sends one join lookup: item proof by signer, bill proof by secret.
func (s *suite) joinLookup(t *testing.T, c nipcw.CircleHubConnection, secret, signer, connPub string, deadline int64) map[string]json.RawMessage {
	t.Helper()
	params := nipcash.CashLookupRequest{ConnectionPubkey: connPub, Deadline: deadline}
	return s.sendItems(t, func(nonce string, notAfter int64) transport.Item {
		return s.circleItem(t, c, secret, "1", nipcash.MethodCashLookup, params, signer, nonce, notAfter)
	})["1"]
}

// lookupStatus reads a lookup's answer.
func lookupStatus(t *testing.T, res map[string]json.RawMessage) *nipcash.CashLookupResult {
	t.Helper()
	if res == nil {
		t.Fatalf("the lookup was omitted")
	}
	if res["error"] != nil {
		t.Fatalf("the lookup was refused: %s", res["error"])
	}
	lr, err := nipcash.ParseCashLookupResult(res["result"])
	if err != nil {
		t.Fatalf("lookup answer %s: %v", res["result"], err)
	}
	return lr
}

func joinWant(t *testing.T, what string, res map[string]json.RawMessage, code string) {
	t.Helper()
	if res == nil {
		t.Errorf("%s: omitted, want %s", what, code)
		return
	}
	if got := resultCode(res); got != code {
		t.Errorf("%s: %q (%s), want %s", what, got, res["error"], code)
	}
}

// joinCases are the Circle Wallet join and join lookup cases (NIP-CW).
var joinCases = []ctCase{
	{id: "CT-JOIN-01", run: ctJoin01},
	{id: "CT-JOIN-02", run: ctJoin02},
	{id: "CT-JOIN-03", run: ctJoin03},
	{id: "CT-JOIN-04", run: ctJoin04},
	{id: "CT-JOIN-05", run: ctJoin05},
	{id: "CT-JOIN-06", run: ctJoin06},
	{id: "CT-JOIN-07", run: ctJoin07},
	{id: "CT-JOIN-08", needs: []need{needCircleFunds}, run: ctJoin08},
	{id: "CT-JOIN-09", run: ctJoin09},
	{id: "CT-JOIN-10", needs: []need{needFaulty, needClock}, run: ctJoin10},
	{id: "CT-JOIN-11", run: ctJoin11},
	{id: "CT-JOIN-12", run: ctJoin12},
	{id: "CT-JOIN-13", run: ctJoin13},
	{id: "CT-JOIN-14", run: ctJoin14},
	{id: "CT-JOIN-15", run: ctJoin15},
	{id: "CT-JOIN-16", run: ctJoin16},
	{id: "CT-JOIN-17", needs: []need{needAdmin}, run: ctJoin17},
	{id: "CT-JOIN-18", needs: []need{needAdmin}, run: ctJoin18},
	{id: "CT-JLK-01", needs: []need{needClock}, run: ctJlk01},
	{id: "CT-JLK-02", run: ctJlk02},
	{id: "CT-JLK-03", run: ctJlk03},
	{id: "CT-JLK-04", needs: []need{needClock}, run: ctJlk04},
	{id: "CT-JLK-05", needs: []need{needAdmin, needClock}, run: ctJlk05},
	{id: "CT-JLK-06", run: ctJlk06},
}

// CT-JOIN-01 (S-CW-01..03): a malformed pubkey, connection_pubkey or typed
// param is BAD_REQUEST and consumes nothing: the same proof joins afterwards.
func ctJoin01(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, pub := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	for name, mut := range map[string]func(map[string]any){
		"uppercase pubkey":             func(m map[string]any) { m["pubkey"] = strings.ToUpper(pub) },
		"no connection_pubkey":         func(m map[string]any) { delete(m, "connection_pubkey") },
		"connection_pubkey = pubkey":   func(m map[string]any) { m["connection_pubkey"] = pub },
		"connection_pubkey not a key":  func(m map[string]any) { m["connection_pubkey"] = strings.Repeat("ff", 32) },
		"max_amount a string":          func(m map[string]any) { m["max_amount"] = "100000" },
		"negative expiry":              func(m map[string]any) { m["expiry"] = -1 },
		"fractional max_receive":       func(m map[string]any) { m["max_receive"] = 200000.5 },
		"unknown budget_renewal":       func(m map[string]any) { m["budget_renewal"] = "fortnightly" },
		"identity_event not an object": func(m map[string]any) { m["identity_event"] = "[]" },
	} {
		m := j.params(t)
		mut(m)
		joinWant(t, name, s.joinWith(t, c, c.Secret, m, priv), nipcw.ErrBadRequest)
	}
	if res := s.join(t, c, j); res == nil || res["result"] == nil {
		t.Errorf("the proof refused at step 1 does not join afterwards: %s", res["error"])
	}
}

// CT-JOIN-02 (S-CW-06): proof failures are UNAUTHORIZED, with the same code and
// message for a member and a non-member.
func ctJoin02(t *testing.T, s *suite) {
	c := s.circleConn(t)
	_, otherHub := keypair(t)
	memberPriv, _ := s.member(t)
	strangerPriv, _ := keypair(t)
	spoil := map[string]func(t *testing.T, priv string) (any, string){
		"stale created_at": func(t *testing.T, priv string) (any, string) {
			j := prepareJoin(t, c, priv, nil, nil)
			old, err := nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(priv), Connection: j.key,
				MaxAmountMillis: 100000, MaxReceiveMillis: 200000, BudgetRenewal: nipcw.RenewalMonthly}.Prepare(c.Pubkey, time.Now().Add(-400*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			return prepared{PreparedJoin: old, key: j.key, priv: priv}.params(t), priv
		},
		"another Hub's d": func(t *testing.T, priv string) (any, string) {
			j := prepareJoin(t, nipcw.CircleHubConnection{Pubkey: otherHub}, priv, nil, nil)
			return j.params(t), priv
		},
		"terms not as signed": func(t *testing.T, priv string) (any, string) {
			m := prepareJoin(t, c, priv, nil, nil).params(t)
			m["max_amount"] = 90000
			return m, priv
		},
		"connection not as signed": func(t *testing.T, priv string) (any, string) {
			m := prepareJoin(t, c, priv, nil, nil).params(t)
			k, _ := nipcw.NewConnectionKey()
			m["connection_pubkey"] = k.Pubkey()
			return m, priv
		},
		"broken signature": func(t *testing.T, priv string) (any, string) {
			m := prepareJoin(t, c, priv, nil, nil).params(t)
			var ev map[string]any
			_ = json.Unmarshal([]byte(m["identity_event"].(string)), &ev)
			sig := []byte(ev["sig"].(string))
			if sig[10] == '0' {
				sig[10] = '1'
			} else {
				sig[10] = '0'
			}
			ev["sig"] = string(sig)
			raw, _ := json.Marshal(ev)
			m["identity_event"] = string(raw)
			return m, priv
		},
	}
	for name, f := range spoil {
		pm, signer := f(t, memberPriv)
		resM := s.joinWith(t, c, c.Secret, pm, signer)
		ps, signerS := f(t, strangerPriv)
		resS := s.joinWith(t, c, c.Secret, ps, signerS)
		joinWant(t, name+" (member)", resM, nipcw.ErrUnauthorized)
		joinWant(t, name+" (non-member)", resS, nipcw.ErrUnauthorized)
		if resM != nil && resS != nil && digitless(resM["error"]) != digitless(resS["error"]) {
			t.Errorf("%s: a member gets %s, a non-member %s: membership leaks", name, resM["error"], resS["error"])
		}
	}
}

// digitless is s without its digits, so two refusals naming different times
// compare equal.
func digitless(s json.RawMessage) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return -1
		}
		return r
	}, string(s))
}

// CT-JOIN-03 (S-CW-11, 12): a replayed proof is REQUEST_REUSED, and one refused
// at step 3 or later stays spent.
func ctJoin03(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, pub := keypair(t)
	j := prepareJoin(t, c, priv, nil, nil)
	joinWant(t, "a non-member", s.join(t, c, j), nipcw.ErrRestricted)
	s.h.AddMember(t, pub, true)
	joinWant(t, "the same proof once a member", s.join(t, c, j), nipcw.ErrRequestReused)
	k := prepareJoin(t, c, priv, nil, nil)
	s.joinOK(t, c, k)
	joinWant(t, "a replay of a join that made a wallet", s.join(t, c, k), nipcw.ErrRequestReused)
}

// CT-JOIN-04 (S-CW-26..28): a request over a ceiling or tighter than the floor
// is LIMIT_EXCEEDED naming the field; an omitted expiry takes the Hub's
// default, never more than its ceiling.
func ctJoin04(t *testing.T, s *suite) {
	c := s.circleConn(t)
	cw := s.circleInfo(t, c).CircleWallet
	priv, _ := s.member(t)
	over := map[string]func(*nipcw.CreateCircleWalletParams){}
	if cw.PerWalletMaxMillis > 0 {
		over["max_amount"] = func(p *nipcw.CreateCircleWalletParams) { p.MaxAmountMillis = uint64(cw.PerWalletMaxMillis) + 1 }
	}
	if cw.PerWalletMaxReceiveMillis > 0 {
		over["max_receive"] = func(p *nipcw.CreateCircleWalletParams) { p.MaxReceiveMillis = uint64(cw.PerWalletMaxReceiveMillis) + 1 }
	}
	if cw.MinBudgetRenewal != "" && cw.MinBudgetRenewal != nipcw.RenewalDaily {
		over["budget_renewal"] = func(p *nipcw.CreateCircleWalletParams) { p.BudgetRenewal = nipcw.RenewalDaily }
	}
	if cw.MaxExpSecs > 0 {
		over["expiry"] = func(p *nipcw.CreateCircleWalletParams) { p.Expiry = time.Duration(cw.MaxExpSecs+1) * time.Second }
	}
	if len(over) == 0 {
		t.Log("get_info reports no per-wallet ceiling, renewal floor or expiry ceiling to exceed")
	}
	for field, mut := range over {
		res := s.join(t, c, prepareJoin(t, c, priv, nil, mut))
		joinWant(t, field, res, nipcw.ErrLimitExceeded)
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(res["error"], &e)
		if !strings.Contains(e.Message, field) {
			t.Errorf("%s: message %q does not name the field", field, e.Message)
		}
	}
	before := time.Now().Unix()
	d := s.joinOK(t, c, prepareJoin(t, c, priv, nil, nil))
	if cw.MaxExpSecs > 0 && (d.ExpiresAt == 0 || d.ExpiresAt > time.Now().Unix()+int64(cw.MaxExpSecs)+5 || d.ExpiresAt < before) {
		t.Errorf("an omitted expiry resolved to expires_at %d; the default must lie within the ceiling %d", d.ExpiresAt, cw.MaxExpSecs)
	}
}

// CT-JOIN-05 (S-CW-30, 31): one wallet per member; two joins of one member in
// one envelope make one wallet.
func ctJoin05(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, _ := s.member(t)
	s.joinOK(t, c, prepareJoin(t, c, priv, nil, nil))
	joinWant(t, "a second join", s.join(t, c, prepareJoin(t, c, priv, nil, nil)), nipcw.ErrWalletExists)

	priv2, _ := s.member(t)
	a, b := prepareJoin(t, c, priv2, nil, nil), prepareJoin(t, c, priv2, nil, nil)
	got := s.sendItems(t, func(n string, na int64) transport.Item {
		return s.circleItem(t, c, c.Secret, "a", nipcw.MethodCreateCircleWallet, a.params(t), priv2, n, na)
	}, func(n string, na int64) transport.Item {
		return s.circleItem(t, c, c.Secret, "b", nipcw.MethodCreateCircleWallet, b.params(t), priv2, n, na)
	})
	made := 0
	for id, res := range got {
		switch code := resultCode(res); {
		case res["result"] != nil:
			made++
		case code != nipcw.ErrWalletExists && code != nipcw.ErrRateLimited:
			t.Errorf("join %s: %q, want WALLET_EXISTS or RATE_LIMITED for the loser", id, code)
		}
	}
	if made != 1 || len(got) != 2 {
		t.Errorf("%d wallets from two concurrent joins (%d answers), want exactly one", made, len(got))
	}
}

// CT-JOIN-06 (S-CW-32): joins past the Hub's rate are RATE_LIMITED, and joins
// refused before the rate step spend no quota.
func ctJoin06(t *testing.T, s *suite) {
	c := s.circleConn(t)
	holderPriv, _ := s.member(t)
	held := prepareJoin(t, c, holderPriv, nil, nil)
	s.joinOK(t, c, held)
	// A key in use is refused at step 9, after the rate step.
	untilLimited := func(priv string) int {
		for n := 1; n <= 10; n++ {
			// Terms vary so each proof is a new event.
			res := s.join(t, c, prepareJoin(t, c, priv, &held.key, func(p *nipcw.CreateCircleWalletParams) { p.MaxAmountMillis -= uint64(n) }))
			switch code := resultCode(res); code {
			case nipcw.ErrRateLimited:
				return n
			case nipcw.ErrRestricted:
			default:
				t.Fatalf("a join naming a key in use: %q, want RESTRICTED", code)
			}
		}
		return 0
	}
	plain, _ := s.member(t)
	r := untilLimited(plain)
	if r == 0 {
		t.Skip("no RATE_LIMITED within 10 joins: the rate limit is a SHOULD")
	}
	early, _ := s.member(t)
	for range 5 {
		m := prepareJoin(t, c, early, nil, nil).withParam(t, "budget_renewal", "fortnightly")
		joinWant(t, "a malformed join", s.joinWith(t, c, c.Secret, m, early), nipcw.ErrBadRequest)
	}
	if r2 := untilLimited(early); r2 != r {
		t.Errorf("RATE_LIMITED at join %d after five refused at step 1, at %d without: refused joins spent quota", r2, r)
	}
}

// withParam is j's params with key set to v (a spoiled copy).
func (j prepared) withParam(t *testing.T, key string, v any) map[string]any {
	t.Helper()
	m := j.params(t)
	m[key] = v
	return m
}

// CT-JOIN-07 (S-CW-33): a connection_pubkey in use is RESTRICTED and rolls the
// whole join back: the member joins afterwards with a fresh key.
func ctJoin07(t *testing.T, s *suite) {
	c := s.circleConn(t)
	aPriv, _ := s.member(t)
	a := prepareJoin(t, c, aPriv, nil, nil)
	s.joinOK(t, c, a)
	bPriv, _ := s.member(t)
	joinWant(t, "a key in use", s.join(t, c, prepareJoin(t, c, bPriv, &a.key, nil)), nipcw.ErrRestricted)
	s.joinOK(t, c, prepareJoin(t, c, bPriv, nil, nil))
}

// CT-JOIN-08 (S-CW-34): a circle at its holdings ceiling refuses a join
// INSUFFICIENT_CAPACITY. It leaves the circle full.
func ctJoin08(t *testing.T, s *suite) {
	c := s.circleConn(t)
	f := s.h.(CircleFunder)
	aPriv, _ := s.member(t)
	d := s.joinOK(t, c, prepareJoin(t, c, aPriv, nil, nil))
	for range 50 {
		avail := s.circleInfo(t, c).CircleWallet.AvailableMillis
		if avail <= 0 {
			break
		}
		f.FundCircleWallet(t, d.WalletPubkey, uint64(avail))
	}
	if s.circleInfo(t, c).CircleWallet.AvailableMillis > 0 {
		t.Skip("the circle did not fill")
	}
	bPriv, _ := s.member(t)
	joinWant(t, "a join to a full circle", s.join(t, c, prepareJoin(t, c, bPriv, nil, nil)), nipcw.ErrInsufficientCapacity)
}

// CT-JOIN-09 (S-CW-41): a non-member with a valid proof is RESTRICTED, and the
// proof is consumed.
func ctJoin09(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, _ := keypair(t)
	j := prepareJoin(t, c, priv, nil, nil)
	joinWant(t, "a non-member", s.join(t, c, j), nipcw.ErrRestricted)
	joinWant(t, "the same proof again", s.join(t, c, j), nipcw.ErrRequestReused)
}

// CT-JOIN-10 (S-CW-23): a join whose commit comes after its proof's freshness
// window is BAD_REQUEST, and nothing was made.
func ctJoin10(t *testing.T, s *suite) {
	c := s.circleConn(t)
	f := s.h.(Faulty)
	priv, _ := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	f.InjectFault(t, FaultStallCommit)
	t.Cleanup(func() { f.InjectFault(t, FaultNone) })
	wait := s.sendLater(t, func(n string, na int64) transport.Item {
		return s.circleItem(t, c, c.Secret, "1", nipcw.MethodCreateCircleWallet, j.params(t), priv, n, na)
	})
	time.Sleep(200 * time.Millisecond)
	s.advance(t, (nipcw.JoinFreshness+60)*time.Second)
	f.InjectFault(t, FaultNone)
	got := wait()
	if got == nil {
		t.Fatalf("no reply once the commit resumed")
	}
	joinWant(t, "a join committing past its proof's window", got["1"], nipcw.ErrBadRequest)
	if st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, j.ConnectionPubkey, j.Deadline)); st.Status == nipcash.LookupDone {
		t.Errorf("the join refused at commit was made: lookup done")
	}
}

// CT-JOIN-11 (S-CW-123): five joins in one envelope are evaluated one by one.
func ctJoin11(t *testing.T, s *suite) {
	c := s.circleConn(t)
	m1, _ := s.member(t)
	m5, _ := s.member(t)
	stranger, _ := keypair(t)
	forger, _ := keypair(t)
	m3, _ := s.member(t)
	m4, _ := s.member(t)
	joins := map[string]struct {
		params any
		signer string
		want   string // "" for a wallet
	}{
		"1": {prepareJoin(t, c, m1, nil, nil).params(t), m1, ""},
		"2": {prepareJoin(t, c, stranger, nil, nil).params(t), stranger, nipcw.ErrRestricted},
		"3": {prepareJoin(t, c, m3, nil, nil).params(t), forger, nipcw.ErrUnauthorized},
		"4": {prepareJoin(t, c, m4, nil, nil).withParam(t, "budget_renewal", "fortnightly"), m4, nipcw.ErrBadRequest},
		"5": {prepareJoin(t, c, m5, nil, nil).params(t), m5, ""},
	}
	var builders []itemBuilder
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		j := joins[id]
		builders = append(builders, func(n string, na int64) transport.Item {
			return s.circleItem(t, c, c.Secret, id, nipcw.MethodCreateCircleWallet, j.params, j.signer, n, na)
		})
	}
	got := s.sendItems(t, builders...)
	for id, j := range joins {
		res := got[id]
		if j.want == "" {
			if res == nil || res["result"] == nil {
				t.Errorf("join %s: %s, want a wallet", id, res["error"])
			}
			continue
		}
		joinWant(t, "join "+id, res, j.want)
	}
}

// CT-JOIN-12 (S-CW-121, 122): refusals are answered with codes; a join whose
// bill proof verifies but whose item proof is another key's, covers other
// params, or is missing is UNAUTHORIZED; one whose bill proof fails is omitted.
func ctJoin12(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, _ := s.member(t)
	other, _ := keypair(t)
	joinWant(t, "an item proof by another key", s.joinWith(t, c, c.Secret, prepareJoin(t, c, priv, nil, nil).params(t), other), nipcw.ErrUnauthorized)
	joinWant(t, "no item proof", s.joinWith(t, c, c.Secret, prepareJoin(t, c, priv, nil, nil).params(t), ""), nipcw.ErrUnauthorized)
	changed := s.sendItems(t, func(n string, na int64) transport.Item {
		j := prepareJoin(t, c, priv, nil, nil)
		it := s.circleItem(t, c, c.Secret, "1", nipcw.MethodCreateCircleWallet, j.params(t), priv, n, na)
		k := prepareJoin(t, c, priv, nil, nil)
		it.Params, _ = json.Marshal(k.Request)
		// The bill proof is rebuilt over the new params, so only the item proof
		// is stale.
		hash, _ := transport.CanonicalParamsHash(it.Params)
		it.BillProof, _ = transport.BuildBillProof(c.Secret, transport.ProofBinding{Target: c.Pubkey, HubXOnly: s.nodeXOnly,
			Method: it.Method, ParamsHash: hash, Nonce: n, NotAfter: na})
		return it
	})["1"]
	joinWant(t, "params changed after the item proof", changed, nipcw.ErrUnauthorized)
	if res := s.joinWith(t, c, mustKey(t), prepareJoin(t, c, priv, nil, nil).params(t), priv); res != nil {
		t.Errorf("a join whose bill proof fails was answered %s %s, want it omitted", res["result"], res["error"])
	}
}

// CT-JOIN-13 (CW-PJ-03): a join on the standard transport is NOT_IMPLEMENTED,
// and create_circle_wallet is listed only in private_methods.
func ctJoin13(t *testing.T, s *suite) {
	c := s.circleConn(t)
	gi := s.circleInfo(t, c)
	if slices.Contains(gi.Methods, nipcw.MethodCreateCircleWallet) || !slices.Contains(gi.PrivateMethods, nipcw.MethodCreateCircleWallet) ||
		!slices.Contains(gi.PrivateMethods, nipcash.MethodCashLookup) {
		t.Errorf("methods %v, private_methods %v: create_circle_wallet and cash_lookup belong in private_methods only", gi.Methods, gi.PrivateMethods)
	}
	priv, _ := s.member(t)
	ctx, cancel := ctx15()
	defer cancel()
	resp, err := nwcTo(t, c.Pubkey, c.Secret, c.Relays).Call(ctx, nipcw.MethodCreateCircleWallet, prepareJoin(t, c, priv, nil, nil).Request)
	if err != nil || resp.Error == nil || resp.Error.Code != nipcw.ErrNotImplemented {
		t.Errorf("a join on the standard transport: %+v %v, want NOT_IMPLEMENTED", resp, err)
	}
}

// CT-JOIN-14 (S-CW-37): the result is exactly {"encrypted_details"}; inside are
// every term and no secret.
func ctJoin14(t *testing.T, s *suite) {
	c := s.circleConn(t)
	cw := s.circleInfo(t, c).CircleWallet
	priv, _ := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	res := s.join(t, c, j)
	if res == nil || res["result"] == nil {
		t.Fatalf("join refused: %s", res["error"])
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(res["result"], &fields); err != nil || len(fields) != 1 || fields["encrypted_details"] == nil {
		t.Errorf("result %s, want exactly encrypted_details", res["result"])
	}
	d, err := j.ParseResult(res["result"])
	if err != nil {
		t.Fatalf("details: %v", err)
	}
	if len(d.MissingTerms) > 0 || len(d.LeakedFields) > 0 || d.CapsRaised || len(d.Relays) == 0 {
		t.Errorf("details missing %v, leaking %v, caps raised %v, relays %v", d.MissingTerms, d.LeakedFields, d.CapsRaised, d.Relays)
	}
	if (cw.RotationDelaySecs == nil) != (d.RotationDelaySecs == nil) {
		t.Errorf("rotation_delay_secs in get_info %v, in the details %v: present in both or neither", cw.RotationDelaySecs, d.RotationDelaySecs)
	}
}

// CT-JOIN-15 (S-CW-97, 98): delete_circle_wallet at the dust threshold is {},
// above it RESTRICTED (with CircleFunder); over the Hub connection refused.
func ctJoin15(t *testing.T, s *suite) {
	c := s.circleConn(t)
	f, funds := s.h.(CircleFunder)
	del := func(d *nipcw.CreateCircleWalletResponse, j prepared) *nip47.ResponseEvent {
		ctx, cancel := ctx15()
		defer cancel()
		resp, err := nwcTo(t, d.WalletPubkey, j.key.Secret(), d.Relays).Call(ctx, nipcw.MethodDeleteCircleWallet, struct{}{})
		if err != nil {
			t.Fatalf("delete_circle_wallet: %v", err)
		}
		return resp
	}
	aPriv, _ := s.member(t)
	a := prepareJoin(t, c, aPriv, nil, nil)
	da := s.joinOK(t, c, a)
	if funds {
		bPriv, _ := s.member(t)
		b := prepareJoin(t, c, bPriv, nil, nil)
		db := s.joinOK(t, c, b)
		f.FundCircleWallet(t, db.WalletPubkey, db.DustThresholdMillis+1)
		if resp := del(db, b); resp.Error == nil || resp.Error.Code != nipcw.ErrRestricted {
			t.Errorf("delete above dust: %+v, want RESTRICTED", resp.Response)
		}
		f.FundCircleWallet(t, da.WalletPubkey, da.DustThresholdMillis)
	} else {
		t.Log("without CircleFunder only an empty wallet's delete is checked")
	}
	if resp := del(da, a); resp.Error != nil {
		t.Errorf("delete at or below dust: %+v, want {}", resp.Error)
	}
	ctx, cancel := ctx15()
	defer cancel()
	resp, err := nwcTo(t, c.Pubkey, c.Secret, c.Relays).Call(ctx, nipcw.MethodDeleteCircleWallet, struct{}{})
	if err != nil || resp.Error == nil {
		t.Errorf("delete_circle_wallet over the Hub connection: %+v %v, want refused", resp, err)
	}
}

// CT-JOIN-16 (S-CW-18): a client that understates the deadline and joins again
// still gets at most one wallet.
func ctJoin16(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, _ := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	if res := s.join(t, c, j); res == nil || res["result"] == nil {
		t.Fatalf("join: %s", res["error"])
	}
	// The reply is "lost"; the lookup understates the deadline.
	lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, j.ConnectionPubkey, time.Now().Unix()-400))
	joinWant(t, "a rejoin", s.join(t, c, prepareJoin(t, c, priv, nil, nil)), nipcw.ErrWalletExists)
}

// CT-JOIN-17 (CW-ACC-01): with accepting false every join is RESTRICTED, and
// join lookups and members' wallets are still served; nothing was consumed, so
// the refused proof joins once the circle reopens.
func ctJoin17(t *testing.T, s *suite) {
	c := s.circleConn(t)
	admin := s.h.(Admin)
	aPriv, _ := s.member(t)
	a := prepareJoin(t, c, aPriv, nil, nil)
	da := s.joinOK(t, c, a)
	admin.SetAccepting(t, false)
	t.Cleanup(func() { admin.SetAccepting(t, true) })
	if acc := s.circleInfo(t, c).CircleWallet.Accepting; acc == nil || *acc {
		t.Errorf("get_info accepting %v, want false", acc)
	}
	bPriv, _ := s.member(t)
	b := prepareJoin(t, c, bPriv, nil, nil)
	joinWant(t, "a join to a closed circle", s.join(t, c, b), nipcw.ErrRestricted)
	if st := lookupStatus(t, s.joinLookup(t, c, c.Secret, aPriv, a.ConnectionPubkey, a.Deadline)); st.Status != nipcash.LookupDone {
		t.Errorf("a join lookup while closed: %s, want done", st.Status)
	}
	ctx, cancel := ctx15()
	defer cancel()
	if _, err := nwcTo(t, da.WalletPubkey, a.key.Secret(), da.Relays).GetInfo(ctx); err != nil {
		t.Errorf("a member's wallet while closed: %v", err)
	}
	admin.SetAccepting(t, true)
	if res := s.join(t, c, b); res == nil || res["result"] == nil {
		t.Errorf("the proof refused while closed, once reopened: %s, want a wallet", res["error"])
	}
}

// CT-JOIN-18 (CW-MULTI-01): a join whose bill proof is a second live
// connection's is served; once that connection is revoked, the same join is
// omitted.
func ctJoin18(t *testing.T, s *suite) {
	c := s.circleConn(t)
	admin := s.h.(Admin)
	second, err := nipcw.DecodeCircleHubConnection(admin.AddCircleConnection(t))
	if err != nil {
		t.Fatalf("the second connection: %v", err)
	}
	if second.Pubkey != c.Pubkey || second.Secret == c.Secret {
		t.Fatalf("the second connection has pubkey %s and the same secret %v: want the circle's pubkey, its own secret", second.Pubkey, second.Secret == c.Secret)
	}
	aPriv, _ := s.member(t)
	if res := s.joinWith(t, second, second.Secret, prepareJoin(t, second, aPriv, nil, nil).params(t), aPriv); res == nil || res["result"] == nil {
		t.Fatalf("a join over the second connection: %v", res)
	}
	admin.RevokeCircleConnection(t, encodeCircle(t, second))
	bPriv, _ := s.member(t)
	if res := s.joinWith(t, second, second.Secret, prepareJoin(t, second, bPriv, nil, nil).params(t), bPriv); res != nil {
		t.Errorf("a join over a revoked connection was answered %s %s, want it omitted", res["result"], res["error"])
	}
}

func encodeCircle(t *testing.T, c nipcw.CircleHubConnection) string {
	t.Helper()
	s, err := nipcw.EncodeCircleHubConnection(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// CT-JLK-01 (S-CW-15): with no record a lookup is pending (retry_after =
// deadline + 1) until the deadline, unknown for six minutes after, then
// expired; a deadline more than six minutes ahead counts as six.
func ctJlk01(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, _ := s.member(t)
	k, _ := nipcw.NewConnectionKey()
	now := time.Now().Unix()
	far := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, k.Pubkey(), now+3600))
	if far.Status != nipcash.LookupPending || far.RetryAfter > time.Now().Unix()+nipcash.JoinLookupWindow+2 {
		t.Errorf("a deadline an hour ahead: %s retry_after %d, want pending within six minutes", far.Status, far.RetryAfter)
	}
	d := now + 30
	st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, k.Pubkey(), d))
	if st.Status != nipcash.LookupPending || st.RetryAfter != d+1 {
		t.Errorf("before the deadline: %s retry_after %d, want pending %d", st.Status, st.RetryAfter, d+1)
	}
	s.advance(t, 60*time.Second)
	if st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, k.Pubkey(), d)); st.Status != nipcash.LookupUnknown {
		t.Errorf("past the deadline: %s, want unknown", st.Status)
	}
	s.advance(t, nipcash.JoinLookupWindow*time.Second)
	if st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, k.Pubkey(), d)); st.Status != nipcash.LookupExpired {
		t.Errorf("six minutes past the deadline: %s, want expired", st.Status)
	}
}

// CT-JLK-02 (S-CW-16): a lookup of a made join is done with the recorded
// encrypted_details, byte for byte.
func ctJlk02(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, _ := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	res := s.join(t, c, j)
	if res == nil || res["result"] == nil {
		t.Fatalf("join: %s", res["error"])
	}
	st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, j.ConnectionPubkey, j.Deadline))
	if st.Status != nipcash.LookupDone || !jsonEqual(st.Result, res["result"]) {
		t.Errorf("lookup %s %s, want done with the reply %s", st.Status, st.Result, res["result"])
	}
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && string(mustMarshal(x)) == string(mustMarshal(y))
}

func mustMarshal(v any) []byte { b, _ := json.Marshal(v); return b }

// CT-JLK-03 (S-CW-19, 20): a lookup by another signer is answered by its
// deadline, never done; one whose bill proof is not the Hub connection's is
// omitted; one whose bill proof verifies and item proof fails is UNAUTHORIZED.
func ctJlk03(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, _ := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	s.joinOK(t, c, j)
	other, _ := keypair(t)
	if st := lookupStatus(t, s.joinLookup(t, c, c.Secret, other, j.ConnectionPubkey, j.Deadline)); st.Status == nipcash.LookupDone {
		t.Errorf("another signer's lookup is done: the record is matched on (signer, connection_pubkey)")
	}
	if res := s.joinLookup(t, c, mustKey(t), priv, j.ConnectionPubkey, j.Deadline); res != nil {
		t.Errorf("a lookup whose bill proof fails was answered %s %s, want it omitted", res["result"], res["error"])
	}
	res := s.sendItems(t, func(n string, na int64) transport.Item {
		it := s.circleItem(t, c, c.Secret, "1", nipcash.MethodCashLookup, nipcash.CashLookupRequest{ConnectionPubkey: j.ConnectionPubkey, Deadline: j.Deadline}, priv, n, na)
		var p map[string]any
		_ = json.Unmarshal(it.Params, &p)
		p["deadline"] = j.Deadline + 1
		it.Params, _ = json.Marshal(p)
		hash, _ := transport.CanonicalParamsHash(it.Params)
		it.BillProof, _ = transport.BuildBillProof(c.Secret, transport.ProofBinding{Target: c.Pubkey, HubXOnly: s.nodeXOnly,
			Method: it.Method, ParamsHash: hash, Nonce: n, NotAfter: na})
		return it
	})["1"]
	joinWant(t, "a lookup whose item proof fails", res, nipcw.ErrUnauthorized)
}

// CT-JLK-04 (S-CW-21): the record outlives a quick delete; past its deadline
// plus six minutes the lookup is expired.
func ctJlk04(t *testing.T, s *suite) {
	c := s.circleConn(t)
	priv, _ := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	d := s.joinOK(t, c, j)
	ctx, cancel := ctx15()
	defer cancel()
	if resp, err := nwcTo(t, d.WalletPubkey, j.key.Secret(), d.Relays).Call(ctx, nipcw.MethodDeleteCircleWallet, struct{}{}); err != nil || resp.Error != nil {
		t.Fatalf("delete the empty wallet: %+v %v", resp, err)
	}
	if st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, j.ConnectionPubkey, j.Deadline)); st.Status != nipcash.LookupDone {
		t.Errorf("a lookup after a quick delete: %s, want done", st.Status)
	}
	s.advance(t, time.Duration(j.Deadline-time.Now().Unix()+nipcash.JoinLookupWindow+60)*time.Second)
	if st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, j.ConnectionPubkey, j.Deadline)); st.Status != nipcash.LookupExpired {
		t.Errorf("a lookup past the deadline plus six minutes, the wallet deleted: %s, want expired", st.Status)
	}
}

// CT-JLK-05 (S-CW-133): after a rotation the lookup naming the new key is
// pending until completes_at, then done with connection_pubkey the new key.
func ctJlk05(t *testing.T, s *suite) {
	c := s.circleConn(t)
	admin := s.h.(Admin)
	priv, _ := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	d := s.joinOK(t, c, j)
	if d.RotationDelaySecs == nil {
		t.Skip("the wallet cannot be rotated: its details carry no rotation_delay_secs")
	}
	k, _ := nipcw.NewConnectionKey()
	req, err := nipcw.NewMemberRequest(priv, c.Pubkey, nipcw.ActionRotate, d.WalletPubkey, k.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Unix()
	admin.Rotate(t, req)
	st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, k.Pubkey(), j.Deadline))
	if st.Status != nipcash.LookupPending || st.RetryAfter < before+int64(*d.RotationDelaySecs) {
		t.Errorf("during the rotation: %s retry_after %d, want pending until completes_at (≥ %d)", st.Status, st.RetryAfter, before+int64(*d.RotationDelaySecs))
	}
	s.advance(t, time.Duration(*d.RotationDelaySecs+1)*time.Second)
	st = lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, k.Pubkey(), j.Deadline))
	if st.Status != nipcash.LookupDone {
		t.Fatalf("after completes_at: %s, want done", st.Status)
	}
	got, err := nipcw.JoinLookupParams{Credential: nipcw.BySigning(priv), ConnectionPubkey: k.Pubkey(), Deadline: j.Deadline}.ParseResult(c.Pubkey, st.Result)
	if err != nil || got.ConnectionPubkey != k.Pubkey() || got.WalletPubkey != d.WalletPubkey {
		t.Errorf("the details after the rotation: %+v %v, want the same wallet under the new key", got, err)
	}
}

// CT-JLK-06 (S-CW-24, 25): lookups change nothing: repeated, they answer the
// same, and a join naming the looked-up key still works; the Hub reports its
// identity and serves cash_lookup.
func ctJlk06(t *testing.T, s *suite) {
	c := s.circleConn(t)
	gi := s.circleInfo(t, c)
	id := strings.ToLower(gi.CircleWallet.Identity)
	if len(id) == 66 {
		id = id[2:]
	}
	if id != c.HubIdentity {
		t.Errorf("circle_wallet.identity %q, want the string's TLV 4 %s", gi.CircleWallet.Identity, c.HubIdentity)
	}
	priv, _ := s.member(t)
	j := prepareJoin(t, c, priv, nil, nil)
	var first *nipcash.CashLookupResult
	for range 3 {
		st := lookupStatus(t, s.joinLookup(t, c, c.Secret, priv, j.ConnectionPubkey, j.Deadline))
		if first == nil {
			first = st
		} else if st.Status != first.Status || st.RetryAfter != first.RetryAfter {
			t.Errorf("a repeated lookup answered %+v, then %+v", first, st)
		}
	}
	s.joinOK(t, c, j)
}
