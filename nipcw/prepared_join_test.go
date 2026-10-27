package nipcw

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

func mustXOnly(t *testing.T, priv string) string {
	t.Helper()
	p, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func proofOf(t *testing.T, req CreateCircleWalletRequest) nip01.Event {
	t.Helper()
	var ev nip01.Event
	if err := json.Unmarshal([]byte(req.IdentityEvent), &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// K-JOIN-1: the spec's join proof (NIP-CW §Identity Proof).
func TestPrepare_KJOIN1(t *testing.T) {
	conn, err := ConnectionKeyFromSecret(key2)
	if err != nil {
		t.Fatal(err)
	}
	hub := mustXOnly(t, key3)
	j, err := CreateCircleWalletParams{Credential: BySigning(key1), Connection: conn,
		MaxAmountMillis: 100000, MaxReceiveMillis: 200000, BudgetRenewal: RenewalMonthly}.Prepare(hub, time.Unix(1720000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if j.ProofID != "f796fb3c192db23c1ea2636c580408c6e574e290c6193e7694d170abedbc65b8" {
		t.Fatalf("proof id = %s", j.ProofID)
	}
	ev := proofOf(t, j.Request)
	want := [][]string{{"d", hub}, {"connection", "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"}, {"terms", "100000:200000:0:monthly"}}
	if !slices.EqualFunc(ev.Tags, want, slices.Equal) || ev.Content != "" || ev.Kind != 23199 {
		t.Fatalf("proof = %+v", ev)
	}
	if j.CreatedAt != 1720000000 || j.Deadline != 1720000300 || j.ConnectionPubkey != conn.Pubkey() || j.HubPubkey != hub {
		t.Fatalf("prepared = %+v", j)
	}
}

// T12-01 (S-CW-01, 02, 40): the request's rules; the secret is never sent.
func TestPrepare_Request(t *testing.T) {
	priv, pub := generateTestKeypair(t)
	hub := mustXOnly(t, key3)
	now := time.Unix(1720000000, 0)
	conn := newTestConnectionKey(t)
	j, err := CreateCircleWalletParams{Credential: BySigning(priv), Connection: conn, MaxAmountMillis: 1,
		MaxReceiveMillis: 2, Expiry: 30 * 24 * time.Hour}.Prepare(hub, now)
	if err != nil {
		t.Fatal(err)
	}
	r := j.Request
	if r.Pubkey != pub || r.ConnectionPubkey != conn.Pubkey() || r.MaxAmount != 1 || r.MaxReceive != 2 ||
		r.Expiry != 2592000 || r.BudgetRenewal != RenewalNever {
		t.Fatalf("request = %+v", r)
	}
	wire, _ := json.Marshal(r)
	for _, k := range []string{`"max_receive":2`, `"budget_renewal":"never"`} {
		if !strings.Contains(string(wire), k) {
			t.Errorf("wire %s lacks %s", wire, k)
		}
	}
	if strings.Contains(string(wire), conn.Secret()) {
		t.Fatal("the connection secret appears in the request")
	}
	if tv, _ := oneTag(ptr(proofOf(t, r)), "terms"); tv != "1:2:2592000:never" {
		t.Fatalf("terms tag = %q", tv)
	}

	cases := map[string]CreateCircleWalletParams{
		"no connection key":    {Credential: BySigning(priv)},
		"connection = pubkey":  {Credential: BySigning(priv), Connection: mustKey(t, priv)},
		"renewal not in enum":  {Credential: BySigning(priv), Connection: conn, BudgetRenewal: "Monthly"},
		"negative expiry":      {Credential: BySigning(priv), Connection: conn, Expiry: -time.Second},
		"max_amount over 2^63": {Credential: BySigning(priv), Connection: conn, MaxAmountMillis: MaxTermValue + 1},
	}
	for name, p := range cases {
		if _, err := p.Prepare(hub, now); err == nil {
			t.Errorf("%s: prepared", name)
		}
	}
	if _, err := (CreateCircleWalletParams{Credential: BySigning(priv)}).Prepare(hub, now); !errors.Is(err, ErrNoConnectionKey) {
		t.Errorf("no key: %v", err)
	}
	if _, err := (CreateCircleWalletParams{Credential: BySigning(priv), Connection: conn}).Prepare(strings.ToUpper(hub), now); err == nil {
		t.Error("an uppercase hub pubkey was accepted")
	}
	// Fresh key per request (CW-S-01).
	a, b := newTestConnectionKey(t), newTestConnectionKey(t)
	if a.Pubkey() == b.Pubkey() {
		t.Fatal("two fresh connection keys are equal")
	}
	// CW-REQ-01: an uppercase secret is refused.
	if _, err := ConnectionKeyFromSecret(strings.Repeat("AB", 32)); err == nil {
		t.Error("an uppercase connection secret was accepted")
	}
}

func ptr(ev nip01.Event) *nip01.Event { return &ev }

func mustKey(t *testing.T, secret string) ConnectionKey {
	t.Helper()
	k, err := ConnectionKeyFromSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// T12-27 for Prepare: 2^63-1 accepted, 2^63 refused for each value.
func TestPrepare_Range(t *testing.T) {
	priv, _ := generateTestKeypair(t)
	hub := mustXOnly(t, key3)
	conn := newTestConnectionKey(t)
	ok := CreateCircleWalletParams{Credential: BySigning(priv), Connection: conn, MaxAmountMillis: MaxTermValue,
		MaxReceiveMillis: MaxTermValue, Expiry: time.Duration(1<<63 - 1)}
	if _, err := ok.Prepare(hub, time.Now()); err != nil {
		t.Fatalf("max values: %v", err)
	}
	for _, p := range []CreateCircleWalletParams{
		{Credential: BySigning(priv), Connection: conn, MaxAmountMillis: MaxTermValue + 1},
		{Credential: BySigning(priv), Connection: conn, MaxReceiveMillis: MaxTermValue + 1},
	} {
		if _, err := p.Prepare(hub, time.Now()); !errors.Is(err, ErrTerms) {
			t.Errorf("%+v: %v, want ErrTerms", p, err)
		}
	}
}

// T12-04 (S-CW-12) and T12-20 (S-CW-121, 125): the item targets the Hub, its item
// proof is the requester's, its bill proof the Hub connection secret's; a second
// use is refused.
func TestPreparedJoin_Item(t *testing.T) {
	memberPriv, memberPub := generateTestKeypair(t)
	hubSecret, hubPub := generateTestKeypair(t)
	_, node := generateTestKeypair(t)
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b := nipcash.ItemBinding{HubXOnly: node, Nonce: nonce, NotAfter: now.Add(time.Minute).Unix()}
	j, err := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: newTestConnectionKey(t), MaxAmountMillis: 1000}.Prepare(hubPub, now)
	if err != nil {
		t.Fatal(err)
	}
	item, err := j.Item("join", hubSecret, b)
	if err != nil {
		t.Fatalf("Item: %v", err)
	}
	if item.Target != hubPub || item.Method != MethodCreateCircleWallet {
		t.Fatalf("item targets %q with %q", item.Target, item.Method)
	}
	hash, err := transport.CanonicalParamsHash(item.Params)
	if err != nil {
		t.Fatal(err)
	}
	want := transport.ProofBinding{Target: hubPub, HubXOnly: node, Method: MethodCreateCircleWallet,
		ParamsHash: hash, Nonce: nonce, NotAfter: b.NotAfter}
	if signer, err := transport.VerifyItemProof(item.Proof, want, now); err != nil || signer != memberPub {
		t.Fatalf("item proof: %s %v", signer, err)
	}
	if signer, err := transport.VerifyBillProof(item.BillProof, want, now); err != nil || signer != mustXOnly(t, hubSecret) {
		t.Fatalf("bill proof: %s %v", signer, err)
	}
	if _, err := j.Item("again", hubSecret, b); !errors.Is(err, ErrPreparedJoinUsed) {
		t.Fatalf("second use: %v", err)
	}
	if !j.Used() {
		t.Fatal("Used() false after Item")
	}
	j2, _ := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: newTestConnectionKey(t)}.Prepare(hubPub, now)
	if _, err := j2.Item("join", "", b); err == nil {
		t.Fatal("a join without the Hub connection secret has no bill proof and must be refused")
	}
}

func details(conn string, extra string) string {
	return `{"wallet_pubkey":"` + testWalletPubkey + `","connection_pubkey":"` + conn + `","relays":["wss://r1.example","","wss://r2.example"],` +
		`"max_amount":100000,"max_receive":200000,"expires_at":1720000000,"fees_ppm":0,"dust_threshold_millis":1000,` +
		`"rotation_delay_secs":432000,"budget_renewal":"monthly"` + extra + `}`
}

// T12-05 (S-CW-29, 37–39, 96) and CW-RESP-01..05.
func TestPreparedJoin_ParseResult(t *testing.T) {
	memberPriv, memberPub := generateTestKeypair(t)
	hubPriv, hubPub := generateTestKeypair(t)
	conn := newTestConnectionKey(t)
	j, err := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: conn, MaxAmountMillis: 100000,
		MaxReceiveMillis: 200000, BudgetRenewal: RenewalMonthly}.Prepare(hubPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r, err := j.ParseResult(hubReply(t, hubPriv, memberPub, details(conn.Pubkey(), "")))
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if r.WalletPubkey != testWalletPubkey || r.ConnectionPubkey != conn.Pubkey() || !slices.Equal(r.Relays, []string{"wss://r1.example", "wss://r2.example"}) ||
		r.MaxAmountMillis != 100000 || r.MaxReceiveMillis != 200000 || r.ExpiresAt != 1720000000 || r.FeesPpm != 0 ||
		r.DustThresholdMillis != 1000 || r.RotationDelaySecs == nil || *r.RotationDelaySecs != 432000 ||
		r.BudgetRenewal != RenewalMonthly || r.MissingTerms != nil || r.LeakedFields != nil || r.CapsRaised {
		t.Fatalf("response = %+v", r)
	}

	// EncryptDetails, the Hub side, builds a reply ParseResult reads.
	rot := uint64(432000)
	enc, err := EncryptDetails(hubPriv, memberPub, CircleWalletDetails{WalletPubkey: testWalletPubkey, ConnectionPubkey: conn.Pubkey(),
		Relays: []string{"wss://r"}, MaxAmount: 100001, MaxReceive: 1, FeesPpm: 0, RotationDelaySecs: &rot, BudgetRenewal: "monthly"})
	if err != nil {
		t.Fatal(err)
	}
	r, err = j.ParseResult([]byte(enc))
	if err != nil || !r.CapsRaised || r.MissingTerms != nil {
		t.Fatalf("EncryptDetails round trip: %+v %v", r, err)
	}

	rejected := map[string][]byte{
		"no connection_pubkey":    hubReply(t, hubPriv, memberPub, `{"wallet_pubkey":"`+testWalletPubkey+`","relays":["wss://r"]}`),
		"old reply, other key":    hubReply(t, hubPriv, memberPub, details(newTestConnectionKey(t).Pubkey(), "")),
		"from another key":        hubReply(t, randomPriv(t), memberPub, details(conn.Pubkey(), "")),
		"no usable relay":         hubReply(t, hubPriv, memberPub, strings.Replace(details(conn.Pubkey(), ""), `"relays":["wss://r1.example","","wss://r2.example"]`, `"relays":[""," "]`, 1)),
		"no wallet_pubkey":        hubReply(t, hubPriv, memberPub, strings.Replace(details(conn.Pubkey(), ""), testWalletPubkey, "nope", 1)),
		"no encrypted_details":    []byte(`{}`),
		"encrypted to co-member":  hubReply(t, hubPriv, mustXOnly(t, randomPriv(t)), details(conn.Pubkey(), "")),
		"details not json object": hubReply(t, hubPriv, memberPub, `[1]`),
	}
	for name, raw := range rejected {
		if _, err := j.ParseResult(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := j.ParseResult(hubReply(t, hubPriv, memberPub, details(newTestConnectionKey(t).Pubkey(), ""))); !errors.Is(err, ErrDetailsConnection) {
		t.Errorf("old reply: %v, want ErrDetailsConnection", err)
	}

	// Leaked fields, raised caps and missing terms are reported, never fatal.
	leaky := details(conn.Pubkey(), `,"secret":"`+conn.Secret()+`","pairing_uri":"x"`)
	leaky = strings.Replace(leaky, `"max_receive":200000`, `"max_receive":200001`, 1)
	outer := hubReply(t, hubPriv, memberPub, leaky)
	outer = append(outer[:len(outer)-1], []byte(`,"wallet_pubkey":"`+testWalletPubkey+`"}`)...)
	r, err = j.ParseResult(outer)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.LeakedFields, []string{"pairing_uri", "secret", "wallet_pubkey"}) || !r.CapsRaised {
		t.Fatalf("leaked %v, caps raised %v", r.LeakedFields, r.CapsRaised)
	}
	sparse := `{"wallet_pubkey":"` + testWalletPubkey + `","connection_pubkey":"` + conn.Pubkey() + `","relays":["wss://r"],"fees_ppm":0}`
	r, err = j.ParseResult(hubReply(t, hubPriv, memberPub, sparse))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.MissingTerms, []string{"max_amount", "max_receive", "expires_at", "dust_threshold_millis", "budget_renewal"}) {
		t.Fatalf("missing = %v (fees_ppm 0 is present)", r.MissingTerms)
	}
}

func randomPriv(t *testing.T) string {
	t.Helper()
	p, _ := generateTestKeypair(t)
	return p
}

// T12-07 (S-CW-16, 20): the join lookup item.
func TestJoinLookupParams_Item(t *testing.T) {
	memberPriv, memberPub := generateTestKeypair(t)
	hubSecret, hubPub := generateTestKeypair(t)
	hubPriv := hubSecret // the test Hub's connection key doubles as its secret here
	_, node := generateTestKeypair(t)
	now := time.Now()
	j, err := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: newTestConnectionKey(t)}.Prepare(hubPub, now)
	if err != nil {
		t.Fatal(err)
	}
	p := JoinLookupParams{Credential: BySigning(memberPriv), ConnectionPubkey: j.ConnectionPubkey, Deadline: j.Deadline}
	if p.Deadline != now.Unix()+300 {
		t.Fatalf("deadline = %d", p.Deadline)
	}
	nonce, _ := transport.NewNonce()
	b := nipcash.ItemBinding{HubXOnly: node, Nonce: nonce, NotAfter: now.Add(time.Minute).Unix()}
	item, err := p.Item("lk", hubPub, hubSecret, b)
	if err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(item.Params, &params); err != nil {
		t.Fatal(err)
	}
	if item.Target != hubPub || item.Method != nipcash.MethodCashLookup || len(params) != 2 ||
		params["connection_pubkey"] != j.ConnectionPubkey || params["deadline"] != float64(j.Deadline) {
		t.Fatalf("item %+v params %v", item, params)
	}
	hash, _ := transport.CanonicalParamsHash(item.Params)
	want := transport.ProofBinding{Target: hubPub, HubXOnly: node, Method: nipcash.MethodCashLookup, ParamsHash: hash, Nonce: nonce, NotAfter: b.NotAfter}
	if signer, err := transport.VerifyItemProof(item.Proof, want, now); err != nil || signer != memberPub {
		t.Fatalf("item proof %s %v", signer, err)
	}
	if signer, err := transport.VerifyBillProof(item.BillProof, want, now); err != nil || signer != hubPub {
		t.Fatalf("bill proof %s %v", signer, err)
	}
	// CW-LK-02 / T12-09: done is checked as a reply, naming the key looked up.
	r, err := p.ParseResult(hubPub, hubReply(t, hubPriv, memberPub, details(j.ConnectionPubkey, "")))
	if err != nil || r.ConnectionPubkey != j.ConnectionPubkey {
		t.Fatalf("lookup done: %+v %v", r, err)
	}
	if _, err := p.ParseResult(hubPub, hubReply(t, hubPriv, memberPub, details(newTestConnectionKey(t).Pubkey(), ""))); err == nil {
		t.Fatal("a done naming another key was accepted")
	}
}
