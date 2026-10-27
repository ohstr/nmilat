package vectors

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

// ---- private-join.json (NIP-CW §Private Join)

type privateJoinFile struct {
	header
	Hub           string `json:"hub"`
	HubConnSecret string `json:"hubConnectionSecret"`
	// LiveConnections are the Hub connection pubkeys whose secrets may sign
	// a join's bill proof.
	LiveConnections []string               `json:"liveConnections"`
	Node            string                 `json:"node"`
	Nonce           string                 `json:"nonce"`
	NotAfter        int64                  `json:"notAfter"`
	Now             int64                  `json:"now"`
	Build           []privateJoinBuildCase `json:"build"`
	Verify          []privateJoinCheckCase `json:"verify"`
}

type privateJoinBuildCase struct {
	Name   string         `json:"name"`
	Inputs map[string]any `json:"inputs"`
	Item   map[string]any `json:"item,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// privateJoinCheckCase is a signed item with a fixed created_at, and what a
// Hub concludes about it: each proof's signer or error, and whether the join
// is admitted to authorization (target is the Hub, both proofs verify, the
// item proof is the requester's and the bill proof the Hub connection's).
type privateJoinCheckCase struct {
	Name       string `json:"name"`
	Target     string `json:"target"`
	Params     string `json:"params"`
	Proof      string `json:"proof"`
	BillProof  string `json:"billProof"`
	ItemSigner string `json:"itemSigner,omitempty"`
	ItemError  string `json:"itemError,omitempty"`
	BillSigner string `json:"billSigner,omitempty"`
	BillError  string `json:"billError,omitempty"`
	Admitted   bool   `json:"admitted"`
}

const (
	pjHubConnSecret = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
	pjOtherSecret   = "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"
	pjSecondSecret  = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"
	pjRevokedSecret = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
	pjParamsHash    = "<params hash>"
)

// proofShape is a proof without its time-dependent fields: nmilat signs
// join proofs at the current time, so only kind, signer and tags are fixed,
// and ph (which hashes the params, identity proof included) is replaced
// after checking it.
func proofShape(raw json.RawMessage, wantPH string) map[string]any {
	var ev nip01.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		panic(err)
	}
	tags := make([][]string, 0, len(ev.Tags))
	for _, t := range ev.Tags {
		t = append([]string(nil), t...)
		if len(t) > 1 && t[0] == "ph" {
			if t[1] != wantPH {
				panic(fmt.Sprintf("ph %s does not hash the params (%s)", t[1], wantPH))
			}
			t[1] = pjParamsHash
		}
		tags = append(tags, t)
	}
	return map[string]any{"kind": ev.Kind, "pubkey": ev.PubKey, "tags": tags}
}

func buildPrivateJoin() (any, error) {
	hubPub, _ := utils.GetPublicKey(hubSecret)
	hubConnPub, _ := utils.GetPublicKey(pjHubConnSecret)
	memberPub, _ := utils.GetPublicKey(claimantSecret)
	node, _ := utils.GetPublicKey(strings.Repeat("07", 32))
	conn, _ := nipcw.ConnectionKeyFromSecret(strings.Repeat("11", 32))
	const now = attTime
	f := privateJoinFile{
		header: newHeader(
			"NIP-CW §Private Join: create_circle_wallet as a private-transport item, the only way to join (no standard-transport join, no fallback). Its target and both proofs' d tag are the Hub connection pubkey and h the node identity; the item proof is the requester's, the bill proof a live Hub connection secret's (liveConnections; a revoked one is omitted). Also the join lookup and the post-rotation lookup (cash_lookup by connection_pubkey and deadline).",
			"nipcw/private_join.go, nipcash/transport_item.go; nipcw/private_join_test.go, nipcash/client/batch_circle_join_test.go",
		),
		Hub: hubPub, HubConnSecret: pjHubConnSecret, LiveConnections: []string{hubConnPub, must(utils.GetPublicKey(pjSecondSecret))}, Node: node, Nonce: envNonce, NotAfter: now + 60, Now: now,
	}
	b := nipcash.ItemBinding{HubXOnly: node, Nonce: envNonce, NotAfter: now + 60}

	recordItem := func(name string, inputs map[string]any, method string, item transport.Item, err error, params any) {
		c := privateJoinBuildCase{Name: name, Inputs: inputs}
		if err != nil {
			c.Error = err.Error()
			f.Build = append(f.Build, c)
			return
		}
		ph, err := transport.CanonicalParamsHash(item.Params)
		if err != nil {
			panic(err)
		}
		// The item must pass nmilat's own checks before it is recorded.
		want := transport.ProofBinding{Target: hubPub, HubXOnly: node, Method: method, ParamsHash: ph, Nonce: envNonce, NotAfter: b.NotAfter}
		if s, err := transport.VerifyItemProof(item.Proof, want, time.Now()); err != nil || s != memberPub {
			panic(fmt.Sprintf("%s: item proof %q, %v", name, s, err))
		}
		if s, err := transport.VerifyBillProof(item.BillProof, want, time.Now()); err != nil || s != hubConnPub {
			panic(fmt.Sprintf("%s: bill proof %q, %v", name, s, err))
		}
		if err := json.Unmarshal(item.Params, params); err != nil {
			panic(err)
		}
		c.Item = map[string]any{
			"id": item.ID, "target": item.Target, "method": item.Method,
			"params":    flattenRequest(params),
			"proof":     proofShape(item.Proof, ph),
			"billProof": proofShape(item.BillProof, ph),
		}
		f.Build = append(f.Build, c)
	}
	build := func(name, connSecret string, p nipcw.CreateCircleWalletParams, inputs map[string]any) {
		inputs["connectionSecret"] = connSecret
		inputs["now"] = now
		j, err := p.Prepare(hubPub, time.Unix(now, 0))
		if err != nil {
			recordItem(name, inputs, nipcw.MethodCreateCircleWallet, transport.Item{}, err, nil)
			return
		}
		item, err := j.Item("join", inputs["hubConnectionSecret"].(string), b)
		recordItem(name, inputs, nipcw.MethodCreateCircleWallet, item, err, &nipcw.CreateCircleWalletRequest{})
		if err == nil {
			_, again := j.Item("join", inputs["hubConnectionSecret"].(string), b)
			recordItem(name+": a second Item of the same prepared join", inputs, nipcw.MethodCreateCircleWallet, transport.Item{}, again, nil)
		}
	}
	in := func(hubConn string, max uint64, expiry int, renewal string) map[string]any {
		return map[string]any{"hubConnectionSecret": hubConn, "maxAmountMillis": max, "expirySeconds": expiry, "budgetRenewal": renewal}
	}
	member := nipcw.BySigning(claimantSecret)
	build("full", conn.Secret(), nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, MaxAmountMillis: 100000, Expiry: 30 * 24 * time.Hour, BudgetRenewal: "monthly"}, in(pjHubConnSecret, 100000, 2592000, "monthly"))
	build("the Hub's defaults", conn.Secret(), nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, MaxAmountMillis: 1}, in(pjHubConnSecret, 1, 0, ""))
	build("no Hub connection secret", conn.Secret(), nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, MaxAmountMillis: 1}, in("", 1, 0, ""))
	build("no connection key", "", nipcw.CreateCircleWalletParams{Credential: member, MaxAmountMillis: 1}, in(pjHubConnSecret, 1, 0, ""))

	// Lookups of a lost join reply: by the join's connection key, and after a
	// rotation by the new one (NIP-CW §Lost Join Reply).
	lookup := func(name, connPub string, deadline int64) {
		inputs := map[string]any{"hubConnectionSecret": pjHubConnSecret, "connectionPubkey": connPub, "deadline": deadline}
		item, err := nipcw.JoinLookupParams{Credential: member, ConnectionPubkey: connPub, Deadline: deadline}.Item("lookup", hubPub, pjHubConnSecret, b)
		recordItem(name, inputs, nipcash.MethodCashLookup, item, err, &map[string]any{})
	}
	lookup("join lookup", conn.Pubkey(), now+nipcw.JoinFreshness)
	rotated := must(nipcw.ConnectionKeyFromSecret(strings.Repeat("12", 32)))
	lookup("post-rotation lookup", rotated.Pubkey(), now+nipcw.JoinFreshness)
	lookup("lookup without a deadline", conn.Pubkey(), 0)

	// Fixed items, signed at `now`, checked the way a Hub checks a join.
	identity := nip01.Event{Kind: nipcw.KindCircleIdentityProof, CreatedAt: uint64(now), Tags: [][]string{{"d", hubPub}, {"connection", conn.Pubkey()}}}
	if err := identity.Sign(claimantSecret); err != nil {
		return nil, err
	}
	identityJSON, _ := json.Marshal(identity)
	params, _ := json.Marshal(nipcw.CreateCircleWalletRequest{Pubkey: memberPub, ConnectionPubkey: conn.Pubkey(), MaxAmount: 1000, IdentityEvent: string(identityJSON)})
	ph, err := transport.CanonicalParamsHash(params)
	if err != nil {
		return nil, err
	}
	good := transport.ProofBinding{Target: hubPub, HubXOnly: node, Method: nipcw.MethodCreateCircleWallet, ParamsHash: ph, Nonce: envNonce, NotAfter: now + 60}
	// The Hub's live connection secrets: a bill proof by any of them is the
	// Hub connection's; a revoked one (pjRevokedSecret) is not.
	live := map[string]bool{hubConnPub: true, must(utils.GetPublicKey(pjSecondSecret)): true}
	check := func(name string, target string, itemSecret string, itemB transport.ProofBinding, billSecret string, billB transport.ProofBinding, sentParams json.RawMessage) {
		c := privateJoinCheckCase{
			Name: name, Target: target, Params: string(sentParams),
			Proof:     string(signProof(transport.KindItemProof, itemSecret, itemB, now)),
			BillProof: string(signProof(transport.KindBillProof, billSecret, billB, now)),
		}
		sentPH, err := transport.CanonicalParamsHash(sentParams)
		if err != nil {
			panic(err)
		}
		want := transport.ProofBinding{Target: target, HubXOnly: node, Method: nipcw.MethodCreateCircleWallet, ParamsHash: sentPH, Nonce: envNonce, NotAfter: now + 60}
		itemSigner, itemErr := transport.VerifyItemProof(json.RawMessage(c.Proof), want, time.Unix(now, 0))
		billSigner, billErr := transport.VerifyBillProof(json.RawMessage(c.BillProof), want, time.Unix(now, 0))
		c.ItemSigner, c.ItemError = itemSigner, errString(itemErr)
		c.BillSigner, c.BillError = billSigner, errString(billErr)
		var req nipcw.CreateCircleWalletRequest
		_ = json.Unmarshal(sentParams, &req)
		c.Admitted = target == hubPub && itemErr == nil && billErr == nil && itemSigner == req.Pubkey && live[billSigner]
		f.Verify = append(f.Verify, c)
	}
	with := func(f func(*transport.ProofBinding)) transport.ProofBinding { x := good; f(&x); return x }
	check("valid join", hubPub, claimantSecret, good, pjHubConnSecret, good, params)
	check("item proof signed by another key than the requester", hubPub, pjOtherSecret, good, pjHubConnSecret, good, params)
	check("bill proof signed by the requester, not the Hub connection secret", hubPub, claimantSecret, good, claimantSecret, good, params)
	check("d is the node, not the Hub connection pubkey", node, claimantSecret, with(func(x *transport.ProofBinding) { x.Target = node }), pjHubConnSecret, with(func(x *transport.ProofBinding) { x.Target = node }), params)
	check("h is the Hub connection pubkey, not the node", hubPub, claimantSecret, with(func(x *transport.ProofBinding) { x.HubXOnly = hubPub }), pjHubConnSecret, with(func(x *transport.ProofBinding) { x.HubXOnly = hubPub }), params)
	tampered, _ := json.Marshal(nipcw.CreateCircleWalletRequest{Pubkey: memberPub, ConnectionPubkey: conn.Pubkey(), MaxAmount: 999999, IdentityEvent: string(identityJSON)})
	check("params changed after signing", hubPub, claimantSecret, good, pjHubConnSecret, good, tampered)
	check("bill proof by a second live Hub connection's secret", hubPub, claimantSecret, good, pjSecondSecret, good, params)
	check("bill proof by a revoked Hub connection's secret", hubPub, claimantSecret, good, pjRevokedSecret, good, params)
	return f, nil
}
