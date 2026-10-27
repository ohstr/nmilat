package vectors

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

// ---- nipcw.json

type nipcwFile struct {
	header
	Terms          []termsCase         `json:"terms"`
	ParseTerms     []parseTermsCase    `json:"parseTerms"`
	JoinProof      joinProofKAT        `json:"joinProof"`
	Requests       []circleRequestCase `json:"requests"`
	VerifyJoin     []verifyJoinCase    `json:"verifyJoinProof"`
	Results        []circleResultCase  `json:"results"`
	CircleWallet   []circleInfoCase    `json:"circleWallet"`
	MemberRequests []memberRequestCase `json:"memberRequests"`
	Notifications  []notificationCase  `json:"notifications"`
	GetBudget      []getBudgetCase     `json:"getBudget"`
}

type termsJSON struct {
	MaxAmount  uint64 `json:"maxAmount"`
	MaxReceive uint64 `json:"maxReceive"`
	Expiry     uint64 `json:"expiry"`
	Renewal    string `json:"renewal"`
}

// termsCase: TermsTag(Terms) is Tag or refused.
type termsCase struct {
	ID    string    `json:"id,omitempty"`
	Terms termsJSON `json:"terms"`
	Tag   string    `json:"tag,omitempty"`
	Error string    `json:"error,omitempty"`
}

// parseTermsCase: ParseTerms(Input), strict.
type parseTermsCase struct {
	Input string     `json:"input"`
	Terms *termsJSON `json:"terms,omitempty"`
	Error string     `json:"error,omitempty"`
}

// joinProofKAT: K-JOIN-1, the spec join proof prepared at CreatedAt.
type joinProofKAT struct {
	ID               string         `json:"id"`
	SignerSecret     string         `json:"signerSecret"`
	Hub              string         `json:"hub"`
	ConnectionSecret string         `json:"connectionSecret"`
	Terms            string         `json:"terms"`
	CreatedAt        int64          `json:"createdAt"`
	ProofID          string         `json:"proofId"`
	Deadline         int64          `json:"deadline"`
	Request          map[string]any `json:"request"`
}

type circleRequestCase struct {
	Name    string         `json:"name"`
	Inputs  map[string]any `json:"inputs"`
	Error   string         `json:"error,omitempty"`
	Request map[string]any `json:"request,omitempty"`
}

// verifyJoinCase: VerifyJoinProof(Params, Hub, Now) returns the proof id or
// refuses; Consumed says the id was already used.
type verifyJoinCase struct {
	Name     string `json:"name"`
	Params   string `json:"params"`
	Hub      string `json:"hub"`
	Now      int64  `json:"now"`
	Consumed bool   `json:"consumed"`
	ProofID  string `json:"proofId,omitempty"`
	Error    string `json:"error,omitempty"`
}

type circleResultCase struct {
	Name   string         `json:"name"`
	Result string         `json:"result"`
	Error  string         `json:"error,omitempty"`
	Want   map[string]any `json:"want,omitempty"`
}

// circleInfoCase: a get_info result as a client reads it: the
// circle_wallet block (accepting, terms), network and chain, and the
// always-required fields it is missing.
type circleInfoCase struct {
	Name          string         `json:"name"`
	Result        string         `json:"result"`
	Error         string         `json:"error,omitempty"`
	Want          map[string]any `json:"want,omitempty"`
	MissingAlways []string       `json:"missingAlways"`
	Accepting     *bool          `json:"accepting"`
	ValidNetwork  bool           `json:"validNetwork"`
}

// memberRequestCase: VerifyMemberRequest(Event, Hub, Now).
type memberRequestCase struct {
	Name     string         `json:"name"`
	Event    nip01.Event    `json:"event"`
	Hub      string         `json:"hub"`
	Now      int64          `json:"now"`
	Consumed bool           `json:"consumed"`
	Error    string         `json:"error,omitempty"`
	Want     map[string]any `json:"want,omitempty"`
}

// notificationCase: a NIP-CW notification as the member decrypts it.
type notificationCase struct {
	Name    string         `json:"name"`
	Event   nip01.Event    `json:"event"`
	Error   string         `json:"error,omitempty"`
	Type    string         `json:"type,omitempty"`
	Payload map[string]any `json:"payload,omitempty"`
}

// getBudgetCase: a get_budget result and what remains to send and receive.
type getBudgetCase struct {
	Name             string `json:"name"`
	Result           string `json:"result"`
	Error            string `json:"error,omitempty"`
	RemainingSend    int64  `json:"remainingSend"`
	RemainingReceive *int64 `json:"remainingReceive"`
}

const (
	hubSecret = "0606060606060606060606060606060606060606060606060606060606060606"
	cwKey1    = "0000000000000000000000000000000000000000000000000000000000000001"
	cwKey2    = "0000000000000000000000000000000000000000000000000000000000000002"
	cwKey3    = "0000000000000000000000000000000000000000000000000000000000000003"
	cwNow     = 1720000000
)

func toTermsJSON(t nipcw.Terms) termsJSON {
	return termsJSON{t.MaxAmount, t.MaxReceive, t.Expiry, t.Renewal}
}

func buildNIPCW() (any, error) {
	f := nipcwFile{header: newHeader(
		"NIP-CW: the terms tag, the join proof (kind 23199) and create_circle_wallet request, the Hub's join-proof check, the reply's encrypted details, get_info's circle_wallet block with network and chain, member requests, rotation notifications and get_budget.",
		"nipcw/{terms,create_circle_wallet,join_proof,member_request,identity}.go, nip47/methods.go; nipcw/{terms,prepared_join,join_proof,member_request}_test.go (K-TERMS-1..2, K-JOIN-1)",
	)}
	for _, c := range []struct {
		id string
		t  nipcw.Terms
	}{
		{"K-TERMS-1", nipcw.Terms{MaxAmount: 100000, MaxReceive: 200000, Expiry: 0, Renewal: "monthly"}},
		{"K-TERMS-2", nipcw.Terms{MaxAmount: 20000000, MaxReceive: 50000000}},
		{"", nipcw.Terms{MaxAmount: nipcw.MaxTermValue, Renewal: "daily"}},
		{"", nipcw.Terms{MaxAmount: nipcw.MaxTermValue + 1}},
		{"", nipcw.Terms{Renewal: "Monthly"}},
		{"", nipcw.Terms{Renewal: "fortnightly"}},
	} {
		tag, err := nipcw.TermsTag(c.t)
		f.Terms = append(f.Terms, termsCase{c.id, toTermsJSON(c.t), tag, errString(err)})
	}
	for _, in := range []string{"100000:200000:0:monthly", "20000000:50000000:0:never", "0:0:0:daily", "9223372036854775807:0:0:yearly",
		"9223372036854775808:0:0:yearly", "01:0:0:never", "+1:0:0:never", "1:0:0", "1:0:0:never:x", "1:0:0:", "1:0:0:Never", ":0:0:never", "1: 0:0:never", "1:0:0:weekly"} {
		c := parseTermsCase{Input: in}
		t, err := nipcw.ParseTerms(in)
		if err != nil {
			c.Error = err.Error()
		} else {
			tj := toTermsJSON(t)
			c.Terms = &tj
		}
		f.ParseTerms = append(f.ParseTerms, c)
	}

	hub := must(utils.GetPublicKey(cwKey3))
	conn := must(nipcw.ConnectionKeyFromSecret(cwKey2))
	now := time.Unix(cwNow, 0)
	j, err := nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(cwKey1), Connection: conn,
		MaxAmountMillis: 100000, MaxReceiveMillis: 200000, BudgetRenewal: nipcw.RenewalMonthly}.Prepare(hub, now)
	if err != nil {
		return nil, err
	}
	f.JoinProof = joinProofKAT{"K-JOIN-1", cwKey1, hub, cwKey2, "100000:200000:0:monthly", j.CreatedAt, j.ProofID, j.Deadline, flattenRequest(j.Request)}

	member := nipcw.BySigning(claimantSecret)
	self := must(nipcw.ConnectionKeyFromSecret(claimantSecret))
	req := func(name string, p nipcw.CreateCircleWalletParams, inputs map[string]any) {
		c := circleRequestCase{Name: name, Inputs: inputs}
		pj, err := p.Prepare(hub, now)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Request = flattenRequest(pj.Request)
		}
		f.Requests = append(f.Requests, c)
	}
	in := func(conn string, max, recv uint64, expiry int, renewal string) map[string]any {
		return map[string]any{"hub": hub, "now": cwNow, "memberSecret": claimantSecret, "connectionSecret": conn, "maxAmountMillis": max, "maxReceiveMillis": recv, "expirySeconds": expiry, "budgetRenewal": renewal}
	}
	req("full", nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, MaxAmountMillis: 100000, MaxReceiveMillis: 50000, Expiry: 30 * 24 * time.Hour, BudgetRenewal: "monthly"}, in(cwKey2, 100000, 50000, 2592000, "monthly"))
	req("empty renewal is never", nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, MaxAmountMillis: 1}, in(cwKey2, 1, 0, 0, ""))
	req("sub-second expiry truncates", nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, Expiry: 1500 * time.Millisecond}, in(cwKey2, 0, 0, 1, ""))
	req("unknown renewal", nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, BudgetRenewal: "Monthly"}, in(cwKey2, 0, 0, 0, "Monthly"))
	req("cap above 2^63-1", nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, MaxAmountMillis: nipcw.MaxTermValue + 1}, in(cwKey2, nipcw.MaxTermValue+1, 0, 0, ""))
	req("no connection key", nipcw.CreateCircleWalletParams{Credential: member}, in("", 0, 0, 0, ""))
	req("connection key equal to the member key", nipcw.CreateCircleWalletParams{Credential: member, Connection: self}, in(claimantSecret, 0, 0, 0, ""))

	// The Hub's check, on K-JOIN-1's request.
	raw, _ := json.Marshal(j.Request)
	vj := func(name string, params []byte, hubPub string, at int64, consumed bool) {
		c := verifyJoinCase{Name: name, Params: string(params), Hub: hubPub, Now: at, Consumed: consumed}
		r, err := nipcw.ParseCreateCircleWalletRequest(params)
		if err == nil {
			c.ProofID, err = nipcw.VerifyJoinProof(r, hubPub, time.Unix(at, 0), func(string) bool { return consumed })
		}
		c.Error = errString(err)
		f.VerifyJoin = append(f.VerifyJoin, c)
	}
	vj("K-JOIN-1 at created_at", raw, hub, cwNow, false)
	vj("300 s later", raw, hub, cwNow+300, false)
	vj("301 s later", raw, hub, cwNow+301, false)
	vj("60 s before", raw, hub, cwNow-60, false)
	vj("61 s before", raw, hub, cwNow-61, false)
	vj("already used", raw, hub, cwNow, true)
	vj("another Hub", raw, must(utils.GetPublicKey(cwKey2)), cwNow, false)
	alt := j.Request
	alt.MaxAmount++
	altRaw, _ := json.Marshal(alt)
	vj("terms changed after signing", altRaw, hub, cwNow, false)
	alt = j.Request
	alt.ConnectionPubkey = must(utils.GetPublicKey(cwKey3))
	altRaw, _ = json.Marshal(alt)
	vj("connection changed after signing", altRaw, hub, cwNow, false)
	alt = j.Request
	alt.Pubkey = hub
	altRaw, _ = json.Marshal(alt)
	vj("pubkey is not the signer", altRaw, hub, cwNow, false)
	vj("params not JSON", []byte("{"), hub, cwNow, false)

	// Replies to the member's join.
	pj, err := nipcw.CreateCircleWalletParams{Credential: member, Connection: conn, MaxAmountMillis: 100000, MaxReceiveMillis: 50000}.Prepare(hub, now)
	if err != nil {
		return nil, err
	}
	memberPub := must(utils.GetPublicKey(claimantSecret))
	result := func(name string, data string) {
		c := circleResultCase{Name: name, Result: data}
		r, err := pj.ParseResult([]byte(data))
		if err != nil {
			c.Error = err.Error()
		} else {
			raw, _ := json.Marshal(r)
			_ = json.Unmarshal(raw, &c.Want)
		}
		f.Results = append(f.Results, c)
	}
	seal := func(details string) string {
		ct, err := nip44.EncryptHex(details, cwKey3, memberPub)
		if err != nil {
			panic(err)
		}
		raw, _ := json.Marshal(map[string]string{"encrypted_details": ct})
		return string(raw)
	}
	w := strings.Repeat("9a", 32)
	cp := conn.Pubkey()
	full := `{"wallet_pubkey":"` + w + `","connection_pubkey":"` + cp + `","relays":["wss://r1.example","wss://r2.example"],"max_amount":100000,"max_receive":50000,"expires_at":1800000000,"fees_ppm":2500,"dust_threshold_millis":1000,"rotation_delay_secs":86400,"budget_renewal":"monthly"}`
	withSeededRand("nipcw-results", func() int {
		details, err := nipcw.EncryptDetails(cwKey3, memberPub, nipcw.CircleWalletDetails{WalletPubkey: w, ConnectionPubkey: cp, Relays: []string{"wss://r1.example"},
			MaxAmount: 100000, MaxReceive: 50000, ExpiresAt: 1800000000, FeesPpm: 2500, DustThresholdMillis: 1000, BudgetRenewal: "monthly"})
		if err != nil {
			panic(err)
		}
		result("EncryptDetails, every term", details)
		result("full details", seal(full))
		result("missing terms are named", seal(`{"wallet_pubkey":"`+w+`","connection_pubkey":"`+cp+`","relays":["wss://r1.example"]}`))
		result("a cap above the request", seal(strings.Replace(full, `"max_amount":100000`, `"max_amount":100001`, 1)))
		result("a leaked secret", seal(strings.Replace(full, `"budget_renewal"`, `"secret":"`+strings.Repeat("11", 32)+`","budget_renewal"`, 1)))
		result("a leaked URI", seal(strings.Replace(full, `"budget_renewal"`, `"uri":"nostr+walletconnect://x","budget_renewal"`, 1)))
		result("another connection pubkey", seal(strings.Replace(full, cp, w, 1)))
		result("blank relays are dropped", seal(strings.Replace(full, `["wss://r1.example","wss://r2.example"]`, `[" ","wss://r1.example",""]`, 1)))
		result("only blank relays", seal(strings.Replace(full, `["wss://r1.example","wss://r2.example"]`, `[" "]`, 1)))
		result("bad wallet pubkey", seal(strings.Replace(full, w, "abc", 1)))
		result("details not JSON", seal(`nope`))
		result("a field beside encrypted_details", strings.TrimSuffix(seal(full), "}")+`,"wallet_pubkey":"`+w+`"}`)
		result("no encrypted_details", `{}`)
		result("result not JSON", `[`)
		ct, _ := nip44.EncryptHex(full, cwKey2, memberPub)
		raw, _ := json.Marshal(map[string]string{"encrypted_details": ct})
		result("details sealed by another key than the Hub connection", string(raw))
		return 0
	})

	info := func(name, result string) {
		c := circleInfoCase{Name: name, Result: result, MissingAlways: []string{}}
		var r nip47.GetInfoResult
		if err := json.Unmarshal([]byte(result), &r); err != nil {
			c.Error = err.Error()
		} else {
			raw, _ := json.Marshal(r)
			_ = json.Unmarshal(raw, &c.Want)
			if r.CircleWallet != nil {
				c.MissingAlways = nonNil(r.CircleWallet.MissingAlways())
				c.Accepting = r.CircleWallet.Accepting
			}
			c.ValidNetwork = nip47.ValidNetwork(r.Network)
		}
		f.CircleWallet = append(f.CircleWallet, c)
	}
	cw := `"circle_wallet":{"available_millis":5000000,"max_exp_secs":2592000,"fees_ppm":2500,"circle_policy":"allowlist","identity":"` + connIdentity + `","per_wallet_max_millis":10000000,"min_budget_renewal":"monthly","fee_reserve":{"ppm":5000,"min_millis":10000},"dust_threshold_millis":1000,"rotation_delay_secs":86400,"accepting":true}`
	info("full", `{"pubkey":"`+connIdentity+`","network":"mainnet","chain":"bitcoin","methods":["get_info"],`+cw+`}`)
	info("not accepting", `{"network":"mainnet","chain":"bitcoin","methods":["get_info"],`+strings.Replace(cw, `"accepting":true`, `"accepting":false`, 1)+`}`)
	info("accepting absent", `{"network":"mainnet","chain":"bitcoin","methods":["get_info"],`+strings.Replace(cw, `,"accepting":true`, ``, 1)+`}`)
	info("fee_reserve and dust_threshold_millis absent", `{"network":"mainnet","chain":"bitcoin","methods":["get_info"],"circle_wallet":{"available_millis":0,"max_exp_secs":0,"fees_ppm":0,"circle_policy":"follow_set","accepting":true}}`)
	info("test network", `{"network":"regtest","chain":"bitcoin","methods":["get_info"],`+cw+`}`)
	info("unknown network", `{"network":"moonnet","chain":"bitcoin","methods":["get_info"],`+cw+`}`)
	info("no circle_wallet", `{"network":"mainnet","chain":"bitcoin","methods":["get_info"]}`)

	// Member requests (kind 23199 with an action), signed at fixed times.
	wallet := strings.Repeat("ab", 32)
	newConn := must(nipcw.ConnectionKeyFromSecret(strings.Repeat("11", 32))).Pubkey()
	mr := func(name string, at int64, consumed bool, tags ...[]string) {
		ev := nip01.Event{Kind: nipcw.KindCircleIdentityProof, CreatedAt: uint64(at), Tags: tags}
		if err := ev.Sign(claimantSecret); err != nil {
			panic(err)
		}
		c := memberRequestCase{Name: name, Event: ev, Hub: hub, Now: cwNow, Consumed: consumed}
		m, err := nipcw.VerifyMemberRequest(&ev, hub, time.Unix(cwNow, 0), func(string) bool { return consumed })
		if err == nil {
			err = m.CheckConnection()
		}
		if err != nil {
			c.Error = err.Error()
		} else {
			raw, _ := json.Marshal(m)
			_ = json.Unmarshal(raw, &c.Want)
		}
		f.MemberRequests = append(f.MemberRequests, c)
	}
	d, wt := []string{"d", hub}, []string{"wallet", wallet}
	rot, cn := []string{"action", "rotate"}, []string{"connection", newConn}
	mr("rotate", cwNow, false, d, rot, wt, cn)
	mr("freeze", cwNow, false, d, []string{"action", "freeze"}, wt)
	mr("unfreeze", cwNow, false, d, []string{"action", "unfreeze"}, wt)
	mr("a day old", cwNow-86400, false, d, rot, wt, cn)
	mr("a day and a second old", cwNow-86401, false, d, rot, wt, cn)
	mr("60 s ahead", cwNow+60, false, d, rot, wt, cn)
	mr("61 s ahead", cwNow+61, false, d, rot, wt, cn)
	mr("already used", cwNow, true, d, rot, wt, cn)
	mr("another Hub", cwNow, false, []string{"d", wallet}, rot, wt, cn)
	mr("unknown action", cwNow, false, d, []string{"action", "delete"}, wt)
	mr("two actions", cwNow, false, d, rot, []string{"action", "freeze"}, wt, cn)
	mr("no wallet", cwNow, false, d, rot, cn)
	mr("rotate without a connection", cwNow, false, d, rot, wt)
	mr("freeze with a connection", cwNow, false, d, []string{"action", "freeze"}, wt, cn)
	mr("with a terms tag", cwNow, false, d, rot, wt, cn, []string{"terms", "1:0:0:never"})
	mr("rotate to an invalid key", cwNow, false, d, rot, wt, []string{"connection", strings.Repeat("ff", 32)})

	// Rotation and freeze notifications, NIP-44.
	appPub := memberPub
	notif := func(name, typ string, payload any) {
		raw, _ := json.Marshal(payload)
		ev, err := nip47.NewNotificationEvent(cwKey3, appPub, nip47.Notification{NotificationType: typ, Notification: raw}, true)
		if err != nil {
			panic(err)
		}
		ev.CreatedAt = cwNow
		if err := ev.Sign(cwKey3); err != nil {
			panic(err)
		}
		c := notificationCase{Name: name, Event: *ev}
		n, err := nip47.ParseNotificationEvent(ev, claimantSecret)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Type = n.NotificationType
			_ = json.Unmarshal(n.Notification, &c.Payload)
		}
		f.Notifications = append(f.Notifications, c)
	}
	withSeededRand("nipcw-notifications", func() int {
		notif("rotation_pending", nip47.NotificationRotationPending, nip47.RotationPending{ConnectionPubkey: newConn, CompletesAt: cwNow + 86400})
		notif("rotation_cancelled", nip47.NotificationRotationCancelled, nip47.RotationChanged{ConnectionPubkey: newConn})
		notif("rotation_completed", nip47.NotificationRotationCompleted, nip47.RotationChanged{ConnectionPubkey: newConn})
		notif("wallet_frozen", nip47.NotificationWalletFrozen, map[string]any{"wallet_pubkey": wallet})
		return 0
	})

	budget := func(name, result string) {
		c := getBudgetCase{Name: name, Result: result}
		var r nip47.GetBudgetResult
		if err := json.Unmarshal([]byte(result), &r); err != nil {
			c.Error = err.Error()
		} else {
			c.RemainingSend = r.RemainingSend()
			if v, ok := r.RemainingReceive(); ok {
				c.RemainingReceive = &v
			}
		}
		f.GetBudget = append(f.GetBudget, c)
	}
	budget("send and receive", `{"used_budget":15000000,"total_budget":20000000,"renews_at":1722678400,"renewal_period":"monthly","total_receive_budget":50000000,"used_receive_budget":1000}`)
	budget("send only", `{"used_budget":0,"total_budget":100000,"renewal_period":"never"}`)
	budget("overspent", `{"used_budget":30000,"total_budget":20000,"renewal_period":"daily"}`)
	budget("receive overspent", `{"used_budget":0,"total_budget":1,"renewal_period":"never","total_receive_budget":5,"used_receive_budget":9}`)
	budget("not JSON", `[`)
	return f, nil
}
