package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/internal/credcodec"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip13"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
)

// ---- relay-hash.json

type relayHashFile struct {
	header
	Secret   string          `json:"secret"`
	Hash     []relayHashCase `json:"hash"`
	Negative []relayHashCase `json:"negative"`
}

// relayHashCase: RelayHash(Relays, Secret). A negative case is what a wrong
// construction computes; RelayHash never produces it.
type relayHashCase struct {
	ID     string   `json:"id"`
	Relays []string `json:"relays"`
	Note   string   `json:"note,omitempty"`
	Hash   string   `json:"hash,omitempty"`
	Error  string   `json:"error,omitempty"`
}

func buildRelayHash() (any, error) {
	f := relayHashFile{header: newHeader(
		"The relay hash a mint and zap payload and every connection signature bind: sha256 over each relay hint in the order given as a 1-byte length then its bytes, then the 32-byte secret. Every entry counts as given, an empty or blank one included.",
		"nipcash/provenance.go RelayHash; nipcash/token_codec_test.go, kat_test.go (K-RH-1..8)",
	), Secret: specSecret()}
	sec := seq(0)
	r1, r2 := specRelay1, specRelay2
	add := func(id string, relays []string) {
		h, err := nipcash.RelayHash(relays, specSecret())
		f.Hash = append(f.Hash, relayHashCase{ID: id, Relays: relays, Hash: h, Error: errString(err)})
	}
	add("K-RH-1", []string{r1, r2})
	add("K-RH-4", []string{r1, "", r2})
	add("K-RH-5", []string{r2, r1})
	add("K-RH-7", []string{" ", r1})
	add("K-RH-8", []string{r1})
	add("no hint", []string{})
	add("255-byte hint", []string{strings.Repeat("a", 255)})
	add("256-byte hint is refused", []string{strings.Repeat("a", 256)})
	sum := func(parts ...[]byte) string {
		s := sha256.Sum256(bytes.Join(parts, nil))
		return hex.EncodeToString(s[:])
	}
	lp := func(s string) []byte { return append([]byte{byte(len(s))}, s...) }
	f.Negative = []relayHashCase{
		{ID: "K-RH-2", Relays: []string{r1, r2}, Note: "no length bytes", Hash: sum([]byte(r1), []byte(r2), sec)},
		{ID: "K-RH-3", Relays: []string{r1, r2}, Note: "no secret", Hash: sum(lp(r1), lp(r2))},
		{ID: "K-RH-6", Relays: []string{r1, r2}, Note: "secret as hex text", Hash: sum(lp(r1), lp(r2), []byte(specSecret()))},
	}
	return f, nil
}

// ---- request-id.json

type requestIDFile struct {
	header
	Valid    []validCase   `json:"valid"`
	Derived  []derivedCase `json:"derived"`
	Requires []methodFlag  `json:"privateTransportRequiresRequestId"`
}

type validCase struct {
	ID    string `json:"id,omitempty"`
	Input string `json:"input"`
	Valid bool   `json:"valid"`
}

type derivedCase struct {
	ID       string `json:"id,omitempty"`
	Replaced string `json:"replaced"`
	Derived  string `json:"derived,omitempty"`
	Error    string `json:"error,omitempty"`
}

type methodFlag struct {
	Method string `json:"method"`
	Value  bool   `json:"value"`
}

var cashMethods = []string{"mint_cash", "cash_redeem", "cash_transfer", "cash_consolidate", "cash_status", "cash_lookup", "cash_order",
	"cash_withdraw_quote", "cash_withdraw", "create_circle_wallet", "pay_invoice", ""}

func buildRequestID() (any, error) {
	f := requestIDFile{header: newHeader(
		"request_id: 32 to 64 lowercase hex characters of even length; the derived id of a re-placed call is sha256(\"retry:\" || replaced id). privateTransportRequiresRequestId is the private transport's I6 list, the methods refused BAD_REQUEST there without one; mint_cash is not served there, and needs a request_id on NIP-47.",
		"nipcash/request_id.go; nipcash/deadline_lookup_test.go (K-RID-1, K-DID-1..2)",
	)}
	for _, c := range [][2]string{
		{"K-RID-1", vecRID}, {"K-RID-1 (31 chars)", vecRID[:31]}, {"K-RID-1 (uppercase)", strings.ToUpper(vecRID)},
		{"", strings.Repeat("a", 34)}, {"", strings.Repeat("a", 33)}, {"", strings.Repeat("a", 64)}, {"", strings.Repeat("a", 66)},
		{"", strings.Repeat("g", 32)}, {"", ""},
	} {
		f.Valid = append(f.Valid, validCase{c[0], c[1], nipcash.ValidRequestID(c[1])})
	}
	d1, err := nipcash.DerivedRequestID(vecRID)
	f.Derived = append(f.Derived, derivedCase{"K-DID-1", vecRID, d1, errString(err)})
	d2, err := nipcash.DerivedRequestID(d1)
	f.Derived = append(f.Derived, derivedCase{"K-DID-2", d1, d2, errString(err)})
	d3, err := nipcash.DerivedRequestID("XYZ")
	f.Derived = append(f.Derived, derivedCase{"", "XYZ", d3, errString(err)})
	for _, m := range cashMethods {
		f.Requires = append(f.Requires, methodFlag{m, nipcash.RequiresRequestID(m)})
	}
	return f, nil
}

// ---- lookup.json

type lookupFile struct {
	header
	Deadline      []deadlineCase     `json:"deadline"`
	Decide        []decideCase       `json:"decideLookup"`
	Window        []windowCase       `json:"deadlineWindow"`
	Retained      []retainedCase     `json:"recordRetained"`
	Tombstone     []retainedCase     `json:"tombstoneAnswerable"`
	Params        []lookupParamsCase `json:"params"`
	Results       []lookupResultCase `json:"results"`
	AnswersTombst []methodFlag       `json:"answersWithTombstone"`
}

type deadlineCase struct {
	ID       string `json:"id,omitempty"`
	Deadline int64  `json:"deadline"`
	Now      int64  `json:"now"`
	Horizon  int64  `json:"horizon"`
	Error    string `json:"error,omitempty"`
}

type decideCase struct {
	ID         string `json:"id,omitempty"`
	Now        int64  `json:"now"`
	Deadline   int64  `json:"deadline"`
	Horizon    int64  `json:"horizon"`
	Join       bool   `json:"join"`
	HaveRecord bool   `json:"haveRecord"`
	Status     string `json:"status"`
	RetryAfter int64  `json:"retryAfter"`
}

type windowCase struct {
	Horizon int64 `json:"horizon"`
	Window  int64 `json:"window"`
}

type retainedCase struct {
	Now      int64 `json:"now"`
	Until    int64 `json:"until"`
	Horizon  int64 `json:"horizon,omitempty"`
	Retained bool  `json:"retained"`
}

type lookupParamsCase struct {
	Name   string                    `json:"name"`
	Params nipcash.CashLookupRequest `json:"params"`
	Error  string                    `json:"error,omitempty"`
}

// lookupResultCase: ParseCashLookupResult, and for a done result its inner
// result read as the named method's (a tombstone, an order's current
// state, a withdrawal's current payout).
type lookupResultCase struct {
	Name   string             `json:"name"`
	Method string             `json:"method"`
	Result string             `json:"result"`
	Error  string             `json:"error,omitempty"`
	Status string             `json:"status,omitempty"`
	Retry  int64              `json:"retryAfter,omitempty"`
	Inner  map[string]any     `json:"inner,omitempty"`
	Gone   *nipcash.Tombstone `json:"gone,omitempty"`
}

func buildLookup() (any, error) {
	f := lookupFile{header: newHeader(
		"Deadlines and cash_lookup: CheckDeadline against the Hub's horizon H, DecideLookup (pending with retry_after, unknown, expired, done; a join lookup's window), retention, lookup params, and done results (a destroyed bill's tombstone in place of its token, an order's current state, a withdrawal's current payout).",
		"nipcash/{lookup_decision,cash_lookup,expiry,tombstone,withdraw_payout}.go; nipcash/deadline_lookup_test.go (K-DL-1, K-LK-1..7, K-JLK-1)",
	)}
	const T, H = int64(1720000000), int64(300)
	for _, c := range []struct {
		id string
		d  int64
		h  int64
	}{{"K-DL-1", T + 300, H}, {"K-DL-1", T + 301, H}, {"K-DL-1", T - 1, H}, {"K-DL-1", T, H}, {"", 0, H}, {"", T + 10, 59}, {"", T + 600, 600}} {
		f.Deadline = append(f.Deadline, deadlineCase{c.id, c.d, T, c.h, errString(nipcash.CheckDeadline(c.d, T, c.h))})
	}
	dec := func(id string, in nipcash.LookupInput) {
		d := nipcash.DecideLookup(in)
		f.Decide = append(f.Decide, decideCase{id, in.Now, in.Deadline, in.Horizon, in.Join, in.HaveRecord, string(d.Status), d.RetryAfter})
	}
	D := T
	dec("K-LK-1", nipcash.LookupInput{Now: D, Deadline: D, Horizon: H})
	dec("K-LK-2", nipcash.LookupInput{Now: D + 1, Deadline: D, Horizon: H})
	dec("K-LK-3", nipcash.LookupInput{Now: D + 300, Deadline: D, Horizon: H})
	dec("K-LK-4", nipcash.LookupInput{Now: D + 301, Deadline: D, Horizon: H})
	dec("K-LK-5", nipcash.LookupInput{Now: D + 9999, Deadline: D, Horizon: H, HaveRecord: true})
	dec("K-LK-6", nipcash.LookupInput{Now: D, Deadline: D + 10000, Horizon: H})
	dec("K-LK-7", nipcash.LookupInput{Now: D + 450, Deadline: D, Horizon: 600})
	dec("a lookup naming a used id is answered (I7)", nipcash.LookupInput{Now: D + 100, Deadline: D, Horizon: H, HaveRecord: true})
	dec("", nipcash.LookupInput{Now: D - 100, Deadline: D - 200, Horizon: H})
	for _, now := range []int64{T, T + 300, T + 301, T + 660, T + 661} {
		dec("K-JLK-1", nipcash.LookupInput{Now: now, Deadline: T + 300, Horizon: H, Join: true})
	}
	dec("K-JLK-1", nipcash.LookupInput{Now: T, Deadline: T + 1000, Join: true})
	for _, h := range []int64{60, 120, 300, 86401} {
		f.Window = append(f.Window, windowCase{h, nipcash.DeadlineWindow(h)})
	}
	for _, now := range []int64{D + H, D + H + 1} {
		f.Retained = append(f.Retained, retainedCase{now, D, H, nipcash.RecordRetained(now, D, H)})
	}
	for _, now := range []int64{T, T + 1} {
		f.Tombstone = append(f.Tombstone, retainedCase{Now: now, Until: T, Retained: nipcash.TombstoneAnswerable(now, T)})
	}
	for _, c := range []struct {
		name string
		p    nipcash.CashLookupRequest
	}{
		{"by request_id", nipcash.CashLookupRequest{RequestID: vecRID, Deadline: T}},
		{"by connection_pubkey (a join)", nipcash.CashLookupRequest{ConnectionPubkey: wdSlice, Deadline: T}},
		{"a cash-authorized call", nipcash.CashLookupRequest{RequestID: vecRID, Deadline: T, CashSecret: strings.Repeat("c1", 32)}},
		{"both keys", nipcash.CashLookupRequest{RequestID: vecRID, ConnectionPubkey: wdSlice, Deadline: T}},
		{"neither key", nipcash.CashLookupRequest{Deadline: T}},
		{"no deadline", nipcash.CashLookupRequest{RequestID: vecRID}},
		{"invalid request_id", nipcash.CashLookupRequest{RequestID: "XYZ", Deadline: T}},
	} {
		f.Params = append(f.Params, lookupParamsCase{c.name, c.p, errString(c.p.Validate())})
	}
	res := func(name, method, raw string) {
		c := lookupResultCase{Name: name, Method: method, Result: raw}
		r, err := nipcash.ParseCashLookupResult([]byte(raw))
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Status, c.Retry = string(r.Status), r.RetryAfter
			if r.Status == nipcash.LookupDone && len(r.Result) > 0 {
				var inner any
				var ierr error
				switch method {
				case nipcash.MethodCashWithdraw:
					inner, ierr = nipcash.ParsePayout(r.Result)
				default:
					if t, ok := nipcash.ParseTombstone(r.Result); ok {
						c.Gone = t
					} else {
						var m map[string]any
						ierr = json.Unmarshal(r.Result, &m)
						inner = m
					}
				}
				if g, ok := ierr.(*nipcash.BillGone); ok {
					c.Gone = &g.Tombstone
				} else if ierr != nil {
					c.Error = ierr.Error()
				} else if inner != nil {
					raw, _ := json.Marshal(inner)
					_ = json.Unmarshal(raw, &c.Inner)
				}
			}
		}
		f.Results = append(f.Results, c)
	}
	res("pending", nipcash.MethodCashTransfer, `{"status":"pending","retry_after":1720000301}`)
	res("unknown", nipcash.MethodCashTransfer, `{"status":"unknown"}`)
	res("expired", nipcash.MethodCashTransfer, `{"status":"expired"}`)
	res("done with the method's result", nipcash.MethodCashTransfer, `{"status":"done","result":{"amount_millis":21000,"identity_type":"pubkey","identity_value":"`+wdSlice+`","new_wallet_token":""}}`)
	res("done: a destroyed new bill is its tombstone in place of its token", nipcash.MethodCashTransfer, `{"status":"done","result":{"amount_millis":21000,"identity_type":"pubkey","identity_value":"`+wdSlice+`","new_wallet_token":{"status":"spent","reason":"transferred","retained_until":1722592000}}}`)
	res("done: past retained_until the tombstone carries status and reason only", nipcash.MethodMintCash, `{"status":"done","result":{"wallet_pubkey":"`+wdSlice+`","cash_token":{"status":"spent","reason":"redeemed"},"recipients":[{"identity_type":"pubkey","identity_value":"`+wdSlice+`","amount_millis":21000}]}}`)
	res("order done: the current state", "cash_order", `{"status":"done","result":{"state":"paid","order_id":"`+vecRID+`"}}`)
	payout := `{"state":"broadcast","address":"` + kAddr1 + `","amount_millis":21000000,"fee_millis":1742000,"payout_millis":19258000,"sent_by":1720003600,"final_depth":1,"signed":true,"receipt":"{}","txid":"` + strings.Repeat("ab", 32) + `","vout":0,"depth":0}`
	res("withdraw done: the current payout", nipcash.MethodCashWithdraw, `{"status":"done","result":`+payout+`}`)
	res("unknown status", nipcash.MethodCashTransfer, `{"status":"maybe"}`)
	res("pending without retry_after", nipcash.MethodCashTransfer, `{"status":"pending"}`)
	res("done without a result", nipcash.MethodCashTransfer, `{"status":"done"}`)
	res("not JSON", nipcash.MethodCashTransfer, `[`)
	for _, m := range cashMethods {
		f.AnswersTombst = append(f.AnswersTombst, methodFlag{m, nipcash.AnswersWithTombstone(m)})
	}
	return f, nil
}

// ---- mint-cash.json

type mintCashFile struct {
	header
	Commitment []commitmentCase  `json:"commitment"`
	Requests   []mintRequestCase `json:"requests"`
	Results    []mintResultCase  `json:"results"`
}

type commitmentCase struct {
	ID     string `json:"id,omitempty"`
	Secret string `json:"secret"`
	Note   string `json:"note,omitempty"`
	Commit string `json:"commit,omitempty"`
	Error  string `json:"error,omitempty"`
}

type mintRequestCase struct {
	Name    string         `json:"name"`
	Inputs  map[string]any `json:"inputs"`
	Request map[string]any `json:"request,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type mintResultCase struct {
	Name   string             `json:"name"`
	Lookup bool               `json:"lookup"`
	Result string             `json:"result"`
	Error  string             `json:"error,omitempty"`
	Gone   *nipcash.Tombstone `json:"gone,omitempty"`
	Want   map[string]any     `json:"want,omitempty"`
	Token  string             `json:"token,omitempty"`
}

func buildMintCash() (any, error) {
	f := mintCashFile{header: newHeader(
		"mint_cash: the cash commitment sha256(32 secret bytes), the request (recipients, expiry, request_id; no pairing_uri) and the result (wallet, cash_token, expires_at, recipients; a lookup may answer a tombstone).",
		"nipcash/{mint_cash,secret}.go; nipcash/mint_cash_test.go, wire_types_test.go (K-CMT-1..3)",
	)}
	for _, c := range []commitmentCase{
		{ID: "K-CMT-1", Secret: hex.EncodeToString(seq(0))},
		{ID: "K-CMT-3", Secret: strings.Repeat("00", 32)},
		{Secret: strings.ToUpper(hex.EncodeToString(seq(0)))},
		{Secret: strings.Repeat("00", 31)},
		{Secret: "zz" + strings.Repeat("00", 31)},
	} {
		c.Commit, _ = nipcash.CashCommitment(c.Secret)
		_, err := nipcash.CashCommitment(c.Secret)
		c.Error = errString(err)
		f.Commitment = append(f.Commitment, c)
	}
	neg := sha256.Sum256([]byte(hex.EncodeToString(seq(0))))
	f.Commitment = append(f.Commitment, commitmentCase{ID: "K-CMT-2", Secret: hex.EncodeToString(seq(0)), Note: "negative: sha256 of the hex text, never produced", Commit: hex.EncodeToString(neg[:])})

	user := wdSlice
	cash := must(nipcash.CashTargetFromSecret(hex.EncodeToString(seq(0))))
	ck := must(nipcash.ConnectionKey("discord", "80351110224678912", wdHub))
	req := func(name string, p nipcash.MintCashParams, inputs map[string]any) {
		c := mintRequestCase{Name: name, Inputs: inputs}
		r, err := p.Request()
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Request = flattenRequest(r)
		}
		f.Requests = append(f.Requests, c)
	}
	req("one pubkey recipient", nipcash.MintCashParams{RequestID: vecRID, Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(user), 21000)}}, map[string]any{"recipients": []any{map[string]any{"pubkey": user, "amount": 21000}}, "requestId": vecRID})
	req("pubkey and connection_key, an expiry", nipcash.MintCashParams{RequestID: vecRID, Expiry: 30 * 24 * time.Hour, Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(user), 1000), nipcash.Send(ck, 2000)}},
		map[string]any{"recipients": []any{map[string]any{"pubkey": user, "amount": 1000}, map[string]any{"discord": "80351110224678912", "ia": wdHub, "amount": 2000}}, "expirySeconds": 2592000, "requestId": vecRID})
	req("cash-mode (K-CMT-1 commitment)", nipcash.MintCashParams{RequestID: vecRID, Recipients: []nipcash.Allocation{nipcash.Send(cash, 21000)}}, map[string]any{"recipients": []any{map[string]any{"cashSecret": cash.Secret(), "amount": 21000}}, "requestId": vecRID})
	req("cash-mode beside another recipient", nipcash.MintCashParams{RequestID: vecRID, Recipients: []nipcash.Allocation{nipcash.Send(cash, 1), nipcash.Send(nipcash.Pubkey(user), 1)}}, map[string]any{"recipients": "cash + pubkey", "requestId": vecRID})
	req("no request_id", nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(user), 1)}}, map[string]any{"recipients": "pubkey"})
	req("zero amount", nipcash.MintCashParams{RequestID: vecRID, Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(user), 0)}}, map[string]any{"recipients": "pubkey 0", "requestId": vecRID})
	req("no recipient", nipcash.MintCashParams{RequestID: vecRID}, map[string]any{"requestId": vecRID})

	p := nipcash.MintCashParams{RequestID: vecRID, Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(user), 21000)}}
	res := func(name, raw string) {
		for _, lookup := range []bool{false, true} {
			c := mintResultCase{Name: name, Lookup: lookup, Result: raw}
			var r *nipcash.MintCashResult
			var err error
			if lookup {
				r, err = p.ParseLookupResult([]byte(raw))
			} else {
				r, err = p.ParseResult([]byte(raw))
			}
			if g, ok := err.(*nipcash.BillGone); ok {
				c.Gone = &g.Tombstone
			}
			c.Error = errString(err)
			if r != nil {
				rb, _ := json.Marshal(r)
				_ = json.Unmarshal(rb, &c.Want)
				c.Token = r.CashToken
				if r.TokenTombstone != nil {
					c.Gone = r.TokenTombstone
				}
			}
			f.Results = append(f.Results, c)
		}
	}
	res("minted", `{"wallet_pubkey":"`+wdBill+`","cash_token":"`+specToken+`","expires_at":1722592000,"recipients":[{"identity_type":"pubkey","identity_value":"`+user+`","amount_millis":21000}]}`)
	res("never expires", `{"wallet_pubkey":"`+wdBill+`","cash_token":"`+specToken+`","recipients":[{"identity_type":"pubkey","identity_value":"`+user+`","amount_millis":21000}]}`)
	res("a lookup's tombstone for the bill", `{"wallet_pubkey":"`+wdBill+`","cash_token":{"status":"spent","reason":"redeemed"},"recipients":[{"identity_type":"pubkey","identity_value":"`+user+`","amount_millis":21000}]}`)
	res("pairing_uri is not read", `{"wallet_pubkey":"`+wdBill+`","cash_token":"`+specToken+`","pairing_uri":"nostr+walletconnect://x","recipients":[{"identity_type":"pubkey","identity_value":"`+user+`","amount_millis":21000}]}`)
	res("no cash_token", `{"wallet_pubkey":"`+wdBill+`","recipients":[]}`)
	res("not JSON", `[`)
	return f, nil
}

// ---- budget-period.json

type budgetPeriodFile struct {
	header
	Start []budgetStartCase `json:"start"`
}

type budgetStartCase struct {
	ID      string `json:"id,omitempty"`
	Created int64  `json:"created"`
	Renewal string `json:"renewal"`
	K       int64  `json:"k"`
	Start   int64  `json:"start,omitempty"`
	Error   string `json:"error,omitempty"`
}

func buildBudgetPeriod() (any, error) {
	f := budgetPeriodFile{header: newHeader(
		"NIP-CW budget periods: the start of the k-th period of a wallet created at created, in UTC. Monthly and yearly stay anchored to the creation day, clamped to the month's last day, counted from the creation.",
		"nipcw/budget_period.go BudgetPeriodStart; nipcw/budget_period_test.go (K-BP-1..9)",
	)}
	add := func(id string, created int64, renewal string, k int64) {
		t, err := nipcw.BudgetPeriodStart(time.Unix(created, 0), renewal, k)
		c := budgetStartCase{ID: id, Created: created, Renewal: renewal, K: k, Error: errString(err)}
		if err == nil {
			c.Start = t.Unix()
		}
		f.Start = append(f.Start, c)
	}
	for k := int64(1); k <= 3; k++ {
		add("K-BP-"+strconv.FormatInt(k, 10), 1706695200, "monthly", k)
	}
	for k := int64(1); k <= 4; k++ {
		add("K-BP-"+strconv.FormatInt(k+3, 10), 1709200800, "yearly", k)
	}
	add("K-BP-8", 1706695200, "daily", 1)
	add("K-BP-9", 1706695200, "weekly", 1)
	add("", 1706695200, "monthly", 0)
	add("", 1706695200, "monthly", 12)
	add("", 1706695200, "never", 0)
	add("", 1706695200, "never", 1)
	add("", 1706695200, "", 0)
	add("", 1706695200, "monthly", -1)
	add("", 1706695200, "Monthly", 1)
	return f, nil
}

// ---- cw-fees.json

type cwFeesFile struct {
	header
	Reserve nip47.FeeReserve `json:"feeReserve"`
	FeesPpm uint64           `json:"feesPpm"`
	FeeSkim []feeCase        `json:"feeSkim"`
	Routing []feeCase        `json:"routingFeeReserve"`
	MaxCost []feeCase        `json:"maxCost"`
	SendCap []sendCapCase    `json:"sendCap"`
}

type feeCase struct {
	ID     string `json:"id,omitempty"`
	Amount uint64 `json:"amount"`
	Want   uint64 `json:"want"`
}

// sendCapCase: whether a payment fits a send cap with Used already spent:
// Used + MaxCost(Amount) <= Cap, else QUOTA_EXCEEDED.
type sendCapCase struct {
	ID      string `json:"id"`
	Used    uint64 `json:"used"`
	Cap     uint64 `json:"cap"`
	Amount  uint64 `json:"amount"`
	MaxCost uint64 `json:"maxCost"`
	Allowed bool   `json:"allowed"`
}

func buildCWFees() (any, error) {
	r := nip47.FeeReserve{Ppm: 5000, MinMillis: 10000}
	f := cwFeesFile{header: newHeader(
		"NIP-CW fees and caps: the fees_ppm skim (rounded down), the routing-fee reserve (the larger of min_millis and amount x ppm, rounded down), and the most a payment may cost (amount + skim + reserve), counted against the send cap.",
		"nipcw/fees.go FeeSkim, RoutingFeeReserve, MaxCost; nipcw/fees_test.go (K-CWFEE-1..6)",
	), Reserve: r, FeesPpm: 2500}
	for _, a := range []uint64{399, 400, 100_000_000} {
		f.FeeSkim = append(f.FeeSkim, feeCase{"K-CWFEE-1", a, nipcw.FeeSkim(a, 2500)})
	}
	for _, c := range []struct {
		id string
		a  uint64
	}{{"K-CWFEE-4", 4_962_781}, {"K-CWFEE-5", 4_962_782}, {"K-CWFEE-6", 100_000}, {"K-CWFEE-6", 1_000_000}, {"", 0}} {
		f.Routing = append(f.Routing, feeCase{c.id, c.a, nipcw.RoutingFeeReserve(c.a, r)})
	}
	for _, c := range []struct {
		id string
		a  uint64
	}{{"K-CWFEE-2", 10_000_000}, {"K-CWFEE-3", 9_900_000}, {"K-CWFEE-4", 4_962_781}, {"K-CWFEE-5", 4_962_782}, {"K-CWFEE-6", 100_000}, {"K-CWFEE-6", 1_000_000}} {
		f.MaxCost = append(f.MaxCost, feeCase{c.id, c.a, nipcw.MaxCost(c.a, 2500, r)})
	}
	for _, c := range []struct {
		id string
		a  uint64
	}{{"K-CWFEE-4", 4_962_781}, {"K-CWFEE-5", 4_962_782}} {
		mc := nipcw.MaxCost(c.a, 2500, r)
		f.SendCap = append(f.SendCap, sendCapCase{c.id, 15_000_000, 20_000_000, c.a, mc, 15_000_000+mc <= 20_000_000})
	}
	return f, nil
}

// ---- npv1.json

type npv1File struct {
	header
	Token  []npvCase       `json:"token"`
	Verify []npvVerifyCase `json:"verify"`
}

type npvCase struct {
	ID     string `json:"id,omitempty"`
	Pubkey string `json:"pubkey"`
	Code   string `json:"code"`
	Hash   string `json:"hash,omitempty"`
	Token  string `json:"token,omitempty"`
	Error  string `json:"error,omitempty"`
}

type npvVerifyCase struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Pubkey string `json:"pubkey"`
	Code   string `json:"code"`
	Error  string `json:"error,omitempty"`
}

func buildNPV1() (any, error) {
	f := npv1File{header: newHeader(
		"NIP-IC npv1 challenge tokens: TLV 0 = sha256 over the pubkey and the pre-auth code, bech32 under npv1.",
		"nipIC/challenge.go NewChallengeToken, ChallengeToken.Verify; nipIC/evaluate_test.go (K-NPV-1)",
	)}
	add := func(id, pub, code string) {
		c := npvCase{ID: id, Pubkey: pub, Code: code}
		tok, err := nipIC.NewChallengeToken(pub, code)
		c.Token, c.Error = string(tok), errString(err)
		if err == nil {
			_, data, derr := credcodec.DecodeBech32(string(tok))
			if derr == nil && len(data) == 34 {
				c.Hash = hex.EncodeToString(data[2:])
			}
		}
		f.Token = append(f.Token, c)
	}
	add("K-NPV-1", k1Pub, "123456")
	add("", k1Pub, "000000")
	add("", wdBill, "123456")
	add("", "zz", "123456")
	tok := must(nipIC.NewChallengeToken(k1Pub, "123456"))
	ver := func(name string, t nipIC.ChallengeToken, pub, code string) {
		f.Verify = append(f.Verify, npvVerifyCase{name, string(t), pub, code, errString(t.Verify(pub, code))})
	}
	ver("K-NPV-1", tok, k1Pub, "123456")
	ver("changed code", tok, k1Pub, "123456 ")
	ver("another pubkey", tok, wdBill, "123456")
	ver("uppercase token", nipIC.ChallengeToken(strings.ToUpper(string(tok))), k1Pub, "123456")
	return f, nil
}

// ---- nconnection.json

type nconnectionFile struct {
	header
	KAT    nconnectionKAT `json:"kat"`
	Decode []decodeCase   `json:"decode"`
	Encode []encodeCase   `json:"encode"`
}

type nconnectionKAT struct {
	ID     string          `json:"id"`
	Fields nconnectionJSON `json:"fields"`
	TLV    string          `json:"tlv"`
	String string          `json:"string"`
}

func buildNConnection() (any, error) {
	f := nconnectionFile{header: newHeader(
		"NIP-IC nconnection1: TLV 0 the connection key (32 bytes, exactly once), TLV 1 relays, TLV 2 the platform (at most once, a valid platform name); unknown types ignored; the strict decoder refuses an overrun.",
		"nipIC/nconnection.go; nipIC/nconnection_test.go (K-NCN-1)",
	)}
	key := wdCK1
	s, err := nipIC.EncodeNConnection(nipIC.ConnectionKey(key), []string{specRelay1}, "discord")
	if err != nil {
		return nil, err
	}
	_, data, err := credcodec.DecodeBech32(s)
	if err != nil {
		return nil, err
	}
	f.KAT = nconnectionKAT{"K-NCN-1", nconnectionJSON{key, []string{specRelay1}, "discord"}, hex.EncodeToString(data), s}
	add := func(name, input string) { f.Decode = append(f.Decode, decodeVector(name, kindNConnection, input)) }
	ck := repeat(0x44, 32)
	kb, _ := hex.DecodeString(key)
	nc := func(entries ...tlv) string { return bech32String("nconnection", entries) }
	add("K-NCN-1", s)
	add("K-NCN-1 uppercase", strings.ToUpper(s))
	add("key only", nc(tlv{0, ck}))
	add("key, relays and platform", nc(tlv{0, ck}, tlv{1, fixURL}, tlv{1, []byte("wss://r2.example")}, tlv{2, []byte("github")}))
	add("platform before key", nc(tlv{2, []byte("x")}, tlv{0, ck}))
	add("unknown types are ignored", nc(tlv{0, kb}, tlv{3, []byte("x")}, tlv{255, nil}))
	add("missing key", nc(tlv{1, fixURL}))
	add("short key", nc(tlv{0, ck[:31]}))
	add("two keys", nc(tlv{0, ck}, tlv{0, repeat(0x55, 32)}))
	add("two platforms", nc(tlv{0, ck}, tlv{2, []byte("github")}, tlv{2, []byte("x")}))
	add("platform Discord", nc(tlv{0, ck}, tlv{2, []byte("Discord")}))
	add("platform git:hub", nc(tlv{0, ck}, tlv{2, []byte("git:hub")}))
	add("blank relay", nc(tlv{0, ck}, tlv{1, []byte("")}))
	add("overrun", bech32String("nconnection", []tlv{{0, ck}}, 1, 9, 'a'))
	add("lone trailing byte", bech32String("nconnection", []tlv{{0, ck}}, 1))
	add("wrong prefix", bech32String("lokicash", []tlv{{0, ck}}))
	add("bech32m checksum", bech32mString("nconnection", []tlv{{0, ck}}))
	enc := func(name string, j nconnectionJSON) {
		f.Encode = append(f.Encode, encodeVector(name, kindNConnection, j))
	}
	h := hex.EncodeToString(ck)
	enc("K-NCN-1", nconnectionJSON{key, []string{specRelay1}, "discord"})
	enc("key only", nconnectionJSON{h, []string{}, ""})
	enc("relays and platform", nconnectionJSON{h, []string{"wss://r1.example", "wss://r2.example"}, "github"})
	enc("short key", nconnectionJSON{h[:62], []string{}, ""})
	enc("uppercase key", nconnectionJSON{strings.ToUpper(h), []string{}, ""})
	enc("platform Discord", nconnectionJSON{h, []string{}, "Discord"})
	enc("non-ASCII relay", nconnectionJSON{h, []string{"wss://ü.example"}, ""})
	return f, nil
}

// ---- pow.json

type powFile struct {
	header
	Difficulty []powDifficultyCase `json:"difficulty"`
	Rejection  []powRejectionCase  `json:"parseRejection"`
	Tags       powTagsCase         `json:"tags"`
	Validate   []powValidateCase   `json:"validate"`
	RelayRule  []powRelayCase      `json:"relayRule"`
	MaxAhead   int64               `json:"maxPowAhead"`
}

type powDifficultyCase struct {
	ID         string `json:"id,omitempty"`
	EventID    string `json:"eventId"`
	Difficulty int    `json:"difficulty"`
	Error      string `json:"error,omitempty"`
}

type powRejectionCase struct {
	ID         string `json:"id,omitempty"`
	Message    string `json:"message"`
	Difficulty int    `json:"difficulty"`
	PowRefusal bool   `json:"powRefusal"`
}

// powTagsCase: K-POW-3, the tags a request mined to Target for an envelope
// with not_after NotAfter carries, beside its p tag: an expiration equal to
// not_after and a NIP-13 nonce naming the target. Example is one such event
// mined here (a deterministic nonce search) and its nip13 check.
type powTagsCase struct {
	ID       string      `json:"id"`
	NotAfter int64       `json:"notAfter"`
	Target   int         `json:"target"`
	Shape    [][]string  `json:"shape"`
	Example  nip01.Event `json:"example"`
}

type powValidateCase struct {
	Name       string      `json:"name"`
	Event      nip01.Event `json:"event"`
	Difficulty int         `json:"difficulty"`
	Error      string      `json:"error,omitempty"`
}

// powRelayCase: K-POW-4, the PoW relay rule for a kind 23190 at Now: exactly
// one expiration, not past and at most MaxPowAhead ahead.
type powRelayCase struct {
	ID         string `json:"id"`
	Now        int64  `json:"now"`
	Expiration *int64 `json:"expiration"`
	Accepted   bool   `json:"accepted"`
}

func buildPow() (any, error) {
	f := powFile{header: newHeader(
		"Proof of work on kind 23190 requests: NIP-13 difficulty of an id, the relay's pow: refusal message, the nonce and expiration tags, and the relay rule bounding the expiration to one day ahead.",
		"nipcash/transport/pow.go, nip13/nip13.go, internal/cashtest/powrelay.go; nipcash/transport/serve_test.go (K-POW-1..3), internal/cashtest/powrelay_test.go (K-POW-4)",
	), MaxAhead: transport.MaxPowAhead}
	for _, c := range [][2]string{
		{"K-POW-1", "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358"},
		{"", strings.Repeat("0", 64)},
		{"", "8" + strings.Repeat("0", 63)},
		{"", "00ff" + strings.Repeat("0", 60)},
		{"", "zz"},
	} {
		d, err := nip13.Difficulty(c[1])
		f.Difficulty = append(f.Difficulty, powDifficultyCase{c[0], c[1], d, errString(err)})
	}
	for _, c := range [][2]string{{"K-POW-2", "pow: difficulty 20 required"}, {"", "pow: too low"}, {"", "blocked: no"}, {"", "pow:20"}, {"", "POW: difficulty 20"}, {"", ""}} {
		d, ok := transport.ParsePowRejection(c[1])
		f.Rejection = append(f.Rejection, powRejectionCase{c[0], c[1], d, ok})
	}
	const T = int64(1720000000)
	ex := nip01.Event{Kind: transport.KindPrivateRequest, PubKey: wdHub, CreatedAt: uint64(T - 3600), Content: "x",
		Tags: [][]string{{"p", wdBill}, {"expiration", strconv.FormatInt(T+60, 10)}}}
	ex = mineDeterministic(ex, 8)
	f.Tags = powTagsCase{"K-POW-3", T + 60, 20, [][]string{{"expiration", strconv.FormatInt(T+60, 10)}, {"nonce", "<n>", "20"}}, ex}
	val := func(name string, ev nip01.Event) {
		_, d, err := nip13.ValidatePow(nip13.Fields{ID: ev.ID, PubKey: ev.PubKey, CreatedAt: ev.CreatedAt, Kind: ev.Kind, Tags: ev.Tags, Content: ev.Content})
		f.Validate = append(f.Validate, powValidateCase{name, ev, d, errString(err)})
	}
	val("mined to 8", ex)
	over := ex
	over.Tags = append([][]string(nil), ex.Tags...)
	over.Tags[len(over.Tags)-1] = []string{"nonce", ex.Tags[len(ex.Tags)-1][1], "40"}
	val("declares more than the id has", over)
	moved := ex
	moved.Content = "y"
	val("content changed after mining", moved)
	none := ex
	none.Tags = ex.Tags[:2]
	val("no nonce tag", none)
	exp := func(v int64) *int64 { return &v }
	for _, c := range []struct {
		e  *int64
		ok bool
	}{{exp(T + 86400), true}, {exp(T + 86401), false}, {exp(T - 1), false}, {nil, false}, {exp(T), true}} {
		f.RelayRule = append(f.RelayRule, powRelayCase{"K-POW-4", T, c.e, c.ok})
	}
	return f, nil
}

// mineDeterministic appends a nonce tag counting up from 0 until the id
// has at least target leading zero bits, and returns the unsigned event
// with its id. nip13.Mine searches in parallel and so is not reproducible.
func mineDeterministic(ev nip01.Event, target int) nip01.Event {
	base := ev.Tags
	for n := 0; ; n++ {
		ev.Tags = append(append([][]string(nil), base...), []string{"nonce", strconv.Itoa(n), strconv.Itoa(target)})
		id, err := ev.HashID()
		if err != nil {
			panic(err)
		}
		if d, _ := nip13.Difficulty(hex.EncodeToString(id)); d >= target {
			ev.ID = hex.EncodeToString(id)
			return ev
		}
	}
}
