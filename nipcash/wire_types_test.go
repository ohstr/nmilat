package nipcash

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func u64(v uint64) *uint64 { return &v }

// T10-01..T10-05.
func TestT10_01_MintRequest(t *testing.T) {
	pk := Pubkey(strings.Repeat("a", 64))
	if _, err := (MintCashParams{Recipients: []Allocation{Send(pk, 1)}}).Request(); !errors.Is(err, ErrRequestIDRequired) {
		t.Errorf("mint without request_id: %v", err)
	}
	if _, err := (CashTransferParams{Credential: BySecret(strings.Repeat("1", 64)), To: pk, CurrentAmount: 1}).Request(strings.Repeat("b", 64)); !errors.Is(err, ErrRequestIDRequired) {
		t.Errorf("transfer without request_id: %v", err)
	}
	if _, err := (CashConsolidateParams{To: pk}).Request(); !errors.Is(err, ErrRequestIDRequired) {
		t.Errorf("consolidate without request_id: %v", err)
	}
	req, err := (MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(pk, 1)}}).Request()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(req)
	for _, k := range []string{"idempotency_key", "min_transfer_millis", "cash_secret"} {
		if strings.Contains(string(b), k) {
			t.Errorf("%s in %s", k, b)
		}
	}
	if !strings.Contains(string(b), `"request_id":"`+testRID+`"`) {
		t.Errorf("no request_id: %s", b)
	}
	big := uint64(9223372036854775808)
	for name, tc := range map[string]struct {
		r    []Allocation
		want error
	}{
		"none":     {nil, ErrNoRecipients},
		"zero":     {[]Allocation{Send(pk, 0)}, ErrZeroAmount},
		"overflow": {[]Allocation{Send(pk, big), Send(Pubkey(strings.Repeat("c", 64)), big)}, ErrAmountOverflow},
		"dup":      {[]Allocation{Send(pk, 1), Send(pk, 2)}, ErrDuplicateRecipient},
		"cash+pk":  {[]Allocation{Send(mustCashTarget(t), 1), Send(pk, 1)}, ErrMixedCashAllocation},
		"two cash": {[]Allocation{Send(mustCashTarget(t), 1), Send(mustCashTarget(t), 1)}, ErrMixedCashAllocation},
		"ck no ia": {[]Allocation{Send(attestedKey(t, "discord", "u", ""), 1)}, ErrMissingIAPubkey},
	} {
		if _, err := (MintCashParams{RequestID: testRID, Recipients: tc.r}).Request(); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

// T10-06.
func TestT10_06_MintParseResult(t *testing.T) {
	ct := mustCashTarget(t)
	p := MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(ct, 21000)}}
	body := func(token, extra string) []byte {
		return []byte(`{"wallet_pubkey":"` + ktokWallet + `","cash_token":` + token + extra + `,"recipients":[{"identity_type":"cash","identity_value":"` + ct.Commitment() + `","amount_millis":21000}]}`)
	}
	r, err := p.ParseResult(body(`"`+ktok1+`"`, `,"pairing_uri":"nostr+walletconnect://x"`))
	if err != nil || r.CashToken != ktok1 || !r.ExpiresAt.Never() {
		t.Fatalf("good: %+v %v", r, err)
	}
	for _, exp := range []string{`,"expires_at":null`, `,"expires_at":0`} {
		if r, _ := p.ParseResult(body(`"`+ktok1+`"`, exp)); !r.ExpiresAt.Never() {
			t.Errorf("%s not never", exp)
		}
	}
	if r, err := p.ParseResult(body(`""`, "")); !errors.Is(err, ErrEmptyToken) || r == nil {
		t.Errorf("empty token: %v (result kept: %v)", err, r != nil)
	}
	if _, err := p.ParseResult(body(`"`+ktok1+`"`, `,"x":{"cash_secret":"s"}`)); !errors.Is(err, ErrHubReturnedSecret) {
		t.Errorf("cash_secret: %v", err)
	}
	other := MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(mustCashTarget(t), 21000)}}
	if _, err := other.ParseResult(body(`"`+ktok1+`"`, "")); !errors.Is(err, ErrCommitmentEcho) {
		t.Errorf("echo: %v", err)
	}
	if _, err := p.ParseResult(body(`{"status":"spent","reason":"redeemed"}`, "")); !errors.Is(err, ErrTombstoneInReply) {
		t.Errorf("tombstone in a direct reply: %v", err)
	}
	if r, err := p.ParseLookupResult(body(`{"status":"spent","reason":"redeemed"}`, "")); err != nil || r.TokenTombstone == nil || r.WalletPubkey != ktokWallet {
		t.Errorf("tombstone in a lookup: %+v %v", r, err)
	}
}

// T10-07..T10-10, T10-33.
func TestT10_07_TransferRequest(t *testing.T) {
	wallet := strings.Repeat("b", 64)
	priv, _ := generateTestKeypair(t)
	pk := Pubkey(strings.Repeat("a", 64))
	cashSrc := mustCashTarget(t)
	iaPriv, _ := generateTestKeypair(t)
	userPriv, userPub := generateTestKeypair(t)
	ck := mustConnCred(t, userPriv, buildTestAttestation(t, iaPriv, userPub, testDiscordKey(t), 1))
	base := func() CashTransferParams {
		return CashTransferParams{RequestID: testRID, Credential: BySigning(priv), To: pk, CurrentAmount: 5000}
	}
	for name, tc := range map[string]struct {
		edit func(*CashTransferParams)
		want error
	}{
		"zap cash source": {func(p *CashTransferParams) { p.ZapTarget, p.Credential = "e", BySecret(cashSrc.Secret()) }, ErrZapCashSource},
		"zap ck source":   {func(p *CashTransferParams) { p.ZapTarget, p.Credential = "e", ck }, ErrZapCKSource},
		"zap cash target": {func(p *CashTransferParams) { p.ZapTarget, p.To = "e", mustCashTarget(t) }, ErrZapTargetIdentity},
		"zap ck target": {func(p *CashTransferParams) {
			p.ZapTarget, p.To = "e", attestedKey(t, "discord", "u", strings.Repeat("c", 64))
		}, ErrZapTargetIdentity},
		"split 0":           {func(p *CashTransferParams) { p.SplitAmount = u64(0) }, ErrSplitAmount},
		"split too big":     {func(p *CashTransferParams) { p.SplitAmount = u64(5001) }, ErrSplitAmount},
		"cash split no rem": {func(p *CashTransferParams) { p.Credential, p.SplitAmount = BySecret(cashSrc.Secret()), u64(1000) }, ErrRemainderCommitment},
		"cash split same rem": {func(p *CashTransferParams) {
			p.Credential, p.SplitAmount, p.RemainderTarget = BySecret(cashSrc.Secret()), u64(1000), cashSrc
		}, ErrRemainderCommitment},
		"rem on pubkey": {func(p *CashTransferParams) { p.SplitAmount, p.RemainderTarget = u64(1000), mustCashTarget(t) }, ErrRemainderCommitment},
		"rem on full": {func(p *CashTransferParams) {
			p.Credential, p.RemainderTarget = BySecret(cashSrc.Secret()), mustCashTarget(t)
		}, ErrRemainderCommitment},
	} {
		p := base()
		tc.edit(&p)
		if _, err := p.Request(wallet); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	p := base()
	p.Credential, p.SplitAmount, p.RemainderTarget = BySecret(cashSrc.Secret()), u64(1000), mustCashTarget(t)
	req, err := p.Request(wallet)
	if err != nil || req.RemainderCommitment != p.RemainderTarget.Commitment() {
		t.Fatalf("cash split: %+v %v", req, err)
	}
	cashTo := mustCashTarget(t)
	p = base()
	p.To = cashTo
	req, _ = p.Request(wallet)
	if req.NewIdentity.IdentityValue != cashTo.Commitment() || req.NewIdentity.IAPubkey != "" || req.ZapTarget != nil {
		t.Errorf("cash To: %+v", req.NewIdentity)
	}
	p = base()
	p.ZapTarget = "30023:x:y"
	if req, _ := p.Request(wallet); req.ZapTarget == nil || *req.ZapTarget != "30023:x:y" {
		t.Error("zap_target not sent")
	}
	if _, err := (&CashTransferResult{NewWalletPubkey: "x"}).RecipientToken("orig"); err == nil {
		t.Error("a spin-off without a token gave a token")
	}
}

// T10-11, T10-13, T10-14, T10-22, T10-23.
func TestT10_11_TransferResults(t *testing.T) {
	p := CashTransferParams{RequestID: testRID, Credential: BySecret(strings.Repeat("1", 64)), To: Pubkey(strings.Repeat("a", 64)), CurrentAmount: 5}
	inPlace, err := p.ParseResult([]byte(`{"amount_millis":5,"identity_type":"pubkey","identity_value":"x"}`))
	if err != nil || inPlace.NewWalletToken != "" {
		t.Fatalf("in place: %+v %v", inPlace, err)
	}
	zap, err := p.ParseResult([]byte(`{"amount_millis":5,"identity_type":"pubkey","new_wallet_pubkey":"w","new_wallet_token":"tok","issued_at":1720000000,"expires_at":0}`))
	if err != nil || !zap.ZapSigned() || *zap.ExpiresAt != 0 || zap.NewWalletToken != "tok" {
		t.Fatalf("zap: %+v %v", zap, err)
	}
	noIssued, err := p.ParseResult([]byte(`{"amount_millis":5,"new_wallet_pubkey":"w","new_wallet_token":"tok"}`))
	if err != nil || noIssued.ZapSigned() || noIssued.NewWalletToken != "tok" {
		t.Errorf("zap without issued_at: %+v %v", noIssued, err)
	}
	split, err := p.ParseResult([]byte(`{"amount_millis":2,"remaining_amount_millis":3,"new_wallet_pubkey":"w","new_wallet_token":"a","remainder_wallet_pubkey":"r","remainder_wallet_token":"b"}`))
	if err != nil || *split.RemainingAmountMillis != 3 || split.RemainderWalletToken != "b" {
		t.Errorf("split: %+v %v", split, err)
	}
	for _, raw := range []string{`{"amount_millis":5,"cash_secret":"x"}`, `{"amount_millis":5,"secret":"x"}`} {
		if _, err := p.ParseResult([]byte(raw)); !errors.Is(err, ErrHubReturnedSecret) {
			t.Errorf("%s: %v", raw, err)
		}
	}
	var gone *BillGone
	if _, err := p.ParseResult([]byte(`{"status":"spent","reason":"transferred","retained_until":9}`)); !errors.As(err, &gone) || gone.Tombstone.Reason != ReasonTransferred {
		t.Errorf("tombstone: %v", err)
	}
	tombTok := `{"amount_millis":2,"new_wallet_pubkey":"w","new_wallet_token":{"status":"spent","reason":"redeemed"},"remainder_wallet_pubkey":"r","remainder_wallet_token":{"status":"spent"}}`
	if _, err := p.ParseResult([]byte(tombTok)); !errors.Is(err, ErrTombstoneInReply) {
		t.Errorf("tombstone in a direct reply: %v", err)
	}
	r, err := p.ParseLookupResult([]byte(tombTok))
	if err != nil || r.NewWalletTombstone == nil || r.RemainderWalletTombstone == nil || r.NewWalletPubkey != "w" {
		t.Errorf("lookup: %+v %v", r, err)
	}
	if _, err := ParseCashRedeemResult([]byte(`{"status":"spent","reason":"redeemed"}`)); !errors.As(err, &gone) {
		t.Errorf("redeem tombstone: %v", err)
	}
	cp := CashConsolidateParams{RequestID: testRID, To: mustCashTarget(t)}
	if _, err := cp.ParseResult([]byte(`{"status":"spent"}`)); !errors.As(err, &gone) {
		t.Errorf("consolidate tombstone: %v", err)
	}
}

// T10-15, T10-16.
func TestT10_15_ConsolidateItem(t *testing.T) {
	privA, pubA := generateTestKeypair(t)
	privB, _ := generateTestKeypair(t)
	wA, wB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	p := CashConsolidateParams{RequestID: testRID, To: Pubkey(strings.Repeat("c", 64)),
		Sources: []Source{From(wA, 3000, BySigning(privA)), From(wB, 4000, BySigning(privB))}}
	b := ItemBinding{HubXOnly: strings.Repeat("d", 64), Nonce: strings.Repeat("e", 64), NotAfter: 1}
	item, err := p.Item("1", wA, connSecretFor(wA), b)
	if err != nil {
		t.Fatal(err)
	}
	var ev struct {
		PubKey string `json:"pubkey"`
	}
	_ = json.Unmarshal(item.Proof, &ev)
	if ev.PubKey != pubA {
		t.Errorf("item proof signed by %s, want Sources[0]'s key", ev.PubKey)
	}
	if _, err := p.Item("1", wB, connSecretFor(wB), b); !errors.Is(err, ErrConsolidateTarget) {
		t.Errorf("target not Sources[0]: %v", err)
	}
	req, _ := p.Request()
	sh, _ := SourcesHash([]string{wA, wB})
	for i, src := range req.Sources {
		var e struct {
			Tags [][]string `json:"tags"`
		}
		_ = json.Unmarshal([]byte(src.IdentityEvent), &e)
		tags := map[string]string{}
		for _, tag := range e.Tags {
			tags[tag[0]] = tag[1]
		}
		want := []string{"3000", "4000"}[i]
		if tags["s"] != sh || tags["m"] != MethodCashConsolidate || tags["amount_millis"] != want {
			t.Errorf("source %d tags %v", i, tags)
		}
	}
	short := CashConsolidateParams{RequestID: testRID, To: Pubkey(strings.Repeat("c", 64)), Sources: p.Sources[:1]}
	if _, err := short.Request(); !errors.Is(err, ErrTooFewSources) {
		t.Errorf("one source: %v", err)
	}
	cashSrc := CashConsolidateParams{RequestID: testRID, To: Pubkey(strings.Repeat("c", 64)),
		Sources: []Source{From(wA, 1, BySecret(strings.Repeat("1", 64))), From(wB, 1, BySigning(privB))}}
	if _, err := cashSrc.Request(); !errors.Is(err, ErrCashSource) {
		t.Errorf("cash source: %v", err)
	}
}

// T10-18, T10-21, T10-35, T10-36, T10-38.
func TestT10_21_ScopesTombstonesOrdered(t *testing.T) {
	for _, s := range []string{"", "mine", "all"} {
		if !IsValidCashStatusScope(s) {
			t.Errorf("%q", s)
		}
	}
	if IsValidCashStatusScope("everyone") {
		t.Error("everyone")
	}
	for _, r := range []string{"redeemed", "transferred", "consolidated", "expired", "reclaimed"} {
		if tb, ok := ParseTombstone([]byte(`{"status":"spent","reason":"` + r + `"}`)); !ok || tb.Reason != r {
			t.Errorf("%s", r)
		}
		if TombstoneReason(r) != r {
			t.Errorf("TombstoneReason(%s)", r)
		}
	}
	if tb, ok := ParseTombstone([]byte(`{"status":"spent","reason":"burned"}`)); !ok || tb.Reason != "" {
		t.Error("burned")
	}
	if TombstoneReason("written-off") != "" {
		t.Error("written-off")
	}
	enc, _ := json.Marshal(Tombstone{Status: StatusSpent, Reason: TombstoneReason("written-off")})
	if strings.Contains(string(enc), "reason") {
		t.Errorf("written-off encodes a reason: %s", enc)
	}
	tb, ok := ParseTombstone([]byte(`{"status":"spent","reason":"transferred","withdraw_request_id":"` + testRID + `"}`))
	if !ok || tb.WithdrawRequestID != testRID || tb.Reason != ReasonTransferred {
		t.Errorf("withdraw tombstone: %+v", tb)
	}
	for in, want := range map[string][2]bool{"": {false, false}, "f": {false, false}, "ff": {false, false},
		"t": {true, false}, "tt": {true, false}, "tf": {false, true}} {
		var flags []bool
		for _, c := range in {
			flags = append(flags, c == 't')
		}
		o, m := OrderedResult(flags)
		if o != want[0] || m != want[1] {
			t.Errorf("OrderedResult(%q) = %v %v", in, o, m)
		}
	}
}

// T10-24, T10-25.
func TestT10_24_Lookup(t *testing.T) {
	pk := strings.Repeat("a", 64)
	for name, r := range map[string]CashLookupRequest{
		"both":                {RequestID: testRID, ConnectionPubkey: pk, Deadline: 1},
		"neither":             {Deadline: 1},
		"no deadline":         {RequestID: testRID},
		"negative deadline":   {RequestID: testRID, Deadline: -1},
		"secret with joinkey": {ConnectionPubkey: pk, Deadline: 1, CashSecret: strings.Repeat("1", 64)},
	} {
		if r.Validate() == nil {
			t.Errorf("%s validated", name)
		}
	}
	if (CashLookupRequest{RequestID: testRID, Deadline: 1}).Validate() != nil {
		t.Error("a good lookup refused")
	}
	for _, raw := range []string{`{"status":"maybe"}`, `{"status":"done"}`, `{"status":"pending"}`, `{"status":"unknown","result":{}}`} {
		if _, err := ParseCashLookupResult([]byte(raw)); !errors.Is(err, ErrLookupMalformed) {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for raw, want := range map[string]LookupStatus{`{"status":"done","result":{}}`: LookupDone, `{"status":"pending","retry_after":5}`: LookupPending,
		`{"status":"unknown"}`: LookupUnknown, `{"status":"expired"}`: LookupExpired} {
		if r, err := ParseCashLookupResult([]byte(raw)); err != nil || r.Status != want {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

// T10-26 (K-FEE-1..6), T10-28, T10-63.
func TestT10_26_Fees(t *testing.T) {
	for _, tc := range [][5]uint64{{5000, 100, 10000, 150, 4850}, {1000, 0, 3333, 3, 997}, {1000, 0, 1000000, 1000, 0},
		{100, 100, 0, 100, 0}, {99, 100, 0, 99, 0}, {21000, 0, 10000, 210, 20790}} {
		fee, net, err := RedeemFee(tc[0], tc[1], tc[2])
		if err != nil || fee != tc[3] || net != tc[4] {
			t.Errorf("RedeemFee%v = %d %d %v", tc[:3], fee, net, err)
		}
	}
	if _, _, err := RedeemFee(1, 0, 1000001); !errors.Is(err, ErrFeeRate) {
		t.Error("K-FEE-6")
	}
	inv := func(v uint64) *uint64 { return &v }
	if _, c := RequiredInvoiceAmount(5000, 150, false, inv(4850), inv(4850)); c.Code != ErrCodeBadRequest {
		t.Error("amount on an amount invoice")
	}
	if _, c := RequiredInvoiceAmount(5000, 150, false, inv(4850), nil); c.Code != "" {
		t.Error("exact amount refused")
	}
	if _, c := RequiredInvoiceAmount(5000, 150, false, nil, nil); c.Code != ErrCodeBadRequest {
		t.Error("amountless without amount")
	}
	if _, c := RequiredInvoiceAmount(99, 99, false, inv(1), nil); c.Code != ErrCodeRestricted {
		t.Error("zero payout")
	}
	if req, c := RequiredInvoiceAmount(5000, 150, true, inv(5000), nil); c.Code != "" || req != 5000 {
		t.Error("same-node")
	}
	row := RecipientStatus{AmountMillis: 5000, NetRedeemableMillis: 4850}
	if m, same := RedeemInvoiceMillis(row, "02"+k1Pub, k1Pub); !same || m != 5000 {
		t.Error("same-node payee")
	}
	if m, same := RedeemInvoiceMillis(row, strings.Repeat("e", 64), k1Pub); same || m != 4850 {
		t.Error("external payee")
	}
}

// T10-29..T10-32 (K-CMT-1..3).
func TestT10_29_Secrets(t *testing.T) {
	if c, _ := CashCommitment(secret0to1f()); c != "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd" {
		t.Errorf("K-CMT-1 %s", c)
	}
	if c, _ := CashCommitment(strings.Repeat("0", 64)); c != "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925" {
		t.Errorf("K-CMT-3 %s", c)
	}
	if c, _ := CashCommitment(secret0to1f()); c == "6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b" {
		t.Error("K-CMT-2: hashed the hex text")
	}
	for _, s := range []string{strings.Repeat("a", 63), strings.Repeat("A", 64), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="} {
		if ValidCashSecret(s) {
			t.Errorf("%q valid", s)
		}
	}
	a := strings.Repeat("ab", 32)
	for _, n := range []int{0, 16, 31} {
		b := a[:n*2] + strings.Repeat("cd", 32-n)
		if CommitmentsEqual(a, b) {
			t.Errorf("%d matching bytes compared equal", n)
		}
	}
	if !CommitmentsEqual(a, a) {
		t.Error("equal commitments")
	}
	saved := randReader
	randReader = io.LimitReader(bytes.NewReader(nil), 0)
	defer func() { randReader = saved }()
	if _, err := NewCashTarget(); err == nil {
		t.Error("a failing reader gave a target")
	}
}

// T10-37.
func TestT10_37_WithdrawTerms(t *testing.T) {
	r, err := ParseCashStatusResult([]byte(`{"recipients":[],"withdraw":{"withdraw_fee_base":1,"withdraw_fee_ppm":2,"script_types":[[0,20],[0,32],[1,32]],"final_depth":6}}`))
	if err != nil || r.Withdraw == nil || r.Withdraw.MinMillis != nil || r.Withdraw.FinalDepth != 6 {
		t.Fatalf("%+v %v", r, err)
	}
	for name, w := range map[string]WithdrawTerms{
		"ppm":     {FeePpm: 1000001, FinalDepth: 1},
		"min>max": {MinMillis: u64(2), MaxMillis: u64(1), FinalDepth: 1},
		"0,21":    {ScriptTypes: [][2]int{{0, 21}}, FinalDepth: 1},
		"17,32":   {ScriptTypes: [][2]int{{17, 32}}, FinalDepth: 1},
		"1,41":    {ScriptTypes: [][2]int{{1, 41}}, FinalDepth: 1},
		"depth0":  {},
	} {
		if w.Validate() == nil {
			t.Errorf("%s validated", name)
		}
	}
	if r, _ := ParseCashStatusResult([]byte(`{"recipients":[]}`)); r.Withdraw != nil {
		t.Error("withdraw without the object")
	}
}

// T10-60.
func TestT10_60_RedeemResult(t *testing.T) {
	if r, err := ParseCashRedeemResult([]byte(`{"preimage":"` + strings.Repeat("a", 64) + `","fees_paid":150}`)); err != nil || r.FeesPaid != 150 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, raw := range []string{`{"preimage":"` + strings.Repeat("A", 64) + `","fees_paid":1}`, `{"preimage":"` + strings.Repeat("a", 63) + `","fees_paid":1}`,
		`{"fees_paid":1}`, `{"preimage":"` + strings.Repeat("a", 64) + `","fees_paid":-1}`, `{"preimage":"` + strings.Repeat("a", 64) + `","fees_paid":"1"}`} {
		if _, err := ParseCashRedeemResult([]byte(raw)); err == nil {
			t.Errorf("%s parsed", raw)
		}
	}
}

// F-LK-1: an unknown status is never unknown.
func FuzzParseCashLookupResult(f *testing.F) {
	f.Add([]byte(`{"status":"unknown"}`))
	f.Add([]byte(`{"status":"Unknown"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseCashLookupResult(data)
		if err != nil {
			return
		}
		switch r.Status {
		case LookupDone, LookupPending, LookupUnknown, LookupExpired:
		default:
			t.Fatalf("status %q accepted", r.Status)
		}
	})
}
