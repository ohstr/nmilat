package nipCO

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/utils"
)

// T20-05: the buyer key (K-BK-1), the unusable branch, the generators.
func TestT20_05_BuyerKey(t *testing.T) {
	sk, pk, err := BuyerKeyFromSecret(secret0to1f())
	if err != nil {
		t.Fatal(err)
	}
	if sk != "c853759de7b777f3588569e48461ec8ad52dbea4c8829b759a05e352cf649dea" ||
		pk != "a5a70781e66224a1a4e26614b36328c1a8913f1a2c80bca00fbb2e5af993c8a3" {
		t.Fatalf("K-BK-1: %s %s", sk, pk)
	}
	var zero [32]byte
	if _, _, err := buyerKeyFromDigest(zero); !errors.Is(err, ErrBuyerKeyUnusable) {
		t.Errorf("digest 0: %v", err)
	}
	var n [32]byte
	order := secp256k1.S256().N.Bytes()
	copy(n[32-len(order):], order)
	if _, _, err := buyerKeyFromDigest(n); !errors.Is(err, ErrBuyerKeyUnusable) {
		t.Errorf("digest n: %v", err)
	}
	if _, _, err := BuyerKeyFromSecret("XYZ"); err == nil {
		t.Error("bad secret accepted")
	}
	target, err := NewCashOrderTarget()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := BuyerKeyFromSecret(target.Secret()); err != nil {
		t.Errorf("NewCashOrderTarget: %v", err)
	}
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		sk, pk, err := NewBuyerKey()
		if err != nil || seen[sk] || len(pk) != 64 {
			t.Fatalf("NewBuyerKey draw %d: %v", i, err)
		}
		seen[sk] = true
	}
	notify, err := NewNotify()
	if err != nil || !ValidNotify(notify) {
		t.Fatalf("NewNotify = %q %v", notify, err)
	}
	// The derivation is over the label and the 32 raw bytes.
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	d := sha256.Sum256(append([]byte("cash-order-key:v1"), raw...))
	if got, _, _ := buyerKeyFromDigest(d); got != sk0(t) {
		t.Errorf("derivation %s", got)
	}
}

func sk0(t *testing.T) string {
	t.Helper()
	sk, _, _ := BuyerKeyFromSecret(secret0to1f())
	return sk
}

// mintToken is a bill token signed by key1 (TLV 4 of K-CO-1).
func mintToken(t *testing.T, amount uint64) (wallet, token string) {
	t.Helper()
	_, wallet = keypairHex(t)
	sec, _ := keypairHex(t)
	tok := nipcash.Token{HRP: "satscash", WalletPubkey: wallet, Secret: sec, RelayURLs: []string{"wss://relay.example.com"},
		AttestedAmountMillis: &amount}
	sign, err := nipcash.LocalMintSigner(key1, "satscash")
	if err != nil {
		t.Fatal(err)
	}
	tok, err = nipcash.SignToken(tok, nipcash.SchemeMintV1, nil, kcoIdentity, sign)
	if err != nil {
		t.Fatal(err)
	}
	s, err := nipcash.Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	return wallet, s
}

func keypairHex(t *testing.T) (string, string) {
	t.Helper()
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv := hex.EncodeToString(k.Serialize())
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// T20-11: ParseLookupResult.
func TestT20_11_ParseLookupResult(t *testing.T) {
	p, _ := cashParams(t)
	ln := `{"state":"open","payment":"lightning","amount_millis":21000000,"fee_millis":22000,"pay_millis":21022000,` +
		`"invoice":"lnbc210220n1...","pay_by":1720003600,"bills":[]}`
	o, err := p.ParseLookupResult([]byte(ln))
	if err != nil || o.State != OrderOpen || o.Invoice == "" || o.PayMillis != 21_022_000 {
		t.Fatalf("Lightning reply: %+v %v", o, err)
	}
	if o, err := p.ParseResult([]byte(ln)); err != nil || o.TermsChanged {
		t.Fatalf("ParseResult: %v", err)
	}
	wallet, tok := mintToken(t, 21_000_000)
	on := Order{State: OrderMinted, Payment: PaymentOnchain, AmountMillis: 21_000_000, FeeMillis: 63_000, PayMillis: 21_063_000,
		Address: "bc1qexample", Confirmations: 1, PayBy: 1720003600,
		Bills: []OrderBill{{WalletPubkey: wallet, Token: nipcash.TokenOrTombstone{Token: tok}, AmountMillis: 21_000_000,
			PaidMillis: 21_063_000, Outpoint: strings.Repeat("ab", 32) + ":0"}}}
	pon := p
	pon.Payment = PaymentOnchain
	raw, _ := json.Marshal(on)
	got, err := pon.ParseLookupResult(raw)
	if err != nil || got.State != OrderMinted || len(got.Bills) != 1 || got.Bills[0].Token.Token != tok || got.Confirmations != 1 {
		t.Fatalf("on-chain: %+v %v", got, err)
	}
	if _, err := pon.ParseResult(raw); !errors.Is(err, ErrOrderReply) {
		t.Errorf("a minted direct reply: %v", err)
	}
	ret := int64(1720000000)
	tomb := on
	tomb.Bills = []OrderBill{on.Bills[0]}
	tomb.Bills[0].Token = nipcash.TokenOrTombstone{Tombstone: &nipcash.Tombstone{Status: "spent", Reason: "redeemed", RetainedUntil: &ret}}
	raw, _ = json.Marshal(tomb)
	if got, err := pon.ParseLookupResult(raw); err != nil || got.Bills[0].Token.Tombstone == nil {
		t.Fatalf("tombstone: %+v %v", got, err)
	}
	mut := func(f func(map[string]any)) []byte {
		var m map[string]any
		raw, _ := json.Marshal(on)
		_ = json.Unmarshal(raw, &m)
		f(m)
		out, _ := json.Marshal(m)
		return out
	}
	for name, data := range map[string][]byte{
		"invoice and address": mut(func(m map[string]any) { m["invoice"] = "lnbc1" }),
		"unknown state":       mut(func(m map[string]any) { m["state"] = "unknown" }),
		"pay mismatch":        mut(func(m map[string]any) { m["pay_millis"] = 21_063_001 }),
		"no confirmations":    mut(func(m map[string]any) { delete(m, "confirmations") }),
		"cash_secret":         mut(func(m map[string]any) { m["cash_secret"] = secret0to1f() }),
		"bad token":           mut(func(m map[string]any) { m["bills"].([]any)[0].(map[string]any)["cash_token"] = "satscash1xyz" }),
		"no outpoint":         mut(func(m map[string]any) { delete(m["bills"].([]any)[0].(map[string]any), "outpoint") }),
	} {
		if _, err := pon.ParseLookupResult(data); !errors.Is(err, ErrOrderReply) {
			t.Errorf("%s: %v", name, err)
		}
	}
	lnBill := strings.Replace(ln, `"bills":[]`, `"bills":[{"wallet_pubkey":"`+wallet+`","cash_token":"`+tok+
		`","amount_millis":21000000,"paid_millis":21022000,"outpoint":"`+strings.Repeat("ab", 32)+`:0"}]`, 1)
	if _, err := p.ParseLookupResult([]byte(lnBill)); !errors.Is(err, ErrOrderReply) {
		t.Errorf("outpoint on a Lightning bill: %v", err)
	}
}

// T20-13: OrderStateAt.
func TestT20_13_OrderStateAt(t *testing.T) {
	const payBy = 1000
	for _, c := range []struct {
		payment  string
		now      int64
		seen     bool
		unminted int
		minted   int
		want     OrderState
	}{
		{PaymentLightning, payBy, false, 0, 0, OrderOpen},
		{PaymentLightning, payBy, true, 1, 0, OrderPaid},
		{PaymentLightning, payBy, true, 0, 1, OrderMinted},
		{PaymentOnchain, payBy, false, 0, 0, OrderOpen},
		{PaymentOnchain, payBy, true, 1, 0, OrderPaid},
		{PaymentOnchain, payBy, true, 0, 1, OrderMinted},
		{PaymentOnchain, payBy, true, 1, 1, OrderPaid},
		{PaymentLightning, payBy + 1, false, 0, 0, OrderExpired},
		{PaymentLightning, payBy + 1, true, 1, 0, OrderPaid},
		{PaymentLightning, payBy + 1, true, 0, 1, OrderMinted},
		{PaymentOnchain, payBy + 1, false, 0, 0, OrderExpired},
		{PaymentOnchain, payBy + 1, true, 1, 0, OrderClosed},
		{PaymentOnchain, payBy + 1, true, 0, 1, OrderClosed},
	} {
		f := OrderFacts{Payment: c.payment, PayBy: payBy, Seen: c.seen, Unminted: c.unminted, Minted: c.minted}
		if got := OrderStateAt(f, c.now); got != c.want {
			t.Errorf("%+v at %d = %s, want %s", f, c.now, got, c.want)
		}
	}
}

// T20-14, T20-15: retention, the used mark, the unpaid on-chain deletion.
func TestT20_14_15_Retention(t *testing.T) {
	const P, D, H = 1000, 900, 300 // D+H = 1200
	r := OrderRetention{Payment: PaymentLightning, PayBy: P, Deadline: D, Horizon: H}
	for _, c := range []struct {
		name string
		r    OrderRetention
		now  int64
		want bool
	}{
		{"open", r, P, true},
		{"D+H", r, D + H, true},
		{"unpaid Lightning past both", r, D + H + 1, false},
		{"Lightning live bill", func() OrderRetention { x := r; x.BillLiveOrTombstoned = true; return x }(), 1e9, true},
		{"on-chain seen watched", OrderRetention{Payment: PaymentOnchain, PayBy: P, Deadline: D, Horizon: H, Seen: true, Watched: true}, 1e9, true},
		{"on-chain seen unwatched", OrderRetention{Payment: PaymentOnchain, PayBy: P, Deadline: D, Horizon: H, Seen: true}, 1e9, false},
	} {
		if got := OrderRetained(c.r, c.now); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if UsedMarkDroppable(D, H, D+H, false) || !UsedMarkDroppable(D, H, D+H+1, false) || UsedMarkDroppable(D, H, D+H+1, true) {
		t.Error("UsedMarkDroppable")
	}
	if got := UnpaidOnchainDeleteAt(2000, D, H); got != 2000 {
		t.Errorf("P > D+H: %d", got)
	}
	if got := UnpaidOnchainDeleteAt(1000, D, H); got != D+H {
		t.Errorf("P < D+H: %d", got)
	}
}

// T20-23: OrderBlocksHubDelete and OrderHubDeleteAt.
func TestT20_23_HubDelete(t *testing.T) {
	const P, D, H = 1000, 900, 300
	on := OrderRetention{Payment: PaymentOnchain, PayBy: P, Deadline: D, Horizon: H, Seen: true, Watched: true}
	late := int64(D + H + 1)
	none := UnmintedPayments{}
	if OrderBlocksHubDelete(on, none, late) || !OrderRetained(on, late) {
		t.Error("watch-only on-chain order blocks")
	}
	if !OrderBlocksHubDelete(on, none, D+H) || !OrderBlocksHubDelete(on, none, P) {
		t.Error("inside D+H or pay_by")
	}
	ln := OrderRetention{Payment: PaymentLightning, PayBy: P, Deadline: D, Horizon: H, BillLiveOrTombstoned: true}
	if !OrderBlocksHubDelete(ln, none, 1e9) {
		t.Error("Lightning live bill")
	}
	ln.BillLiveOrTombstoned = false
	if OrderBlocksHubDelete(ln, none, late) {
		t.Error("Lightning after the tombstone window")
	}
	u := UnmintedPayments{Unconfirmed: 1, LastSeenAt: 5000, MaxWait: 100}
	if !OrderBlocksHubDelete(on, u, 5100) || OrderBlocksHubDelete(on, u, 5101) {
		t.Error("unconfirmed max wait")
	}
	if !OrderBlocksHubDelete(on, UnmintedPayments{Confirmed: 1}, 1e12) {
		t.Error("confirmed blocks")
	}
	for now := int64(0); now < 6000; now += 37 {
		for _, uu := range []UnmintedPayments{none, u} {
			if !OrderRetained(ln, now) && uu == none && OrderBlocksHubDelete(ln, uu, now) {
				t.Fatalf("blocks where not retained at %d", now)
			}
		}
	}
	at, ok := OrderHubDeleteAt(on, u)
	if !ok || at != 5101 || OrderBlocksHubDelete(on, u, at) || !OrderBlocksHubDelete(on, u, at-1) {
		t.Errorf("OrderHubDeleteAt unconfirmed = %d %v", at, ok)
	}
	at, ok = OrderHubDeleteAt(on, none)
	if !ok || at != D+H+1 || OrderBlocksHubDelete(on, none, at) || !OrderBlocksHubDelete(on, none, at-1) {
		t.Errorf("OrderHubDeleteAt = %d %v", at, ok)
	}
	if _, ok := OrderHubDeleteAt(on, UnmintedPayments{Confirmed: 1}); ok {
		t.Error("confirmed: ok")
	}
	if _, ok := OrderHubDeleteAt(OrderRetention{Payment: PaymentLightning, BillLiveOrTombstoned: true}, none); ok {
		t.Error("live Lightning bill: ok")
	}
}

// T20-16 (K-ON-1): the notice and its filter.
func TestT20_16_Notice(t *testing.T) {
	f := OrderNoticeFilter(testNotify)
	raw, err := json.Marshal(&f)
	if err != nil || string(raw) != `{"kinds":[23189],"#p":["`+testNotify+`"]}` {
		t.Fatalf("filter = %s %v", raw, err)
	}
	a, err := NewOrderNotice(testNotify)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewOrderNotice(testNotify)
	if a.Kind != 23189 || a.Content != "" || len(a.Tags) != 1 || a.Tags[0][0] != "p" || a.Tags[0][1] != testNotify {
		t.Fatalf("notice = %+v", a)
	}
	if a.PubKey == b.PubKey {
		t.Error("two notices share a key")
	}
	if !IsOrderNotice(a, testNotify) {
		t.Error("own notice refused")
	}
	other := strings.Repeat("f", 64)
	if IsOrderNotice(a, other) {
		t.Error("another p accepted")
	}
	resign := func(f func(*nip01.Event)) *nip01.Event {
		ev := nip01.NewEvent(KindOrderNotice, "", []string{"p", testNotify})
		f(ev)
		priv, _ := keypairHex(t)
		if err := ev.Sign(priv); err != nil {
			t.Fatal(err)
		}
		return ev
	}
	if IsOrderNotice(resign(func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"e", "x"}) }), testNotify) {
		t.Error("extra tag accepted")
	}
	if IsOrderNotice(resign(func(e *nip01.Event) { e.Content = "hi" }), testNotify) {
		t.Error("content accepted")
	}
	forged := *a
	forged.Sig = b.Sig
	if IsOrderNotice(&forged, testNotify) {
		t.Error("bad signature accepted")
	}
	if _, err := NewOrderNotice("XYZ"); err == nil {
		t.Error("bad notify accepted")
	}
}
