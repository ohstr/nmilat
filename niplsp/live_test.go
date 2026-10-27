package niplsp

import (
	"encoding/json"
	"reflect"
	"testing"
)

func exampleAnnouncement(t *testing.T) *Announcement {
	t.Helper()
	a, err := ParseAnnouncement(signed(t, exampleFields(), exampleCreatedAt), mainnet)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// exampleLive are live answers equal to the example's.
func exampleLive(t *testing.T) Live {
	t.Helper()
	p, err := ParseListProtocols(json.RawMessage(`{"protocols":[1,2,5]}`))
	if err != nil {
		t.Fatal(err)
	}
	l1, err := ParseLSPS1Info(json.RawMessage(lsps1Loki))
	if err != nil {
		t.Fatal(err)
	}
	l2, err := ParseLSPS2Menu(json.RawMessage(lsps2Sat))
	if err != nil {
		t.Fatal(err)
	}
	return Live{Protocols: p, LSPS1: l1, LSPS2Menu: l2}
}

func setOption(opts []Option, name, value string) []Option {
	out := append([]Option(nil), opts...)
	for i := range out {
		if out[i].Name == name {
			out[i].Value = value
		}
	}
	return out
}

func diffOf(d LiveDiff, field string) FieldDiff {
	for _, f := range d.Fields {
		if f.Field == field {
			return f
		}
	}
	return FieldDiff{Field: "absent"}
}

// T23-11: same, worse, better, missing protocol.
func TestCheckLive(t *testing.T) {
	a := exampleAnnouncement(t)

	// Same.
	d := CheckLive(a, exampleLive(t))
	if !d.Same() || d.Worse() || !d.Usable() || len(d.Changed()) != 0 || len(d.Fields) != 16 {
		t.Fatalf("same: %+v", d)
	}

	// A higher live min_fee is worse.
	l := exampleLive(t)
	l.LSPS2Menu = []FeeRow{l.LSPS2Menu[0]}
	l.LSPS2Menu[0].MinFeeMillis = 2000001
	d = CheckLive(a, l)
	if f := diffOf(d, "lsps2_fee[0].min_fee"); f.Verdict != Worse || f.Announced != "2000000" || f.Live != "2000001" {
		t.Fatalf("min_fee: %+v", f)
	}
	if !d.Worse() || d.Same() || len(d.Changed()) != 1 {
		t.Fatalf("%+v", d)
	}

	// A lower max_channel_balance is worse.
	l = exampleLive(t)
	l.LSPS1 = setOption(l.LSPS1, "max_channel_balance", "5000000")
	d = CheckLive(a, l)
	if f := diffOf(d, "max_channel_balance"); f.Verdict != Worse {
		t.Fatalf("max_channel_balance: %+v", f)
	}

	// A missing protocol.
	l = exampleLive(t)
	l.Protocols = []int{1, 2}
	d = CheckLive(a, l)
	if d.Usable() || !reflect.DeepEqual(d.MissingProtocol, []int{5}) || d.Same() {
		t.Fatalf("missing protocol: %+v", d)
	}

	// Better live values.
	l = exampleLive(t)
	l.LSPS1 = setOption(l.LSPS1, "max_channel_balance", "20000000")
	l.LSPS1 = setOption(l.LSPS1, "min_channel_balance", "50000")
	l.LSPS1 = setOption(l.LSPS1, "supports_zero_channel_reserve", "true")
	l.LSPS1 = setOption(l.LSPS1, "min_funding_confirms_within_blocks", "3")
	l.LSPS2Menu = []FeeRow{l.LSPS2Menu[0]}
	l.LSPS2Menu[0].Proportional = 3000
	l.LSPS2Menu[0].MinLifetime = 8640
	d = CheckLive(a, l)
	for _, name := range []string{"max_channel_balance", "min_channel_balance", "supports_zero_channel_reserve",
		"min_funding_confirms_within_blocks", "lsps2_fee[0].proportional", "lsps2_fee[0].min_lifetime"} {
		if f := diffOf(d, name); f.Verdict != Better {
			t.Fatalf("%s: %+v", name, f)
		}
	}
	if d.Worse() || d.Same() || len(d.Changed()) != 6 {
		t.Fatalf("%+v", d)
	}

	// Worse in the other directions.
	l = exampleLive(t)
	l.LSPS1 = setOption(l.LSPS1, "min_required_channel_confirmations", "1")
	l.LSPS1 = setOption(l.LSPS1, "max_channel_expiry_blocks", "4320")
	l.LSPS2Menu[0].MaxPaymentSizeMillis = 1000000000
	l.LSPS2Menu[0].MaxClientToSelfDelay = 144
	l.LSPS2Menu[0].MinPaymentSizeMillis = 20000000
	d = CheckLive(a, l)
	for _, name := range []string{"min_required_channel_confirmations", "max_channel_expiry_blocks",
		"lsps2_fee[0].max_payment_size", "lsps2_fee[0].max_client_to_self_delay", "lsps2_fee[0].min_payment_size"} {
		if f := diffOf(d, name); f.Verdict != Worse {
			t.Fatalf("%s: %+v", name, f)
		}
	}
	l = exampleLive(t)
	l.LSPS1 = setOption(l.LSPS1, "supports_zero_channel_reserve", "true")
	a2 := exampleAnnouncement(t)
	a2.LSPS1 = setOption(a2.LSPS1, "supports_zero_channel_reserve", "true")
	l.LSPS1 = setOption(l.LSPS1, "supports_zero_channel_reserve", "false")
	if f := diffOf(CheckLive(a2, l), "supports_zero_channel_reserve"); f.Verdict != Worse {
		t.Fatalf("zero reserve lost: %+v", f)
	}
}

func TestCheckLiveRowsAndGaps(t *testing.T) {
	a := exampleAnnouncement(t)

	// A live answer lacking an announced option, or the announced row: worse.
	l := exampleLive(t)
	l.LSPS1 = l.LSPS1[:9] // no max_channel_balance
	l.LSPS2Menu = []FeeRow{}
	d := CheckLive(a, l)
	if f := diffOf(d, "max_channel_balance"); f.Verdict != Worse || f.Live != "" {
		t.Fatalf("%+v", f)
	}
	if f := diffOf(d, "lsps2_fee[0].min_fee"); f.Verdict != Worse || f.Live != "" {
		t.Fatalf("%+v", f)
	}

	// A live row beyond the announced ones: better.
	l = exampleLive(t)
	l.LSPS2Menu = append(l.LSPS2Menu, FeeRow{5000000, 1000, 4320, 2016, 1000, 100000000})
	d = CheckLive(a, l)
	if f := diffOf(d, "lsps2_fee[1].min_fee"); f.Verdict != Better || f.Announced != "" {
		t.Fatalf("%+v", f)
	}

	// Fields not asked are not compared; unknown announced options neither.
	d = CheckLive(a, Live{Protocols: []int{1, 2, 5}})
	if !d.Same() || len(d.Fields) != 0 {
		t.Fatalf("%+v", d)
	}
	a.LSPS1 = append(a.LSPS1, Option{"future_option", "1"})
	if d := CheckLive(a, exampleLive(t)); len(d.Fields) != 16 {
		t.Fatal("unknown option compared")
	}
	if d := CheckLive(nil, exampleLive(t)); len(d.Fields) != 0 {
		t.Fatal("nil announcement")
	}

	if Same.String() != "same" || Worse.String() != "worse" || Better.String() != "better" || Verdict(9).String() != "Verdict(9)" {
		t.Fatal("String")
	}
}

// A live LSPS1 answer with no known option was asked: every announced option
// comes out worse, never same.
func TestCheckLiveEmptyLSPS1(t *testing.T) {
	a := exampleAnnouncement(t)
	l := exampleLive(t)
	l1, err := ParseLSPS1Info(json.RawMessage(`{}`))
	if err != nil || l1 == nil {
		t.Fatalf("%v %v", l1, err)
	}
	l.LSPS1 = l1
	d := CheckLive(a, l)
	if d.Same() || len(a.LSPS1) == 0 || d.count(Worse) < len(a.LSPS1) {
		t.Fatalf("%+v", d)
	}
}

// list_protocols not asked: never usable, whatever else matches.
func TestCheckLiveProtocolsNotAsked(t *testing.T) {
	l := exampleLive(t)
	l.Protocols = nil
	if d := CheckLive(exampleAnnouncement(t), l); d.Usable() || d.Same() {
		t.Fatalf("%+v", d)
	}
}
