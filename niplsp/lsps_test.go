package niplsp

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The NIP-LSP example's LSPS answers, in each dialect.
const (
	lsps1Sat = `{
		"min_required_channel_confirmations": 0,
		"min_funding_confirms_within_blocks": 6,
		"supports_zero_channel_reserve": false,
		"max_channel_expiry_blocks": 12960,
		"min_initial_client_balance_sat": "0",
		"max_initial_client_balance_sat": "1000000",
		"min_initial_lsp_balance_sat": "0",
		"max_initial_lsp_balance_sat": "10000000",
		"min_channel_balance_sat": "100000",
		"max_channel_balance_sat": "10000000"
	}`
	// The loki dialect as an LSPS1 server on a loki chain answers, with the
	// options array some servers add, and the fields in another order.
	lsps1Loki = `{
		"options": [],
		"max_channel_balance_loki": "10000000",
		"min_channel_balance_loki": "100000",
		"max_initial_lsp_balance_loki": "10000000",
		"min_initial_lsp_balance_loki": "0",
		"max_initial_client_balance_loki": "1000000",
		"min_initial_client_balance_loki": "0",
		"max_channel_expiry_blocks": 12960,
		"supports_zero_channel_reserve": false,
		"min_funding_confirms_within_blocks": 6,
		"min_required_channel_confirmations": 0,
		"website": "https://ignored.example"
	}`
	// The earlier LSPS1 shape: the options nested.
	lsps1Nested = `{"options": {
		"min_required_channel_confirmations": 0,
		"min_funding_confirms_within_blocks": 6,
		"supports_zero_channel_reserve": false,
		"max_channel_expiry_blocks": 12960,
		"min_initial_client_balance_sat": "0",
		"max_initial_client_balance_sat": "1000000",
		"min_initial_lsp_balance_sat": "0",
		"max_initial_lsp_balance_sat": "10000000",
		"min_channel_balance_sat": "100000",
		"max_channel_balance_sat": "10000000"
	}}`
	lsps2Sat = `{"opening_fee_params_menu": [{
		"min_fee_msat": "2000000",
		"proportional": 4000,
		"valid_until": "2026-10-22T00:00:00.000Z",
		"min_lifetime": 4320,
		"max_client_to_self_delay": 2016,
		"min_payment_size_msat": "10000000",
		"max_payment_size_msat": "4000000000",
		"promise": "abcdef"
	}]}`
	lsps2Loki = `[{
		"min_fee_mloki": "2000000",
		"proportional": 4000,
		"valid_until": "2026-10-22T00:00:00.000Z",
		"min_lifetime": 4320,
		"max_client_to_self_delay": 2016,
		"min_payment_size_mloki": "10000000",
		"max_payment_size_mloki": "4000000000",
		"promise": "012345"
	}]`
	lsps5Answer = `{"num_webhooks": 2, "max_webhooks": 10, "no_change": false}`
)

func exampleMeta() Meta { return exampleFields().Meta }

// T23-10: FromLSPSInfo from the answers in both dialects gives the same
// Fields, the example's; valid_until and promise are dropped.
func TestFromLSPSInfo(t *testing.T) {
	want := exampleFields()
	for _, c := range []struct{ name, l1, l2 string }{
		{"sat", lsps1Sat, lsps2Sat},
		{"loki", lsps1Loki, lsps2Loki},
		{"nested options", lsps1Nested, lsps2Sat},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := FromLSPSInfo([]int{1, 2, 5}, json.RawMessage(c.l1), json.RawMessage(c.l2), json.RawMessage(lsps5Answer), exampleMeta())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f, want) {
				t.Fatalf("\n got %+v\nwant %+v", f, want)
			}
			ev, err := NewAnnouncement(f, exampleCreatedAt)
			if err != nil || ev.ID != exampleID {
				t.Fatalf("K-LSP-1 from LSPS answers: %v %v", err, ev)
			}
			for _, tag := range ev.Tags {
				for _, v := range tag {
					if strings.Contains(v, "2026-10-22") || v == "abcdef" || v == "012345" {
						t.Fatalf("valid_until or promise announced: %q", tag)
					}
				}
			}
		})
	}
}

func TestFromLSPSInfoProtocols(t *testing.T) {
	m := exampleMeta()
	// Step data of a protocol that is not listed is not announced.
	f, err := FromLSPSInfo([]int{2}, json.RawMessage(lsps1Sat), json.RawMessage(lsps2Sat), json.RawMessage(lsps5Answer), m)
	if err != nil {
		t.Fatal(err)
	}
	if f.LSPS1 != nil || f.LSPS5 != nil || len(f.LSPS2) != 1 {
		t.Fatalf("%+v", f)
	}
	// Protocol 5 without an LSPS5 answer announces no field.
	f, err = FromLSPSInfo([]int{5}, nil, nil, nil, m)
	if err != nil || f.LSPS5 != nil {
		t.Fatalf("%v %+v", err, f)
	}
	// A node key given as a node id comes back x-only, an empty status open.
	m.NodeKey = "03" + key1Pub
	m.Status = ""
	f, err = FromLSPSInfo([]int{5}, nil, nil, nil, m)
	if err != nil || f.NodeKey != key1Pub || f.Status != StatusOpen {
		t.Fatalf("%v %+v", err, f)
	}

	cases := []struct {
		name       string
		protocols  []int
		l1, l2, l5 string
		want       error
	}{
		{"protocol 1 without get_info", []int{1}, "", "", "", ErrMissingLSPSAnswer},
		{"protocol 2 without get_info", []int{2}, "", "", "", ErrMissingLSPSAnswer},
		{"protocol 2, empty menu", []int{2}, "", `{"opening_fee_params_menu": []}`, "", ErrNoFeeRow},
		{"no protocol", nil, "", "", "", ErrInvalidFields},
		{"lsps1 not an object", []int{1}, `[]`, "", "", ErrLSPSAnswer},
		{"lsps1 both dialects", []int{1}, `{"min_channel_balance_sat": "1", "min_channel_balance_loki": "1"}`, "", "", ErrLSPSAnswer},
		{"lsps1 negative", []int{1}, `{"max_channel_expiry_blocks": -1}`, "", "", ErrLSPSAnswer},
		{"lsps1 fraction", []int{1}, `{"max_channel_expiry_blocks": 1.5}`, "", "", ErrLSPSAnswer},
		{"lsps1 amount not decimal", []int{1}, `{"max_channel_balance_sat": "1e6"}`, "", "", ErrLSPSAnswer},
		{"lsps1 bool as string", []int{1}, `{"supports_zero_channel_reserve": "true"}`, "", "", ErrLSPSAnswer},
		{"lsps2 no menu", []int{2}, "", `{}`, "", ErrLSPSAnswer},
		{"lsps2 row missing a field", []int{2}, "", `[{"min_fee_msat": "1", "proportional": 1, "min_lifetime": 1, "max_client_to_self_delay": 1, "min_payment_size_msat": "1"}]`, "", ErrLSPSAnswer},
		{"lsps2 row not an object", []int{2}, "", `[1]`, "", ErrLSPSAnswer},
		{"lsps2 menu not an array", []int{2}, "", `{"opening_fee_params_menu": {}}`, "", ErrLSPSAnswer},
		{"lsps5 without max_webhooks", []int{5}, "", "", `{"num_webhooks": 1}`, ErrLSPSAnswer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := func(s string) json.RawMessage {
				if s == "" {
					return nil
				}
				return json.RawMessage(s)
			}
			_, err := FromLSPSInfo(c.protocols, raw(c.l1), raw(c.l2), raw(c.l5), exampleMeta())
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseListProtocols(t *testing.T) {
	for _, raw := range []string{`{"protocols": [1, 2, 5]}`, `[1,2,5]`} {
		p, err := ParseListProtocols(json.RawMessage(raw))
		if err != nil || !reflect.DeepEqual(p, []int{1, 2, 5}) {
			t.Fatalf("%s: %v %v", raw, p, err)
		}
	}
	for _, raw := range []string{`{}`, `{"protocols": ["1"]}`, `[-1]`, `[1.5]`, `"1"`, `[4294967296]`} {
		if _, err := ParseListProtocols(json.RawMessage(raw)); !errors.Is(err, ErrLSPSAnswer) {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}
