package nipCO

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

// F-CO-1: DecodeOrderConnection never panics; an accepted string re-encodes to
// itself (case folded), or, when it carried what the encoder drops or refuses
// (an unknown entry, a blank hint), to a string decoding to the same fields; a
// string verifying for anyone but the seed's signer would be a forgery.
func FuzzDecodeOrderConnection(f *testing.F) {
	f.Add(kco1String)
	f.Add(strings.ToUpper(kco1String))
	f.Add("cashorder1")
	f.Add(kco1String[:len(kco1String)-1] + "q")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := DecodeOrderConnection(s)
		if err != nil {
			if !errors.Is(err, ErrOrderConnection) {
				t.Fatalf("a refusal outside ErrOrderConnection: %v", err)
			}
			return
		}
		if c.Verify() == nil && c.HubIdentity != kcoIdentity {
			t.Fatalf("a string not signed by key 1 verified: %+v", c)
		}
		again, err := EncodeOrderConnection(c)
		if err != nil {
			return // the decoder keeps blank hints and an empty label the encoder refuses
		}
		if strings.ToLower(s) == again {
			return
		}
		c2, err := DecodeOrderConnection(again)
		if err != nil || c2.Pubkey != c.Pubkey || c2.Secret != c.Secret || c2.HubIdentity != c.HubIdentity ||
			c2.Chain != c.Chain || string(c2.Signature) != string(c.Signature) || c2.Label != c.Label ||
			c2.HasLabel != c.HasLabel || strings.Join(c2.Relays, " ") != strings.Join(c.Relays, " ") {
			t.Fatalf("re-encoded string decodes differently: %+v vs %+v (%v)", c2, c, err)
		}
	})
}

// F-ORD-1: ParseCashOrderRequest and CashOrderParams.ParseLookupResult never
// panic; a request carrying a forbidden key is always BAD_REQUEST; an order
// whose state is not one of the five never decodes.
func FuzzParseCashOrderRequest(f *testing.F) {
	f.Add([]byte(specRequest), "")
	f.Add([]byte(specRequest), "expiry")
	f.Add([]byte(`{"recipients":[]}`), "")
	f.Add([]byte(`{"state":"open","payment":"lightning","amount_millis":21000000,"fee_millis":22000,`+
		`"pay_millis":21022000,"invoice":"lnbc1","pay_by":1720003600,"bills":[]}`), "")
	f.Add([]byte(`{"state":"refunded","payment":"onchain","amount_millis":1000,"fee_millis":0,"pay_millis":1000,`+
		`"address":"bc1q","confirmations":1,"pay_by":1,"bills":[]}`), "")
	f.Add([]byte(`[1]`), "cash_secret")
	f.Fuzz(func(t *testing.T, data []byte, forbidden string) {
		req, err := ParseCashOrderRequest(json.RawMessage(data))
		var oe *OrderError
		if err != nil && (!errors.As(err, &oe) || oe.Code != nipcash.ErrCodeBadRequest) {
			t.Fatalf("a refusal that is not BAD_REQUEST: %v", err)
		}
		if err != nil && req != nil && req.defect == nil {
			t.Fatal("a defect returned but not recorded on the request")
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(data, &m) == nil {
			for _, k := range forbiddenOrderKeys {
				if _, ok := m[k]; ok && err == nil {
					t.Fatalf("a request carrying %s was accepted", k)
				}
			}
			for _, k := range forbiddenOrderKeys {
				if k != forbidden {
					continue
				}
				m[k] = json.RawMessage(`1`)
				with, _ := json.Marshal(m)
				if _, err := ParseCashOrderRequest(with); !errors.As(err, &oe) || oe.Code != nipcash.ErrCodeBadRequest {
					t.Fatalf("a request with %s added: %v", k, err)
				}
			}
		}
		for _, p := range []CashOrderParams{{}, {Payment: PaymentLightning}, {Payment: PaymentOnchain, AmountMillis: 1000}} {
			o, err := p.ParseLookupResult(data)
			if err != nil {
				if !errors.Is(err, ErrOrderReply) {
					t.Fatalf("a lookup refusal outside ErrOrderReply: %v", err)
				}
				continue
			}
			if !o.State.valid() {
				t.Fatalf("state %q decoded", o.State)
			}
			if _, err := p.ParseResult(data); err == nil && o.State != OrderOpen {
				t.Fatalf("a direct reply in state %q accepted", o.State)
			}
		}
	})
}
