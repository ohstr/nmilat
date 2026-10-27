package nipCO

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nipcash"
)

// OrderState is an order's state (NIP-CO §Order State).
type OrderState string

const (
	OrderOpen    OrderState = "open"
	OrderPaid    OrderState = "paid"
	OrderMinted  OrderState = "minted"
	OrderExpired OrderState = "expired"
	OrderClosed  OrderState = "closed"
)

func (s OrderState) valid() bool {
	switch s {
	case OrderOpen, OrderPaid, OrderMinted, OrderExpired, OrderClosed:
		return true
	}
	return false
}

// OrderBill is one bill an order minted. Token is its cash token, or the
// tombstone of a bill already destroyed. PaidMillis is the payment it was minted
// from; Outpoint (txid:vout) its on-chain output, "" for Lightning.
type OrderBill struct {
	WalletPubkey string                   `json:"wallet_pubkey"`
	Token        nipcash.TokenOrTombstone `json:"cash_token"`
	AmountMillis uint64                   `json:"amount_millis"`
	PaidMillis   uint64                   `json:"paid_millis"`
	Outpoint     string                   `json:"outpoint,omitempty"`
}

// Order is cash_order's reply and an order lookup's done result (NIP-CO
// §Response): Invoice for Lightning, Address and Confirmations for on-chain.
//
// TermsChanged is never on the wire: the client's Place sets it when the reply's
// confirmations differ from the tier of pay_millis under the terms it read
// before placing. The reply's value is shown, flagged as changed terms; the
// order is never refused for it.
type Order struct {
	State         OrderState  `json:"state"`
	Payment       string      `json:"payment"`
	AmountMillis  uint64      `json:"amount_millis"`
	FeeMillis     uint64      `json:"fee_millis"`
	PayMillis     uint64      `json:"pay_millis"`
	Invoice       string      `json:"invoice,omitempty"`
	Address       string      `json:"address,omitempty"`
	Confirmations uint32      `json:"confirmations,omitempty"`
	PayBy         int64       `json:"pay_by"`
	Bills         []OrderBill `json:"bills"`
	TermsChanged  bool        `json:"-"`
}

// MarshalJSON writes bills as [] when there are none.
func (o Order) MarshalJSON() ([]byte, error) {
	type plain Order
	p := plain(o)
	if p.Bills == nil {
		p.Bills = []OrderBill{}
	}
	return json.Marshal(p)
}

// ParseResult reads a direct cash_order reply: ParseLookupResult's checks, and
// the order must be open with no tombstone in place of a token.
func (p CashOrderParams) ParseResult(data []byte) (*Order, error) {
	o, err := p.ParseLookupResult(data)
	if err != nil {
		return o, err
	}
	if o.State != OrderOpen {
		return o, fmt.Errorf("%w: a new order is open, not %q", ErrOrderReply, o.State)
	}
	for _, b := range o.Bills {
		if b.Token.Tombstone != nil {
			return o, fmt.Errorf("%w: %w", ErrOrderReply, nipcash.ErrTombstoneInReply)
		}
	}
	return o, nil
}

// ParseLookupResult reads an order as a lookup's done carries it: the order as
// it stands. Anything off the NIP-CO §Response shape is ErrOrderReply, never
// unknown and never a state: a cash_secret anywhere, an unknown state or
// payment, a payment, amount or pay_millis that does not match the request (when
// p names them) or amount + fee, invoice and address both or the wrong one for
// the kind, an on-chain order without confirmations, a bill whose token does not
// decode or is not signed under cash-mint:v1, an outpoint on a Lightning bill or
// none on an on-chain one. Checking each token's provenance against the Hub
// identity is the caller's, which knows it.
func (p CashOrderParams) ParseLookupResult(data []byte) (*Order, error) {
	if containsKey(data, "cash_secret") {
		return nil, fmt.Errorf("%w: %w", ErrOrderReply, nipcash.ErrHubReturnedSecret)
	}
	var o Order
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOrderReply, err)
	}
	o.TermsChanged = false
	bad := func(format string, a ...any) (*Order, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{ErrOrderReply}, a...)...)
	}
	switch {
	case !o.State.valid():
		return bad("unknown state %q", o.State)
	case o.Payment != PaymentLightning && o.Payment != PaymentOnchain:
		return bad("unknown payment %q", o.Payment)
	case p.Payment != "" && o.Payment != p.Payment:
		return bad("payment %q, ordered %q", o.Payment, p.Payment)
	case p.AmountMillis != 0 && o.AmountMillis != p.AmountMillis:
		return bad("amount_millis %d, ordered %d", o.AmountMillis, p.AmountMillis)
	case o.AmountMillis == 0 || o.PayMillis != o.AmountMillis+o.FeeMillis || o.PayMillis < o.AmountMillis:
		return bad("pay_millis is not amount_millis + fee_millis")
	case o.PayBy <= 0:
		return bad("no pay_by")
	case o.Invoice != "" && o.Address != "":
		return bad("both invoice and address")
	}
	if o.Payment == PaymentLightning {
		if o.Invoice == "" || o.Confirmations != 0 {
			return bad("a Lightning order carries an invoice and no confirmations")
		}
	} else {
		if o.Address == "" || o.Confirmations < 1 || o.PayMillis%1000 != 0 {
			return bad("an on-chain order carries an address, its confirmations and whole base units")
		}
	}
	for i, b := range o.Bills {
		if !isLowerHex(b.WalletPubkey, 64) || b.AmountMillis == 0 {
			return bad("bill %d: wallet_pubkey or amount", i)
		}
		if o.Payment == PaymentLightning && b.Outpoint != "" {
			return bad("bill %d: an outpoint on a Lightning bill", i)
		}
		if o.Payment == PaymentOnchain && !validOutpoint(b.Outpoint) {
			return bad("bill %d: an on-chain bill names its outpoint", i)
		}
		if b.Token.Tombstone != nil {
			continue
		}
		tok, err := nipcash.Decode(b.Token.Token)
		if err != nil {
			return bad("bill %d: token: %v", i, err)
		}
		if tok.Scheme != nipcash.SchemeMintV1 {
			return bad("bill %d: %v", i, nipcash.ErrTokenScheme)
		}
		if tok.WalletPubkey != b.WalletPubkey {
			return bad("bill %d: the token names another wallet", i)
		}
	}
	return &o, nil
}

// validOutpoint reports txid:vout with a 64-hex txid.
func validOutpoint(s string) bool {
	txid, vout, ok := strings.Cut(s, ":")
	if !ok || !isLowerHex(strings.ToLower(txid), 64) {
		return false
	}
	_, err := strconv.ParseUint(vout, 10, 32)
	return err == nil
}

// containsKey reports an object key name anywhere in data.
func containsKey(data []byte, name string) bool {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return false
	}
	var walk func(any) bool
	walk = func(n any) bool {
		switch t := n.(type) {
		case map[string]any:
			if _, ok := t[name]; ok {
				return true
			}
			for _, c := range t {
				if walk(c) {
					return true
				}
			}
		case []any:
			for _, c := range t {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}
