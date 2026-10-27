package nipCO

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// Tier is one on-chain confirmation tier: a payment of at most UpToMillis needs
// N confirmations. The last tier has no UpToMillis and covers every larger value.
type Tier struct {
	UpToMillis *uint64 `json:"up_to_millis,omitempty"`
	N          uint32  `json:"n"`
}

// KindTerms are the terms of one payment kind (NIP-CO §Terms). Confirmations is
// set for on-chain only.
type KindTerms struct {
	MinMillis     uint64 `json:"min_millis"`
	MaxMillis     uint64 `json:"max_millis"`
	FeeBase       uint64 `json:"fee_base"`
	FeePpm        uint64 `json:"fee_ppm"`
	Window        uint64 `json:"window"`
	Confirmations []Tier `json:"confirmations,omitempty"`
}

// BillTerms are the terms the Hub stamps on an ordered bill.
type BillTerms struct {
	RedeemFeeBase     uint64 `json:"redeem_fee_base"`
	RedeemFeePpm      uint64 `json:"redeem_fee_ppm"`
	MinTransferMillis uint64 `json:"min_transfer_millis"`
}

// Terms is get_info's cash_order object. A nil kind is not sold; both nil means
// the Hub sells nothing on this connection (a retired connection's
// "cash_order": {}).
type Terms struct {
	Lightning *KindTerms `json:"lightning,omitempty"`
	Onchain   *KindTerms `json:"onchain,omitempty"`
	Bill      BillTerms  `json:"bill"`
}

// SellsNothing reports terms that offer neither payment kind.
func (t Terms) SellsNothing() bool { return t.Lightning == nil && t.Onchain == nil }

// Kind returns the terms of a payment kind, nil when it is not sold or unknown.
func (t Terms) Kind(payment string) *KindTerms {
	switch payment {
	case PaymentLightning:
		return t.Lightning
	case PaymentOnchain:
		return t.Onchain
	}
	return nil
}

// ParseOrderInfo reads the terms from a get_info result: its cash_order object,
// or, when raw has no cash_order key, raw itself as that object. Every number
// must be a non-negative JSON integer (1.5, 1e3 and "1000" are refused); unknown
// keys are ignored. The terms are not validated: call Validate.
func ParseOrderInfo(getInfo json.RawMessage) (*Terms, error) {
	top, err := object(getInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOrderTerms, err)
	}
	obj := top
	if raw, ok := top["cash_order"]; ok {
		if obj, err = object(raw); err != nil {
			return nil, fmt.Errorf("%w: cash_order: %v", ErrOrderTerms, err)
		}
	}
	var t Terms
	for _, kind := range []string{PaymentLightning, PaymentOnchain} {
		raw, ok := obj[kind]
		if !ok {
			continue
		}
		k, err := parseKind(raw, kind == PaymentOnchain)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrOrderTerms, kind, err)
		}
		if kind == PaymentLightning {
			t.Lightning = k
		} else {
			t.Onchain = k
		}
	}
	if raw, ok := obj["bill"]; ok {
		b, err := object(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: bill: %v", ErrOrderTerms, err)
		}
		for name, dst := range map[string]*uint64{"redeem_fee_base": &t.Bill.RedeemFeeBase,
			"redeem_fee_ppm": &t.Bill.RedeemFeePpm, "min_transfer_millis": &t.Bill.MinTransferMillis} {
			if err := optUint(b, name, dst); err != nil {
				return nil, fmt.Errorf("%w: bill: %v", ErrOrderTerms, err)
			}
		}
	}
	return &t, nil
}

func parseKind(raw json.RawMessage, onchain bool) (*KindTerms, error) {
	obj, err := object(raw)
	if err != nil {
		return nil, err
	}
	var k KindTerms
	for name, dst := range map[string]*uint64{"min_millis": &k.MinMillis, "max_millis": &k.MaxMillis,
		"fee_base": &k.FeeBase, "fee_ppm": &k.FeePpm, "window": &k.Window} {
		v, ok := obj[name]
		if !ok {
			return nil, fmt.Errorf("missing %s", name)
		}
		if *dst, err = uintValue(v); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
	}
	raw, ok := obj["confirmations"]
	if !ok {
		return &k, nil
	}
	if !onchain {
		return nil, fmt.Errorf("confirmations belong to on-chain terms only")
	}
	var tiers []json.RawMessage
	if err := json.Unmarshal(raw, &tiers); err != nil {
		return nil, fmt.Errorf("confirmations: %v", err)
	}
	for i, tr := range tiers {
		to, err := object(tr)
		if err != nil {
			return nil, fmt.Errorf("tier %d: %v", i, err)
		}
		var tier Tier
		nv, ok := to["n"]
		if !ok {
			return nil, fmt.Errorf("tier %d: missing n", i)
		}
		n, err := uintValue(nv)
		if err != nil || n > 1<<32-1 {
			return nil, fmt.Errorf("tier %d: n: not a 32-bit integer", i)
		}
		tier.N = uint32(n)
		if uv, ok := to["up_to_millis"]; ok {
			u, err := uintValue(uv)
			if err != nil {
				return nil, fmt.Errorf("tier %d: up_to_millis: %v", i, err)
			}
			tier.UpToMillis = &u
		}
		k.Confirmations = append(k.Confirmations, tier)
	}
	return &k, nil
}

func object(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, fmt.Errorf("not a JSON object")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func optUint(obj map[string]json.RawMessage, name string, dst *uint64) error {
	v, ok := obj[name]
	if !ok {
		return nil
	}
	n, err := uintValue(v)
	if err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	*dst = n
	return nil
}

// uintValue reads a non-negative JSON integer written without a fraction or an
// exponent.
func uintValue(raw json.RawMessage) (uint64, error) {
	n, err := strconv.ParseUint(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("not a non-negative integer: %s", raw)
	}
	return n, nil
}

// Validate checks the terms against NIP-CO §Terms: per kind min_millis ≤
// max_millis ≤ perWalletMaxMillis (0 = the ceiling is unknown and that bound is
// skipped: a client cannot see it), a positive window; on-chain tiers in
// ascending up_to_millis, every n at least 1, only the last tier open; no tiers on
// Lightning. Terms that sell nothing are valid.
func (t Terms) Validate(perWalletMaxMillis uint64) error {
	for _, kind := range []string{PaymentLightning, PaymentOnchain} {
		k := t.Kind(kind)
		if k == nil {
			continue
		}
		if err := k.validate(kind == PaymentOnchain, perWalletMaxMillis); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrOrderTerms, kind, err)
		}
	}
	return nil
}

func (k KindTerms) validate(onchain bool, ceiling uint64) error {
	switch {
	case k.MinMillis > k.MaxMillis:
		return fmt.Errorf("min_millis %d above max_millis %d", k.MinMillis, k.MaxMillis)
	case ceiling > 0 && k.MaxMillis > ceiling:
		return fmt.Errorf("max_millis %d above the per-wallet funding ceiling %d", k.MaxMillis, ceiling)
	case k.MaxMillis == 0:
		return fmt.Errorf("max_millis is 0")
	case k.Window == 0:
		return fmt.Errorf("window is 0")
	case !onchain && len(k.Confirmations) > 0:
		return fmt.Errorf("confirmations belong to on-chain terms only")
	case onchain && len(k.Confirmations) == 0:
		return fmt.Errorf("on-chain terms need confirmation tiers")
	}
	return validTiers(k.Confirmations)
}

func validTiers(tiers []Tier) error {
	for i, tr := range tiers {
		last := i == len(tiers)-1
		switch {
		case tr.N < 1:
			return fmt.Errorf("tier %d: n must be at least 1", i)
		case last && tr.UpToMillis != nil:
			return fmt.Errorf("the last tier carries no up_to_millis")
		case !last && tr.UpToMillis == nil:
			return fmt.Errorf("tier %d: only the last tier is open", i)
		case i > 0 && !last && *tr.UpToMillis <= *tiers[i-1].UpToMillis:
			return fmt.Errorf("tier %d: up_to_millis not ascending", i)
		}
	}
	return nil
}
