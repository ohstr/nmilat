package niplsp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// FromLSPSInfo builds an announcement's Fields from the publisher's own
// current LSPS answers, so that what it announces equals what it answers
// (NIP-LSP §Publishing):
//
//   - lsps0Protocols: the protocols of LSPS0 list_protocols;
//   - lsps1Info: the LSPS1 get_info result, read when protocol 1 is listed
//     (its known options, the _sat/_loki amounts in base units);
//   - lsps2Menu: the LSPS2 get_info result, or its opening_fee_params_menu
//     array alone, read when protocol 2 is listed (millis; each row's
//     valid_until and promise dropped);
//   - lsps5: an object holding the LSPS5 fields (max_webhooks), such as a
//     set_webhook result, read when protocol 5 is listed; nil announces none;
//   - m: everything else.
//
// Both unit dialects are read (_sat and _msat, _loki and _mloki). Step data of
// a protocol that is not listed is not announced. It refuses a listed protocol
// 1 or 2 without its answer (ErrMissingLSPSAnswer), an answer it cannot read
// (ErrLSPSAnswer), and Fields NewAnnouncement would refuse, except for the
// expiration's distance from created_at, which NewAnnouncement checks.
func FromLSPSInfo(lsps0Protocols []int, lsps1Info, lsps2Menu, lsps5 json.RawMessage, m Meta) (Fields, error) {
	f := Fields{Meta: m, Protocols: append([]int(nil), lsps0Protocols...)}
	var err error
	if f.HasProtocol(ProtocolLSPS1) {
		if len(lsps1Info) == 0 {
			return Fields{}, fmt.Errorf("%w: protocol 1 without LSPS1 get_info", ErrMissingLSPSAnswer)
		}
		if f.LSPS1, err = ParseLSPS1Info(lsps1Info); err != nil {
			return Fields{}, err
		}
	}
	if f.HasProtocol(ProtocolLSPS2) {
		if len(lsps2Menu) == 0 {
			return Fields{}, fmt.Errorf("%w: protocol 2 without LSPS2 get_info", ErrMissingLSPSAnswer)
		}
		if f.LSPS2, err = ParseLSPS2Menu(lsps2Menu); err != nil {
			return Fields{}, err
		}
	}
	if f.HasProtocol(ProtocolLSPS5) && len(lsps5) > 0 {
		if f.LSPS5, err = ParseLSPS5(lsps5); err != nil {
			return Fields{}, err
		}
	}
	return normalize(f)
}

// ParseListProtocols reads an LSPS0 list_protocols result ({"protocols":
// [...]}) or its protocols array alone.
func ParseListProtocols(raw json.RawMessage) ([]int, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '{' {
		var r struct {
			Protocols *json.RawMessage `json:"protocols"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || r.Protocols == nil {
			return nil, fmt.Errorf("%w: list_protocols has no protocols", ErrLSPSAnswer)
		}
		raw = *r.Protocols
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%w: list_protocols: %v", ErrLSPSAnswer, err)
	}
	out := make([]int, 0, len(items))
	for _, it := range items {
		v, ok := jsonUint(it, false)
		if !ok || v > uint64(^uint32(0)) {
			return nil, fmt.Errorf("%w: protocol %s", ErrLSPSAnswer, it)
		}
		out = append(out, int(v))
	}
	return out, nil
}

// ParseLSPS1Info reads the options of an LSPS1 get_info result, in either unit
// dialect, as announced options in bLIP-51 order: names without the unit
// suffix, amounts in base units. Options it does not know are skipped. The
// options may sit at the top level or, as in earlier LSPS1 versions, in an
// "options" object.
func ParseLSPS1Info(raw json.RawMessage) ([]Option, error) {
	obj, err := object(raw, "LSPS1 get_info")
	if err != nil {
		return nil, err
	}
	if nested, ok := obj["options"]; ok && len(bytes.TrimSpace(nested)) > 0 && bytes.TrimSpace(nested)[0] == '{' {
		if obj, err = object(nested, "LSPS1 get_info options"); err != nil {
			return nil, err
		}
	}
	values, err := readKnown(obj, lsps1Options, "LSPS1 get_info")
	if err != nil {
		return nil, err
	}
	var out []Option
	for _, k := range lsps1Options {
		if v, ok := values[k.Name]; ok {
			out = append(out, Option{Name: k.Name, Value: v})
		}
	}
	return out, nil
}

// ParseLSPS2Menu reads an LSPS2 get_info result's opening_fee_params_menu,
// or the menu array alone, in either unit dialect. Every row must hold the six
// announced fields; valid_until, promise and anything else are dropped.
func ParseLSPS2Menu(raw json.RawMessage) ([]FeeRow, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '{' {
		obj, err := object(raw, "LSPS2 get_info")
		if err != nil {
			return nil, err
		}
		menu, ok := obj["opening_fee_params_menu"]
		if !ok {
			return nil, fmt.Errorf("%w: LSPS2 get_info has no opening_fee_params_menu", ErrLSPSAnswer)
		}
		raw = menu
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("%w: opening_fee_params_menu: %v", ErrLSPSAnswer, err)
	}
	out := make([]FeeRow, 0, len(rows))
	for i, r := range rows {
		obj, err := object(r, "opening_fee_params_menu row")
		if err != nil {
			return nil, err
		}
		values, err := readKnown(obj, feeRowFields[:], "opening_fee_params_menu row")
		if err != nil {
			return nil, err
		}
		var v [6]uint64
		for j, k := range feeRowFields {
			s, ok := values[k.Name]
			if !ok {
				return nil, fmt.Errorf("%w: opening_fee_params_menu row %d has no %s", ErrLSPSAnswer, i, k.Name)
			}
			v[j], _ = canonicalUint(s)
		}
		out = append(out, FeeRow{v[0], v[1], v[2], v[3], v[4], v[5]})
	}
	return out, nil
}

// ParseLSPS5 reads the LSPS5 fields an announcement carries (max_webhooks)
// from an object holding them, such as a set_webhook or list_webhooks result.
func ParseLSPS5(raw json.RawMessage) ([]Option, error) {
	obj, err := object(raw, "LSPS5 answer")
	if err != nil {
		return nil, err
	}
	values, err := readKnown(obj, lsps5Fields, "LSPS5 answer")
	if err != nil {
		return nil, err
	}
	var out []Option
	for _, k := range lsps5Fields {
		if v, ok := values[k.Name]; ok {
			out = append(out, Option{Name: k.Name, Value: v})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: LSPS5 answer has no max_webhooks", ErrLSPSAnswer)
	}
	return out, nil
}

func object(raw json.RawMessage, what string) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("%w: %s is not a JSON object", ErrLSPSAnswer, what)
	}
	return obj, nil
}

// readKnown reads the fields of table from obj, matching LSPS names in either
// dialect to announced names, and returns their announced values. A field
// given in both dialects, or of the wrong JSON type, is refused.
func readKnown(obj map[string]json.RawMessage, table []knownOption, what string) (map[string]string, error) {
	out := map[string]string{}
	from := map[string]string{}
	for key, raw := range obj {
		name, unit := FromLSPSName(key)
		k, ok := lookupOption(table, name)
		if !ok || k.Unit != unit {
			continue
		}
		if prev, dup := from[name]; dup {
			return nil, fmt.Errorf("%w: %s gives both %s and %s", ErrLSPSAnswer, what, prev, key)
		}
		from[name] = key
		var v string
		switch k.Kind {
		case kindBool:
			v = string(bytes.TrimSpace(raw))
			if v != "true" && v != "false" {
				return nil, fmt.Errorf("%w: %s %s = %s", ErrLSPSAnswer, what, key, raw)
			}
		default:
			n, ok := jsonUint(raw, true)
			if !ok {
				return nil, fmt.Errorf("%w: %s %s = %s", ErrLSPSAnswer, what, key, raw)
			}
			v = strconv.FormatUint(n, 10)
		}
		out[name] = v
	}
	return out, nil
}

// jsonUint reads an unsigned integer given as a JSON number or, when
// allowString, as a decimal string, as LSPS writes amounts. No sign, fraction
// or exponent.
func jsonUint(raw json.RawMessage, allowString bool) (uint64, bool) {
	raw = bytes.TrimSpace(raw)
	s := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if !allowString || json.Unmarshal(raw, &s) != nil {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}
