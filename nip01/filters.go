package nip01

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
)

type SubscriptionFilter struct {
	IDs     []string            `json:"ids,omitempty"`
	Authors []string            `json:"authors,omitempty"`
	Kinds   []int               `json:"kinds,omitempty"`
	Tags    map[string][]string `json:"-"`
	Since   uint64              `json:"since,omitempty"`
	Until   uint64              `json:"until,omitempty"`
	Limit   int                 `json:"limit,omitempty"`
	Search  string              `json:"search,omitempty"`
	Cache   json.RawMessage     `json:"cache,omitempty"`
}

// UnmarshalJSON decodes a filter's known fields directly into their typed
// struct fields (via the Alias trick, to avoid recursing back into this
// method), then makes a second, RawMessage-only pass over the same bytes
// to pick out "#"-prefixed tag keys — the one part of a filter's shape
// that isn't a fixed field. RawMessage defers decoding each value's bytes
// until asked, so this second pass costs a map of byte slices rather than
// a map of boxed interface{} values for fields we already parsed in the
// first pass.
func (sf *SubscriptionFilter) UnmarshalJSON(data []byte) error {

	type Alias SubscriptionFilter
	var temp Alias
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	*sf = SubscriptionFilter(temp)
	sf.Tags = nil

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	for key, value := range raw {
		if len(key) < 2 || key[0] != '#' {
			continue
		}
		var strValues []string
		if err := json.Unmarshal(value, &strValues); err != nil {
			continue
		}
		if sf.Tags == nil {
			sf.Tags = make(map[string][]string, 1)
		}
		sf.Tags[key[1:]] = strValues
	}

	return nil
}

// MarshalJSON encodes sf's fixed fields the ordinary way, then splices in
// its "#"-prefixed tag keys before the closing '}' directly on the
// resulting bytes — avoiding the decode-to-map/re-encode round trip a
// generic map[string]interface{} merge would need. Tag keys are sorted so
// repeated calls on an unchanged filter are byte-for-byte identical
// (map iteration order is otherwise randomized per Go's spec).
func (sf *SubscriptionFilter) MarshalJSON() ([]byte, error) {
	type Alias SubscriptionFilter
	data, err := json.Marshal(Alias(*sf))
	if err != nil {
		return nil, err
	}
	if len(sf.Tags) == 0 {
		return data, nil
	}

	keys := make([]string, 0, len(sf.Tags))
	for k := range sf.Tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var buf bytes.Buffer
	buf.Grow(len(data) + 24*len(sf.Tags))
	buf.Write(data[:len(data)-1]) // everything up to (not including) the closing '}'
	if len(data) > len(`{}`) {
		buf.WriteByte(',')
	}
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal("#" + k)
		if err != nil {
			return nil, err
		}
		valuesJSON, err := json.Marshal(sf.Tags[k])
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(valuesJSON)
	}
	buf.WriteByte('}')

	return buf.Bytes(), nil
}

func (sf *SubscriptionFilter) Match(event *Event) bool {
	// IDs/Authors match either exactly or by prefix (a client may send a
	// shortened id/pubkey). slices.Contains alone only covers the exact
	// case, so a miss there falls through to a prefix scan — but that miss
	// is already known, not worth re-checking.
	if sf.IDs != nil && !slices.Contains(sf.IDs, event.ID) {
		if !hasMatchingPrefix(sf.IDs, event.ID) {
			return false
		}
	}

	if sf.Authors != nil && !slices.Contains(sf.Authors, event.PubKey) {
		if !hasMatchingPrefix(sf.Authors, event.PubKey) {
			return false
		}
	}

	if sf.Kinds != nil && !slices.Contains(sf.Kinds, event.Kind) {
		return false
	}

	if sf.Since != 0 && event.CreatedAt < sf.Since {
		return false
	}

	if sf.Until != 0 && event.CreatedAt > sf.Until {
		return false
	}

	for tagKey, tagValues := range sf.Tags {
		if !eventHasTagValue(event.Tags, tagKey, tagValues) {
			return false
		}
	}

	if sf.Search != "" {
		// NIP-50: "The interpretation of this field is up to the relay."
		// Basic implementation: case-insensitive content check
		if !strings.Contains(strings.ToLower(event.Content), strings.ToLower(sf.Search)) {
			return false
		}
	}

	return true
}

// hasMatchingPrefix reports whether any entry in candidates that is
// shorter than a full 32-byte hex id/pubkey is a prefix of full.
func hasMatchingPrefix(candidates []string, full string) bool {
	for _, c := range candidates {
		if len(c) < 64 && len(full) >= len(c) && full[:len(c)] == c {
			return true
		}
	}
	return false
}

// eventHasTagValue reports whether tags has an entry named tagKey whose
// value is one of wanted, without allocating an intermediate slice of
// matches the way Event.GetTag would.
func eventHasTagValue(tags [][]string, tagKey string, wanted []string) bool {
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != tagKey {
			continue
		}
		for _, v := range tag[1:] {
			if slices.Contains(wanted, v) {
				return true
			}
		}
	}
	return false
}

func (sf *SubscriptionFilter) IsEmpty() bool {
	return len(sf.IDs) == 0 && len(sf.Authors) == 0 && len(sf.Kinds) == 0 && len(sf.Tags) == 0 && sf.Since == 0 && sf.Until == 0 && sf.Limit == 0
}

type SubscriptionFilterGroup struct {
	all []*SubscriptionFilter
}

func NewSubscriptionFilterGroup(filters ...*SubscriptionFilter) *SubscriptionFilterGroup {
	return &SubscriptionFilterGroup{all: filters}
}

func (sfg *SubscriptionFilterGroup) Add(filters ...*SubscriptionFilter) {
	sfg.all = append(sfg.all, filters...)
}

func (sfg *SubscriptionFilterGroup) Match(event *Event) bool {
	for _, filter := range sfg.all {
		if filter.Match(event) {
			return true
		}
	}
	return false
}

// Equals reports whether sf and other represent the same filter, field by
// field (a nil Tags map equals an empty one).
func (sf *SubscriptionFilter) Equals(other *SubscriptionFilter) bool {
	if sf == nil || other == nil {
		return sf == other
	}
	if !slices.Equal(sf.IDs, other.IDs) ||
		!slices.Equal(sf.Authors, other.Authors) ||
		!slices.Equal(sf.Kinds, other.Kinds) ||
		sf.Since != other.Since ||
		sf.Until != other.Until ||
		sf.Limit != other.Limit ||
		sf.Search != other.Search ||
		!bytes.Equal(sf.Cache, other.Cache) ||
		len(sf.Tags) != len(other.Tags) {
		return false
	}
	for k, v := range sf.Tags {
		ov, ok := other.Tags[k]
		if !ok || !slices.Equal(v, ov) {
			return false
		}
	}
	return true
}

// Equals reports whether sfg and other hold the same filters in the same
// order.
func (sfg *SubscriptionFilterGroup) Equals(other *SubscriptionFilterGroup) bool {
	if sfg == nil || other == nil {
		return sfg == other
	}
	if len(sfg.all) != len(other.all) {
		return false
	}
	for i, f := range sfg.all {
		if !f.Equals(other.all[i]) {
			return false
		}
	}
	return true
}

func (sfg *SubscriptionFilterGroup) GetAll() []*SubscriptionFilter {
	return sfg.all
}

func (sfg *SubscriptionFilterGroup) Size() int {
	return len(sfg.all)
}

func (sfg *SubscriptionFilterGroup) ResetSince(lastUpdate uint64) {
	if lastUpdate > 0 {
		for i := range sfg.all {
			sfg.all[i].Since = lastUpdate
		}
	}
}

func (sfg *SubscriptionFilterGroup) Copy() *SubscriptionFilterGroup {
	if sfg == nil {
		return nil
	}

	newGroup := NewSubscriptionFilterGroup()
	for _, f := range sfg.all {
		// Deep copy filter
		newF := *f
		// Copy maps/slices if needed
		if f.IDs != nil {
			newF.IDs = make([]string, len(f.IDs))
			copy(newF.IDs, f.IDs)
		}
		if f.Authors != nil {
			newF.Authors = make([]string, len(f.Authors))
			copy(newF.Authors, f.Authors)
		}
		if f.Kinds != nil {
			newF.Kinds = make([]int, len(f.Kinds))
			copy(newF.Kinds, f.Kinds)
		}
		if f.Tags != nil {
			newF.Tags = make(map[string][]string)
			for k, v := range f.Tags {
				newV := make([]string, len(v))
				copy(newV, v)
				newF.Tags[k] = newV
			}
		}
		newGroup.Add(&newF)
	}
	return newGroup
}

func (sfg *SubscriptionFilterGroup) HasSearch() bool {
	for _, f := range sfg.all {
		if f.Search != "" {
			return true
		}
	}
	return false
}
