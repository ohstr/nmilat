package nip01

// NewFilter returns an empty, chainable SubscriptionFilter. The struct
// literal form (&SubscriptionFilter{Kinds: []int{1}}) remains fully valid —
// this is an additive chaining layer on top of the same plain struct.
func NewFilter() *SubscriptionFilter {
	return &SubscriptionFilter{}
}

func (sf *SubscriptionFilter) WithKinds(kinds ...int) *SubscriptionFilter {
	sf.Kinds = append(sf.Kinds, kinds...)
	return sf
}

func (sf *SubscriptionFilter) WithAuthors(pubkeys ...string) *SubscriptionFilter {
	sf.Authors = append(sf.Authors, pubkeys...)
	return sf
}

func (sf *SubscriptionFilter) WithIDs(ids ...string) *SubscriptionFilter {
	sf.IDs = append(sf.IDs, ids...)
	return sf
}

func (sf *SubscriptionFilter) WithLimit(n int) *SubscriptionFilter {
	sf.Limit = n
	return sf
}

func (sf *SubscriptionFilter) WithSince(t uint64) *SubscriptionFilter {
	sf.Since = t
	return sf
}

func (sf *SubscriptionFilter) WithUntil(t uint64) *SubscriptionFilter {
	sf.Until = t
	return sf
}

// WithTag appends values to the named tag filter (e.g. WithTag("e", id1,
// id2)), merging into any values already set for that tag name.
func (sf *SubscriptionFilter) WithTag(name string, values ...string) *SubscriptionFilter {
	if sf.Tags == nil {
		sf.Tags = make(map[string][]string)
	}
	sf.Tags[name] = append(sf.Tags[name], values...)
	return sf
}
