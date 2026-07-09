package nip01

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func TestSubscriptionFilterFormat(t *testing.T) {

	tags := make(map[string][]string)
	tags["e"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "cd0aa9856147b6c5b4ff2b7dfee5da20aa38253099ef1b4a64aced233c9afe29"}
	tags["p"] = []string{"e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"}

	sampleFilter := SubscriptionFilter{
		IDs:     []string{"e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
		Authors: []string{"e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
		Kinds:   []int{1, 2, 99},
		Tags:    tags,
		Since:   1716584173,
		Until:   1716584863,
		Limit:   100,
	}

	tests := []struct {
		name      string
		wantError bool
		alterFunc func(*SubscriptionFilter)
	}{
		{
			"ids",
			false,
			func(f *SubscriptionFilter) {
				f.IDs = []string{}
			},
		},
		{
			"ids",
			false,
			func(f *SubscriptionFilter) {
				f.IDs = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "e6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"}
			},
		},
		{
			"ids",
			false,
			func(f *SubscriptionFilter) {
				f.IDs = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
			},
		},
		{
			"authors",
			false,
			func(f *SubscriptionFilter) {
				f.Authors = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "e6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"}
			},
		},
		{
			"authors",
			false,
			func(f *SubscriptionFilter) {
				f.Authors = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
			},
		},
		{
			"kinds",
			false,
			func(f *SubscriptionFilter) {
				f.Kinds = []int{0, 65536}
			},
		},
		{
			"kinds",
			false,
			func(f *SubscriptionFilter) {
				f.Kinds = []int{0, 99}
			},
		},
		{
			"tags",
			false,
			func(f *SubscriptionFilter) {
				f.Tags = make(map[string][]string)
				f.Tags["e"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
				f.Tags["p"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
			},
		},
		{
			"tags",
			false,
			func(f *SubscriptionFilter) {
				f.Tags = make(map[string][]string)
				f.Tags["e"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
				f.Tags["p"] = []string{"86eff8147c4e72b9807785afee48bb"}
			},
		},
		{
			"tags",
			false,
			func(f *SubscriptionFilter) {
				f.Tags = make(map[string][]string)
				f.Tags["e"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
				f.Tags["p"] = []string{"xa978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
			},
		},
		{
			"tags",
			false,
			func(f *SubscriptionFilter) {
				f.Tags = make(map[string][]string)
				f.Tags["e"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
				f.Tags["p"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
				f.Tags["1p"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
			},
		},
		{
			"tags",
			false,
			func(f *SubscriptionFilter) {
				f.Tags = make(map[string][]string)
				f.Tags["-"] = []string{"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"}
			},
		},
		{
			"tags",
			false,
			func(f *SubscriptionFilter) {
				f.Tags = make(map[string][]string)
			},
		},
		{
			"since",
			false,
			func(f *SubscriptionFilter) {
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := SubscriptionFilter(sampleFilter)
			test.alterFunc(&filter)

			var filter2 SubscriptionFilter
			var filterBytes, filter2Bytes []byte
			var err error

			if filterBytes, err = json.Marshal(filter); err != nil {
				err = fmt.Errorf("failed to parse filter: %w", err)
			} else if err = json.Unmarshal(filterBytes, &filter2); err != nil {
				err = fmt.Errorf("failed to unmarshal filter: %w", err)
			} else if filter2Bytes, err = json.Marshal(filter2); err != nil {
				err = fmt.Errorf("failed to parse filter: %w", err)
			} else if !bytes.Equal(filterBytes, filter2Bytes) {
				err = fmt.Errorf("failed to marshal/unmarshal mismatch objects")
			}

			if err != nil && (err != nil) != test.wantError {
				t.Fatal(err)
			} else if (err == nil) == test.wantError {
				t.Fatalf("error expected")
			}
		})
	}
}

func benchFilter() *SubscriptionFilter {
	return NewFilter().
		WithKinds(1, 7).
		WithAuthors("e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8").
		WithTag("e", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "cd0aa9856147b6c5b4ff2b7dfee5da20aa38253099ef1b4a64aced233c9afe29").
		WithTag("p", "e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8").
		WithLimit(100)
}

func BenchmarkSubscriptionFilterMarshal(b *testing.B) {
	f := benchFilter()
	for b.Loop() {
		if _, err := json.Marshal(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSubscriptionFilterUnmarshal(b *testing.B) {
	data, err := json.Marshal(benchFilter())
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		var f SubscriptionFilter
		if err := json.Unmarshal(data, &f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSubscriptionFilterMatch(b *testing.B) {
	f := benchFilter()
	event := &Event{
		ID:      "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		PubKey:  "e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8",
		Kind:    1,
		Content: "hello",
		Tags: [][]string{
			{"e", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
			{"p", "e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"},
		},
	}
	for b.Loop() {
		f.Match(event)
	}
}
