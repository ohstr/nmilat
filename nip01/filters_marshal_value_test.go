package nip01

import (
	"encoding/json"
	"strings"
	"testing"
)

// Marshalling a filter by value keeps its tag filters (a value receiver).
func TestSubscriptionFilter_MarshalByValueKeepsTags(t *testing.T) {
	f := SubscriptionFilter{Kinds: []int{1}, Tags: map[string][]string{"p": {"ab"}}}
	byValue, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	byPtr, _ := json.Marshal(&f)
	inSlice, _ := json.Marshal([]SubscriptionFilter{f})
	if !strings.Contains(string(byValue), `"#p":["ab"]`) || string(byValue) != string(byPtr) ||
		!strings.Contains(string(inSlice), `"#p":["ab"]`) {
		t.Fatalf("by value %s, by pointer %s, in a slice %s", byValue, byPtr, inSlice)
	}
}
