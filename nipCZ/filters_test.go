package nipCZ

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// T14-11 (S-CZ-48).
func TestFilters(t *testing.T) {
	user, ck1, ck2 := hexKey(t), hexKey(t), hexKey(t)
	in := IncomingFilter(user, []string{ck1, ck2, ck1})
	if !reflect.DeepEqual(in.Tags["p"], []string{user, ck1, ck2}) || !reflect.DeepEqual(in.Kinds, []int{KindCashZap}) {
		t.Fatalf("%+v", in)
	}
	raw, _ := json.Marshal(&in)
	if !strings.Contains(string(raw), `"#p":[`) {
		t.Fatal(string(raw))
	}
	sent := SentFilters(user, []string{ck1, user})
	if len(sent) != 2 || !reflect.DeepEqual(sent[0].Authors, []string{user}) || !reflect.DeepEqual(sent[1].Tags["P"], []string{ck1}) {
		t.Fatalf("%+v", sent)
	}
	if got := SentFilters(user, nil); len(got) != 1 {
		t.Fatal("a #P filter without a ConnectionKey")
	}
}

// T14-08 publish relays, T14-17 IncomingRelays (review 3).
func TestRelays(t *testing.T) {
	f := newFx(t)
	info, _ := ParseCashZapInfo(signInfo(t, f.recipPriv, []string{"relay", "wss://A.example/"}, []string{"relay", "wss://b.example:443"}))
	empty, _ := ParseCashZapInfo(signInfo(t, f.recipPriv, []string{"chain", "bitcoin"}))
	read := []string{"wss://read.example", "wss://read.example/", "https://not-a-relay"}
	ic := []string{"wss://ic.example", "wss://a.example"}

	if got := IncomingRelays(info, read, nil); !reflect.DeepEqual(got, []string{"wss://a.example", "wss://b.example"}) {
		t.Fatalf("%v", got)
	}
	if got := IncomingRelays(info, read, ic); !reflect.DeepEqual(got, []string{"wss://a.example", "wss://b.example", "wss://ic.example"}) {
		t.Fatalf("%v", got)
	}
	for _, i := range []*CashZapInfo{nil, empty} {
		if got := IncomingRelays(i, read, nil); !reflect.DeepEqual(got, []string{"wss://read.example"}) {
			t.Fatalf("%v", got)
		}
	}
	if got := PublishRelays(info, read, []string{"wss://write.example"}, ic); !reflect.DeepEqual(got, []string{"wss://a.example", "wss://b.example", "wss://write.example", "wss://ic.example"}) {
		t.Fatalf("%v", got)
	}
	if got := PublishRelays(nil, read, nil, nil); !reflect.DeepEqual(got, []string{"wss://read.example"}) {
		t.Fatalf("%v", got)
	}
	// The zap lands where it is read.
	for _, i := range []*CashZapInfo{nil, empty, info} {
		for _, icr := range [][]string{nil, ic} {
			pub := PublishRelays(i, read, nil, icr)
			inc := IncomingRelays(i, read, icr)
			for _, r := range pub {
				if !contains(inc, r) {
					t.Fatalf("published to %s, never read there (%v vs %v)", r, pub, inc)
				}
			}
		}
	}
}
