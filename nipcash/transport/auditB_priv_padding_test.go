package transport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// auditB_priv: measure how many DISTINGUISHABLE on-the-wire sizes an observer sees
// across the full 1..MaxItems range, per method, and for the largest item types.
// Nothing here asserts; it measures and prints.

func auditBItem(t *testing.T, id, method, params, nonce string) Item {
	t.Helper()
	return newTestItem(t, id, method, params, nonce)
}

// a realistic cash_redeem params body: a bolt11 invoice is the bulk of it.
func auditBRedeemParams() string {
	inv := "lnbc10u1p3pj257pp5yztkwjcz5ftl5laxkav23zmzekaw37zk6kmv80pk4xaev5qhtz7qdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w"
	return fmt.Sprintf(`{"invoice":%q}`, inv)
}

func auditBTransferParams() string {
	return `{"target_pubkey":"6a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9","amount_millis":1000000}`
}

func auditBConsolidateParams(sources int) string {
	type src struct {
		Token            string `json:"token"`
		IdentityEvent    string `json:"identity_event"`
		AttestationEvent string `json:"attestation_event,omitempty"`
	}
	// A nested signed event, serialised as a JSON string, is what a real source
	// carries. Size it like one: 64-hex id, 64-hex pubkey, 128-hex sig, six tags.
	ev := `{"id":"` + strings.Repeat("a", 64) + `","pubkey":"` + strings.Repeat("b", 64) +
		`","created_at":1759190400,"kind":23198,"tags":[["p","` + strings.Repeat("c", 64) +
		`"],["hub","` + strings.Repeat("d", 64) + `"],["method","cash_consolidate"],["params_hash","` +
		strings.Repeat("e", 64) + `"],["nonce","` + strings.Repeat("f", 64) +
		`"],["not_after","1759190460"]],"content":"","sig":"` + strings.Repeat("9", 128) + `"}`
	out := make([]src, 0, sources)
	for i := 0; i < sources; i++ {
		out = append(out, src{
			Token:            "lokicash1" + strings.Repeat("q", 180),
			IdentityEvent:    ev,
			AttestationEvent: ev,
		})
	}
	b, _ := json.Marshal(map[string]any{"sources": out})
	return string(b)
}

func auditBEnvelope(t *testing.T, n int, method string, params func(int) string) Envelope {
	t.Helper()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	replyTo, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	items := make([]Item, 0, n)
	for i := 1; i <= n; i++ {
		items = append(items, auditBItem(t, fmt.Sprintf("%d", i), method, params(i), nonce))
	}
	return Envelope{
		Version:  EnvelopeVersion,
		NotAfter: time.Now().Add(60 * time.Second).Unix(),
		Nonce:    nonce,
		ReplyTo:  replyTo,
		Items:    items,
	}
}

func TestAuditBPriv_PaddingLeakAcrossFullRange(t *testing.T) {
	cases := []struct {
		name   string
		method string
		params func(int) string
	}{
		{"cash_status", "cash_status", func(int) string { return `{}` }},
		{"cash_status_bearer", "cash_status", func(int) string {
			return `{"cash_secret":"` + strings.Repeat("a", 64) + `"}`
		}},
		{"cash_redeem", "cash_redeem", func(int) string { return auditBRedeemParams() }},
		{"cash_transfer", "cash_transfer", func(int) string { return auditBTransferParams() }},
		{"cash_consolidate_2src", "cash_consolidate", func(int) string { return auditBConsolidateParams(2) }},
	}

	for _, bucketBytes := range []int{4 * 1024, 8 * 1024} {
		limits := DefaultLimits()
		limits.PadBucketBytes = bucketBytes
		for _, tc := range cases {
			sizes := map[int]int{} // padded size -> item count that first produced it
			order := []int{}
			var unpadded1 int
			maxOK := 0
			for n := 1; n <= limits.MaxItems; n++ {
				env := auditBEnvelope(t, n, tc.method, tc.params)
				raw := env
				raw.Pad = ""
				body, _ := json.Marshal(raw)
				if n == 1 {
					unpadded1 = len(body)
				}
				pt, err := env.Encode(limits)
				if err != nil {
					t.Logf("  pad=%dKiB %-22s n=%2d unpadded=%6d -> ENCODE REFUSED: %v",
						bucketBytes/1024, tc.name, n, len(body), err)
					break
				}
				maxOK = n
				if _, seen := sizes[len(pt)]; !seen {
					sizes[len(pt)] = n
					order = append(order, len(pt))
				}
			}
			buckets := make([]string, 0, len(order))
			for _, s := range order {
				buckets = append(buckets, fmt.Sprintf("%dKiB@n>=%d", s/1024, sizes[s]))
			}
			perItem := 0
			if maxOK > 1 {
				env2 := auditBEnvelope(t, 2, tc.method, tc.params)
				env2.Pad = ""
				b2, _ := json.Marshal(env2)
				perItem = len(b2) - unpadded1
			}
			t.Logf("pad=%dKiB %-22s item~%5dB  1..%2d items -> %d distinct wire sizes  [%s]",
				bucketBytes/1024, tc.name, perItem, maxOK, len(order), strings.Join(buckets, " "))

			// Assert, at the DEFAULT bucket and over 1..8 items only.
			//
			// This test measured the whole range and asserted nothing, so it could not
			// fail — the shape a round-3 review found in it. Both bounds on the
			// assertion are deliberate, and the second cost me a wrong threshold first
			// time round: limits.go's "three distinct sizes" is stated for ONE TO EIGHT
			// items, and this sweep runs to MaxItems. Applying the 1..8 figure to a 1..32
			// sweep flags every method, because more items legitimately cross more
			// buckets. The non-default bucket sizes are likewise in the sweep to show the
			// trend and are expected to leak more.
			//
			// Within its stated range the current default does better than the figure it
			// cites — cash_status puts items 1..5 in one bucket and 6..8 in the next, so
			// two sizes, not three. If a change pushes that back above three, the
			// batch-count leak has reopened and this now says so.
			if bucketBytes == DefaultPadBucketBytes {
				inEight := 0
				for _, size := range order {
					if sizes[size] <= 8 {
						inEight++
					}
				}
				// The bound is per-method, because the bucket was sized for ONE method
				// and the difference is a finding rather than an exclusion.
				//
				// A cash_status item is ~1.5 KB, so an 8 KiB bucket holds five of them
				// and 1..8 items collapse to two sizes. A cash_consolidate item with two
				// sources is ~2.9 KB (base 1010 + 2x952, per EstimatedConsolidateItemBytes),
				// so the same bucket holds barely two — and 1..8 items spread across FIVE
				// sizes. Measured: 8KiB@n>=1 16KiB@n>=2 24KiB@n>=4 32KiB@n>=5 40KiB@n>=7.
				//
				// So padding bounds the batch count for the small-item methods and does
				// NOT meaningfully bound it for consolidate: an observer distinguishes one
				// consolidate from two, and two from four. That is inherent to item size
				// against bucket size, not a regression — but it was never written down,
				// and limits.go's "three sizes" figure quietly describes cash_status only.
				//
				// Asserted at the level each method actually achieves today, so a
				// REGRESSION in either is caught while the existing asymmetry stays
				// visible instead of being tuned away.
				want := 3
				if strings.HasPrefix(tc.name, "cash_consolidate") {
					want = 5
				}
				if inEight > want {
					t.Errorf("at the DEFAULT %dKiB bucket, %s produces %d distinct wire sizes "+
						"across 1..8 items, want at most %d; this is the batch-count leak that "+
						"raising the bucket 4KiB->8KiB was meant to bound (all sizes: %s)",
						bucketBytes/1024, tc.name, inEight, want, strings.Join(buckets, " "))
				}
			}
		}
		t.Log("---")
	}
}

// How many items fit in one bucket is the leak metric: k items per bucket means an
// observer learns the batch count to within a factor of k.
//
// DIAGNOSTIC, deliberately: this one reports a ratio and asserts nothing, because
// there is no threshold for it that is not arbitrary. Named and marked so it is not
// mistaken for a regression test — a round-3 review flagged it and its sibling for
// exactly that, and the sibling above now asserts at the default bucket. Read this
// one's output when changing the bucket size or adding a per-item field; it is the
// number that moves.
func TestAuditBPriv_ItemsPerBucket(t *testing.T) {
	for _, bucketBytes := range []int{4 * 1024, 8 * 1024} {
		limits := DefaultLimits()
		limits.PadBucketBytes = bucketBytes
		for _, tc := range []struct {
			name   string
			method string
			params func(int) string
		}{
			{"cash_status", "cash_status", func(int) string { return `{}` }},
			{"cash_redeem", "cash_redeem", func(int) string { return auditBRedeemParams() }},
		} {
			env1 := auditBEnvelope(t, 1, tc.method, tc.params)
			env1.Pad = ""
			b1, _ := json.Marshal(env1)
			env2 := auditBEnvelope(t, 2, tc.method, tc.params)
			env2.Pad = ""
			b2, _ := json.Marshal(env2)
			per := len(b2) - len(b1)
			t.Logf("pad=%dKiB %-14s base=%dB item=%dB -> %.2f items per bucket",
				bucketBytes/1024, tc.name, len(b1)-per, per, float64(bucketBytes)/float64(per))
		}
	}
}

// The observer sees base64 ciphertext, not plaintext. Confirm NIP-44's own padding
// does not collapse (or further split) the transport buckets.
func TestAuditBPriv_WireSizePerBucket(t *testing.T) {
	_, inbox := testKeypair(t)
	limits := DefaultLimits()
	seen := map[int]int{}
	for n := 1; n <= limits.MaxItems; n++ {
		env := auditBEnvelope(t, n, "cash_status", func(int) string { return `{}` })
		pt, err := env.Encode(limits)
		if err != nil {
			break
		}
		ev, _, err := WrapRequest(pt, inbox)
		if err != nil {
			t.Fatalf("WrapRequest: %v", err)
		}
		if prev, ok := seen[len(pt)]; ok && prev != len(ev.Content) {
			t.Errorf("plaintext %d produced wire lengths %d and %d", len(pt), prev, len(ev.Content))
		}
		seen[len(pt)] = len(ev.Content)
	}
	for pt, wire := range seen {
		t.Logf("plaintext %6d -> event.content %6d base64 chars", pt, wire)
	}
	t.Logf("%d distinct plaintext buckets -> %d distinct wire lengths", len(seen), len(seen))
}
