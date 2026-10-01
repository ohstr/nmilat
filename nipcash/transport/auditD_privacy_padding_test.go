package transport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// auditD_privacy: what an OBSERVER reads off a ciphertext length.
//
// A prior pass measured request padding while varying the ITEM COUNT at a fixed
// two-source consolidate. Two things it did not measure are measured here, because
// both are things an observer learns and neither is bounded by the bucket:
//
//  1. the SOURCE count inside one cash_consolidate item. One item, 2..48 sources,
//     is 2.9 KB to 46 KB — six to seven buckets wide. The bucket cannot hide a
//     quantity that is itself many buckets large, so "how many slices is this
//     person combining" is readable from one event.
//  2. the RESPONSE side. ResponseEnvelope.EncodeResponse pads to the same bucket,
//     but a cash_status roster grows with the bill's recipient count, and nothing
//     in the audit trail had measured what the reply length discloses.

func auditDNonce(t *testing.T) string {
	t.Helper()
	n, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// auditDConsolidateParams sizes a consolidate params body like a real one: each
// source carries a token plus its nested signed identity event.
//
// Deliberately sized to AGREE with the figure limits.go measured
// (consolidateItemPerSourceBytes = 952), so the measurement below speaks to the
// shipped default rather than to a fixture of my own choosing. The test logs the
// per-source cost it actually achieved so the agreement is visible, not asserted.
func auditDConsolidateParams(sources int) string {
	type src struct {
		Token         string `json:"token"`
		IdentityEvent string `json:"identity_event"`
	}
	ev := `{"id":"` + strings.Repeat("a", 64) + `","pubkey":"` + strings.Repeat("b", 64) +
		`","created_at":1759190400,"kind":23198,"tags":[["p","` + strings.Repeat("c", 64) +
		`"],["hub","` + strings.Repeat("d", 64) + `"],["method","cash_consolidate"],["params_hash","` +
		strings.Repeat("e", 64) + `"],["nonce","` + strings.Repeat("f", 64) +
		`"],["not_after","1759190460"]],"content":"","sig":"` + strings.Repeat("9", 128) + `"}`
	out := make([]src, 0, sources)
	for i := 0; i < sources; i++ {
		out = append(out, src{
			Token:         "lokicash1" + strings.Repeat("q", 180),
			IdentityEvent: ev,
		})
	}
	b, _ := json.Marshal(map[string]any{"sources": out})
	return string(b)
}

func auditDEnvelope(t *testing.T, items []Item, nonce string) Envelope {
	t.Helper()
	return Envelope{
		Version:  EnvelopeVersion,
		NotAfter: time.Now().Add(60 * time.Second).Unix(),
		Nonce:    nonce,
		ReplyTo:  auditDNonce(t),
		Items:    items,
	}
}

// TestAuditDPrivacy_ConsolidateSourceCountIsReadableOffTheWire measures what one
// cash_consolidate item's ciphertext length says about how many slices it combines.
//
// This is an AMOUNTS-adjacent leak, a tier above batch size on this round's scale:
// the source count is how fragmented the sender's holdings are and how many
// counterparties previously paid them.
func TestAuditDPrivacy_ConsolidateSourceCountIsReadableOffTheWire(t *testing.T) {
	limits := DefaultLimits()
	_, inbox := testKeypair(t)

	type row struct {
		sources   int
		unpadded  int
		padded    int
		wireChars int
	}
	var rows []row
	bucketOf := map[int][]int{} // padded size -> source counts landing there

	for n := minConsolidateSources; n <= limits.MaxConsolidateSources; n++ {
		nonce := auditDNonce(t)
		item := newTestItem(t, "1", "cash_consolidate", auditDConsolidateParams(n), nonce)
		env := auditDEnvelope(t, []Item{item}, nonce)

		raw := env
		raw.Pad = ""
		body, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := env.Encode(limits)
		if err != nil {
			t.Fatalf("sources=%d: Encode: %v", n, err)
		}
		ev, _, err := WrapRequest(pt, inbox)
		if err != nil {
			t.Fatalf("sources=%d: WrapRequest: %v", n, err)
		}
		rows = append(rows, row{n, len(body), len(pt), len(ev.Content)})
		bucketOf[len(pt)] = append(bucketOf[len(pt)], n)
	}

	for _, r := range rows {
		t.Logf("sources=%2d unpadded=%6d padded=%6d wire(base64)=%6d", r.sources, r.unpadded, r.padded, r.wireChars)
	}
	if len(rows) >= 2 {
		perSource := (rows[len(rows)-1].unpadded - rows[0].unpadded) /
			(rows[len(rows)-1].sources - rows[0].sources)
		t.Logf("measured per-source cost %d bytes (limits.go's own figure: %d)",
			perSource, consolidateItemPerSourceBytes)
	}

	// How precisely does the observer learn the source count? Per distinct wire
	// length, how many source counts are indistinguishable.
	worst, best := 0, 1<<30
	for size, ns := range bucketOf {
		if len(ns) > worst {
			worst = len(ns)
		}
		if len(ns) < best {
			best = len(ns)
		}
		t.Logf("padded=%6d (%2d KiB) <- sources %v", size, size/1024, ns)
	}
	t.Logf("SUMMARY: sources %d..%d produce %d distinct wire lengths; "+
		"best anonymity set %d source counts, worst %d",
		minConsolidateSources, limits.MaxConsolidateSources, len(bucketOf), best, worst)

	// The assertion is the privacy consequence, not the arithmetic: at the DEFAULT
	// policy, one single-item consolidate envelope must not sort the legal source
	// range into more than a handful of observable classes. It does; this records
	// the number so a change is visible, and fails if the resolution gets finer.
	if len(bucketOf) > 7 {
		t.Errorf("one consolidate item sorts sources %d..%d into %d distinguishable wire "+
			"lengths at the default %d-byte bucket; padding is not bounding the source count",
			minConsolidateSources, limits.MaxConsolidateSources, len(bucketOf), limits.PadBucketBytes)
	}
	if best < 2 {
		t.Errorf("at least one wire length identifies an EXACT source count (anonymity set 1)")
	}
}

// TestAuditDPrivacy_ResponseLengthLeaksRosterSize measures the reply side.
//
// A cash_status result carries the bill's roster. The hub pads the reply to the same
// bucket, so the question is how many roster entries fit in one bucket — i.e. how
// precisely an observer reads "how many recipients does this bill have" off a reply
// it cannot decrypt.
func TestAuditDPrivacy_ResponseLengthLeaksRosterSize(t *testing.T) {
	limits := DefaultLimits()

	// One roster entry as cash_status actually returns it: a pubkey, an amount, a
	// state and a timestamp.
	entry := func(i int) string {
		return fmt.Sprintf(
			`{"recipient_pubkey":%q,"amount_millis":%d,"state":"unclaimed","claimed_at":null,"transfer_count":0}`,
			strings.Repeat(fmt.Sprintf("%x", i%16), 64), 1000000+int64(i))
	}

	bucketOf := map[int][]int{}
	for n := 1; n <= 200; n++ {
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			parts = append(parts, entry(i))
		}
		result := fmt.Sprintf(`{"total_millis":%d,"identity_mode":"signing","slices":[%s]}`,
			int64(n)*1000000, strings.Join(parts, ","))

		resp := ResponseEnvelope{
			Version:  EnvelopeVersion,
			ReqNonce: auditDNonce(t),
			Seq:      1,
			Total:    1,
			Results: []Result{{
				ID: "1", ResultType: "cash_status", Result: json.RawMessage(result),
			}},
		}
		pt, err := resp.EncodeResponse(limits)
		if err != nil {
			t.Logf("roster=%3d: EncodeResponse refused: %v", n, err)
			break
		}
		bucketOf[len(pt)] = append(bucketOf[len(pt)], n)
	}

	sizes := make([]int, 0, len(bucketOf))
	for size := range bucketOf {
		sizes = append(sizes, size)
	}
	for i := 0; i < len(sizes); i++ {
		for j := i + 1; j < len(sizes); j++ {
			if sizes[j] < sizes[i] {
				sizes[i], sizes[j] = sizes[j], sizes[i]
			}
		}
	}
	worst := 0
	for _, size := range sizes {
		ns := bucketOf[size]
		if len(ns) > worst {
			worst = len(ns)
		}
		t.Logf("reply padded=%6d (%2d KiB) <- roster sizes %d..%d (%d values)",
			size, size/1024, ns[0], ns[len(ns)-1], len(ns))
	}
	t.Logf("SUMMARY: a one-item cash_status reply sorts roster sizes into %d observable "+
		"classes; coarsest class holds %d roster sizes. An observer reads the recipient "+
		"count to within ~%d.", len(sizes), worst, worst)

	if len(sizes) < 2 {
		t.Skip("every roster size landed in one bucket; nothing to report")
	}
}

// TestAuditDPrivacy_ClientNeverChecksTheReplyWasPadded is the asymmetry behind both
// measurements above: padding of the REQUEST is the client's own doing and is
// enforced by Encode, but padding of the REPLY is the hub's unilateral choice and
// NOTHING on the client side verifies it happened.
//
// MinPadBucketBytes guards the ANNOUNCED policy (ParseAnnouncement -> ValidateAnnounced),
// so a hub cannot talk a client into unpadded REQUESTS. It says nothing about what the
// hub then does on the way back.
func TestAuditDPrivacy_ClientNeverChecksTheReplyWasPadded(t *testing.T) {
	// What the client believes, from the announcement it validated.
	announced := DefaultLimits()
	if err := announced.ValidateAnnounced(); err != nil {
		t.Fatalf("default limits are not announceable: %v", err)
	}

	// What the hub actually pads with: a bucket far below the floor, which Validate
	// (the hub's own check, config.PrivateEnvelopeLimits) accepts.
	hubSide := DefaultLimits()
	hubSide.PadBucketBytes = 1
	if err := hubSide.Validate(); err != nil {
		t.Fatalf("a hub CANNOT configure pad_bucket_bytes=1 after all: %v", err)
	}
	if err := hubSide.ValidateAnnounced(); err == nil {
		t.Fatalf("pad_bucket_bytes=1 passed ValidateAnnounced; the floor is gone")
	}

	nonce := auditDNonce(t)
	ids := []string{"a", "b", "c"}
	for n := 1; n <= len(ids); n++ {
		resp := ResponseEnvelope{Version: EnvelopeVersion, ReqNonce: nonce, Seq: 1, Total: 1}
		for i := 0; i < n; i++ {
			resp.Results = append(resp.Results, Result{
				ID: ids[i], ResultType: "cash_status", Result: json.RawMessage(`{"total_millis":1000000}`),
			})
		}
		// Hub encodes with its own (unpadded) policy.
		pt, err := resp.EncodeResponse(hubSide)
		if err != nil {
			t.Fatalf("hub encode: %v", err)
		}
		// Client decodes with the ANNOUNCED policy and accepts it without complaint.
		if _, err := DecodeResponse(pt, nonce, ids, announced); err != nil {
			t.Fatalf("client refused the under-padded reply (good, but unexpected): %v", err)
		}
		t.Logf("results=%d: hub emitted %d bytes under pad_bucket_bytes=1; "+
			"client accepted it against an announced bucket of %d",
			n, len(pt), announced.PadBucketBytes)
	}
	t.Log("DecodeResponse checks version, req_nonce, seq/total, ids and the MAX size. " +
		"It never checks that len(plaintext) is a multiple of the announced PadBucketBytes, " +
		"so an observer-visible leak on the reply path is undetectable to the client.")
}

// TestAuditDPrivacy_MethodIsReadableOnceTheFirstBucketIsLeft asks the question the
// bucket was actually chosen to answer, and asks it of the METHOD rather than the
// item count: given one envelope, can an observer tell what the sender is doing?
//
// Inside the first bucket, no — every small-item method lands on 8192. Past it,
// yes, because the methods have different per-item costs and the bucket index
// becomes a (coarse) readout of bytes, which is a readout of method x count.
func TestAuditDPrivacy_MethodIsReadableOnceTheFirstBucketIsLeft(t *testing.T) {
	limits := DefaultLimits()

	redeemParams := `{"invoice":"lnbc10u1p3pj257pp5yztkwjcz5ftl5laxkav23zmzekaw37zk6kmv80pk4xaev5qhtz7qdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w"}`
	methods := []struct {
		name, method, params string
	}{
		{"cash_status", "cash_status", `{}`},
		{"cash_transfer", "cash_transfer", `{"target_pubkey":"6a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9","amount_millis":1000000}`},
		{"cash_redeem", "cash_redeem", redeemParams},
		{"cash_consolidate/2src", "cash_consolidate", auditDConsolidateParams(2)},
		{"cash_consolidate/10src", "cash_consolidate", auditDConsolidateParams(10)},
		{"cash_consolidate/48src", "cash_consolidate", auditDConsolidateParams(48)},
	}

	// For each item count, which methods are distinguishable from each other.
	for _, n := range []int{1, 2, 4, 8, 16, 32} {
		byMethod := map[string]int{}
		distinct := map[int][]string{}
		for _, m := range methods {
			nonce := auditDNonce(t)
			items := make([]Item, 0, n)
			for i := 1; i <= n; i++ {
				items = append(items, newTestItem(t, fmt.Sprintf("%d", i), m.method, m.params, nonce))
			}
			pt, err := auditDEnvelope(t, items, nonce).Encode(limits)
			if err != nil {
				byMethod[m.name] = -1
				continue
			}
			byMethod[m.name] = len(pt)
			distinct[len(pt)] = append(distinct[len(pt)], m.name)
		}
		parts := make([]string, 0, len(methods))
		for _, m := range methods {
			if byMethod[m.name] < 0 {
				parts = append(parts, fmt.Sprintf("%s=refused", m.name))
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=%dKiB", m.name, byMethod[m.name]/1024))
		}
		t.Logf("items=%2d -> %d distinct padded sizes across %d methods  [%s]",
			n, len(distinct), len(methods), strings.Join(parts, " "))
	}
	t.Log("At n=1 every SMALL-item method collapses to one bucket, which is the property " +
		"the bucket exists for. A consolidate does not: its source count alone spans six " +
		"buckets, so any consolidate past ~6 sources is distinguishable from every other " +
		"single-item request by length alone.")
}
