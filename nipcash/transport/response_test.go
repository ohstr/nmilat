package transport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testResponse(t *testing.T, reqNonce string, results ...Result) ResponseEnvelope {
	t.Helper()
	return ResponseEnvelope{Version: EnvelopeVersion, ReqNonce: reqNonce, Results: results}
}

func TestResponse_RoundTrip(t *testing.T) {
	limits := DefaultLimits()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	resp := testResponse(t, nonce,
		Result{ID: "1", ResultType: "cash_status", Result: json.RawMessage(`{"amount_millis":1000}`)},
		Result{ID: "2", Error: &ResultError{Code: "RATE_LIMITED", Message: "slow down"}},
	)

	plaintext, err := resp.EncodeResponse(limits)
	if err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}
	if len(plaintext)%limits.PadBucketBytes != 0 {
		t.Errorf("response is %d bytes, not padded to a %d bucket", len(plaintext), limits.PadBucketBytes)
	}

	decoded, err := DecodeResponse(plaintext, nonce, []string{"1", "2"}, limits)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if len(decoded.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(decoded.Results))
	}
	if decoded.Results[1].Error == nil || decoded.Results[1].Error.Code != "RATE_LIMITED" {
		t.Error("the per-item error did not survive")
	}
}

// TestResponse_RejectsAnswerToAnotherRequest closes a confusion vector: a client
// must not accept a response produced for some other envelope.
func TestResponse_RejectsAnswerToAnotherRequest(t *testing.T) {
	limits := DefaultLimits()
	mine, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := testResponse(t, theirs, Result{ID: "1"}).EncodeResponse(limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(plaintext, mine, []string{"1"}, limits); !errors.Is(err, ErrResponseMismatch) {
		t.Fatalf("DecodeResponse() = %v, want ErrResponseMismatch", err)
	}
}

// TestResponse_RejectsUnrequestedItemID is the other half: a hub must not be able
// to inject a result for an id the client never sent, which a client demuxing by id
// would otherwise attribute to something.
func TestResponse_RejectsUnrequestedItemID(t *testing.T) {
	limits := DefaultLimits()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := testResponse(t, nonce, Result{ID: "99"}).EncodeResponse(limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(plaintext, nonce, []string{"1", "2"}, limits); !errors.Is(err, ErrUnknownItemID) {
		t.Fatalf("DecodeResponse() = %v, want ErrUnknownItemID", err)
	}
}

func TestResponse_RejectsDuplicateAndContradictoryResults(t *testing.T) {
	limits := DefaultLimits()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	dup, err := testResponse(t, nonce, Result{ID: "1"}, Result{ID: "1"}).EncodeResponse(limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(dup, nonce, []string{"1"}, limits); !errors.Is(err, ErrResponseMalformed) {
		t.Errorf("duplicate result id: got %v, want ErrResponseMalformed", err)
	}

	both, err := testResponse(t, nonce, Result{
		ID:     "1",
		Result: json.RawMessage(`{"ok":true}`),
		Error:  &ResultError{Code: "INTERNAL"},
	}).EncodeResponse(limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(both, nonce, []string{"1"}, limits); !errors.Is(err, ErrResponseMalformed) {
		t.Errorf("result and error together: got %v, want ErrResponseMalformed", err)
	}
}

// TestResponse_OmissionIsNotAnError is the oracle-closure property. An item whose
// proof did not verify, or whose target the hub does not serve, is simply absent —
// and a caller must read that as "not served", never as a statement about the bill.
func TestResponse_OmissionIsNotAnError(t *testing.T) {
	limits := DefaultLimits()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	// Two items requested, only one answered.
	plaintext, err := testResponse(t, nonce,
		Result{ID: "1", ResultType: "cash_status", Result: json.RawMessage(`{}`)},
	).EncodeResponse(limits)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeResponse(plaintext, nonce, []string{"1", "2"}, limits)
	if err != nil {
		t.Fatalf("a partial response must decode cleanly: %v", err)
	}
	omitted := decoded.Omitted([]string{"1", "2"})
	if len(omitted) != 1 || omitted[0] != "2" {
		t.Fatalf("Omitted() = %v, want [2]", omitted)
	}
	// And crucially there is no per-item error for it, since an error would
	// confirm something about a wallet the caller could not prove it holds.
	for _, result := range decoded.Results {
		if result.ID == "2" {
			t.Error("the unserved item was answered; omission is what closes the existence oracle")
		}
	}
}

// TestResponse_PaddingHidesResultCount mirrors the request side: a one-result
// response and a several-result one must be the same size on the wire.
func TestResponse_PaddingHidesResultCount(t *testing.T) {
	limits := DefaultLimits()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	sizes := map[int]struct{}{}
	for count := 1; count <= 6; count++ {
		results := make([]Result, 0, count)
		for i := 1; i <= count; i++ {
			id := string(rune('0' + i))
			results = append(results, Result{ID: id, ResultType: "cash_status", Result: json.RawMessage(`{"amount_millis":1000}`)})
		}
		plaintext, err := testResponse(t, nonce, results...).EncodeResponse(limits)
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(plaintext)] = struct{}{}
	}
	if len(sizes) != 1 {
		t.Errorf("1-6 results produced %d distinct wire sizes, padding is leaking the count", len(sizes))
	}
}

func TestDeriveReplyKey(t *testing.T) {
	var conversationKey [32]byte
	for i := range conversationKey {
		conversationKey[i] = byte(i)
	}
	a, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	keyA, err := DeriveReplyKey(conversationKey, a)
	if err != nil {
		t.Fatalf("DeriveReplyKey: %v", err)
	}

	// Deterministic: the hub and the client must land on the same key.
	again, err := DeriveReplyKey(conversationKey, a)
	if err != nil {
		t.Fatal(err)
	}
	if keyA != again {
		t.Error("DeriveReplyKey is not deterministic")
	}

	// Different tag, different key — otherwise two exchanges on one conversation
	// key would share a response key.
	keyB, err := DeriveReplyKey(conversationKey, b)
	if err != nil {
		t.Fatal(err)
	}
	if keyA == keyB {
		t.Error("two reply tags derived the same key")
	}

	// Different conversation key, different key, even for the same tag.
	var other [32]byte
	other[0] = 0xff
	keyOther, err := DeriveReplyKey(other, a)
	if err != nil {
		t.Fatal(err)
	}
	if keyA == keyOther {
		t.Error("the derived key does not depend on the conversation key")
	}

	// And it must never be the conversation key itself.
	if keyA == conversationKey {
		t.Error("the reply key is the conversation key verbatim")
	}

	for _, bad := range []string{"", "abc", strings.ToUpper(a), strings.Repeat("z", 64)} {
		if _, err := DeriveReplyKey(conversationKey, bad); err == nil {
			t.Errorf("DeriveReplyKey(%q) succeeded, want an error", bad)
		}
	}
}

// FuzzDecodeResponse is the response side of FuzzDecode (envelope_test.go). The
// request side has had a fuzz target since the transport landed; this one did not,
// and it is the side that parses bytes chosen by the HUB — the adversary in session
// C's model, and the one whose output a client then acts on with money.
//
// The invariants asserted are exactly the ones DecodeResponse promises, no more: a
// later stage relies on them without re-checking, so anything that decodes must
// satisfy them. In particular it does NOT assert an upper bound on Total — nothing
// here bounds it, deliberately, because a Hub legitimately discovers its reply's size
// only after serving the items. Bounding that is the client's job (batch_send's chunk
// accounting), and asserting it here would describe a guarantee this function does
// not make.
func FuzzDecodeResponse(f *testing.F) {
	limits := DefaultLimits()
	const reqNonce = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	requestedIDs := []string{"1", "2", "3"}

	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","seq":1,"total":1,"results":[{"id":"1","result":{}}]}`))
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `"}`))                                     // terse: seq/total omitted
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","seq":0,"total":0,"results":[]}`))      // the tolerated 0/0
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","seq":2,"total":1}`))                   // past the end
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","seq":1,"total":0}`))                   // total below 1
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","seq":-1,"total":-1}`))                 // negative both
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","seq":1,"total":9223372036854775807}`)) // int64 max
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","results":[{"id":"1"},{"id":"1"}]}`))   // duplicate id
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","results":[{"id":"nope"}]}`))           // never requested
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","results":[{"id":"1","result":{},"error":{"code":"x"}}]}`))
	f.Add([]byte(`{"v":1,"req_nonce":"wrong","results":[]}`)) // another request's reply
	f.Add([]byte(`{"v":2,"req_nonce":"` + reqNonce + `"}`))   // a version this client cannot read
	f.Add([]byte(`{"v":1,"req_nonce":null,"results":null}`))
	f.Add([]byte(`{"v":1,"req_nonce":"` + reqNonce + `","results":[{"id":"1","result":{`)) // truncated
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeResponse(data, reqNonce, requestedIDs, limits)
		if err != nil {
			if decoded != nil {
				t.Fatal("returned both an envelope and an error")
			}
			return
		}
		if decoded == nil {
			t.Fatal("returned neither an envelope nor an error")
		}
		if len(data) > limits.MaxEnvelopeBytes {
			t.Fatalf("accepted %d bytes over the %d limit", len(data), limits.MaxEnvelopeBytes)
		}
		if decoded.Version != EnvelopeVersion {
			t.Fatalf("accepted version %d", decoded.Version)
		}
		// The reply is bound to THIS request. Accepting another's is how a hostile
		// relay replays one envelope's answer as another's.
		if decoded.ReqNonce != reqNonce {
			t.Fatalf("accepted req_nonce %q, wanted %q", decoded.ReqNonce, reqNonce)
		}
		if decoded.Total < 1 || decoded.Seq < 1 || decoded.Seq > decoded.Total {
			t.Fatalf("accepted seq %d of %d, which is not a position in a reply", decoded.Seq, decoded.Total)
		}

		known := map[string]bool{}
		for _, id := range requestedIDs {
			known[id] = true
		}
		seen := map[string]bool{}
		for _, result := range decoded.Results {
			if !known[result.ID] {
				t.Fatalf("accepted a result for %q, which was never requested", result.ID)
			}
			if seen[result.ID] {
				t.Fatalf("accepted two results for %q", result.ID)
			}
			seen[result.ID] = true
			if result.Result != nil && result.Error != nil {
				t.Fatalf("accepted item %q carrying both a result and an error", result.ID)
			}
		}
		// Which gives the bound the response side has instead of MaxItems: results
		// are a subset of what was asked, so a Hub cannot inflate the reply with ids
		// of its own choosing.
		if len(decoded.Results) > len(requestedIDs) {
			t.Fatalf("accepted %d results for %d requested ids", len(decoded.Results), len(requestedIDs))
		}

		// Omitted must partition the request exactly: every requested id is either
		// answered or omitted, never both and never neither. A caller decides whether
		// a spend may be resent from this, so a gap here is a double-spend question.
		omitted := decoded.Omitted(requestedIDs)
		for _, id := range omitted {
			if seen[id] {
				t.Fatalf("%q is reported as omitted but was answered", id)
			}
			if !known[id] {
				t.Fatalf("%q is reported as omitted but was never requested", id)
			}
		}
		if len(omitted)+len(seen) != len(requestedIDs) {
			t.Fatalf("%d omitted + %d answered != %d requested", len(omitted), len(seen), len(requestedIDs))
		}
	})
}
