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
