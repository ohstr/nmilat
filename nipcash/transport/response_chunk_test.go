package transport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// DecodeResponseChunk refuses only an unusable chunk; everything else is reported
// for the caller holding every chunk to weigh (NIP-CASH §Chunked Replies).
func TestDecodeResponseChunk_ReportsInsteadOfRefusing(t *testing.T) {
	nonce := strings.Repeat("ab", 32)
	plain := `{"v":7,"req_nonce":"` + nonce + `","seq":0,"total":9,"results":[` +
		`{"id":"a","result_type":"cash_status","result":{}},` +
		`{"id":"alien","result_type":"cash_status","result":{}},` +
		`{"id":"a","error":{"code":"NOT_FOUND"}},` +
		`{"id":"b","result_type":"cash_status","result":{},"error":{"code":"INTERNAL"}}]}`
	c, err := DecodeResponseChunk([]byte(plain), nonce, []string{"a", "b"}, 0)
	if err != nil {
		t.Fatalf("DecodeResponseChunk: %v", err)
	}
	if len(c.Results) != 3 || len(c.AlienIDs) != 1 || c.AlienIDs[0] != "alien" {
		t.Fatalf("results %d, alien %v: want 3 kept and the alien dropped", len(c.Results), c.AlienIDs)
	}
	if len(c.DuplicateIDs) != 1 || c.DuplicateIDs[0] != "a" {
		t.Errorf("duplicates = %v, want [a]", c.DuplicateIDs)
	}
	if c.Seq != 0 || c.Total != 9 {
		t.Errorf("seq/total = %d/%d, want them as sent", c.Seq, c.Total)
	}
	if !c.Results[2].HasBoth() {
		t.Error("a result with both a body and an error must be reported")
	}

	if _, err := DecodeResponseChunk([]byte(`{`), nonce, nil, 0); !errors.Is(err, ErrResponseMalformed) {
		t.Errorf("bad JSON: %v", err)
	}
	if _, err := DecodeResponseChunk([]byte(`{"req_nonce":"x","results":[]}`), nonce, nil, 0); !errors.Is(err, ErrResponseMismatch) {
		t.Errorf("foreign nonce: %v", err)
	}
	big := `{"req_nonce":"` + nonce + `","results":[],"pad":"` + strings.Repeat("0", MaxNIP44Plaintext) + `"}`
	if _, err := DecodeResponseChunk([]byte(big), nonce, nil, 1024); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("over max(maxBytes, 65535): %v", err)
	}
	fits := big[:MaxNIP44Plaintext-2] + `"}`
	if _, err := DecodeResponseChunk([]byte(fits), nonce, nil, 1024); err != nil && errors.Is(err, ErrEnvelopeTooLarge) {
		t.Errorf("65535 bytes refused for size under a smaller max_bytes: %v", err)
	}
}

// A chunk with neither results nor error decides nothing; "results": [] is a
// complete answer of omissions, and EncodeResponse writes it for an empty reply.
func TestResponse_EmptyResultsAreWritten(t *testing.T) {
	nonce := strings.Repeat("ab", 32)
	enc, err := ResponseEnvelope{Version: EnvelopeVersion, ReqNonce: nonce}.EncodeResponse(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(enc), `"results":[]`) {
		t.Fatalf("no explicit empty results: %s", enc[:80])
	}
	c, err := DecodeResponseChunk(enc, nonce, nil, 0)
	if err != nil || c.DecidesNothing() {
		t.Fatalf("empty results read as deciding nothing: %v", err)
	}

	withErr, err := json.Marshal(ResponseEnvelope{ReqNonce: nonce, Error: &ResultError{Code: "QUOTA_EXCEEDED"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(withErr), "results") {
		t.Errorf("an envelope-level error carries no results: %s", withErr)
	}
	c, err = DecodeResponseChunk([]byte(`{"req_nonce":"`+nonce+`","seq":1,"total":1}`), nonce, nil, 0)
	if err != nil || !c.DecidesNothing() {
		t.Fatalf("a chunk with neither must decide nothing (err %v)", err)
	}
}

// T01-16 (transport half): detail travels on item and envelope errors; absent is "".
func TestResultError_Detail(t *testing.T) {
	var e ResultError
	if err := json.Unmarshal([]byte(`{"code":"RESTRICTED","message":"m","detail":"own_address"}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Detail != "own_address" {
		t.Errorf("detail = %q", e.Detail)
	}
	b, _ := json.Marshal(ResultError{Code: "RESTRICTED"})
	if strings.Contains(string(b), "detail") {
		t.Errorf("an empty detail is omitted: %s", b)
	}
}
