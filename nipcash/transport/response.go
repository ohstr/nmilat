package transport

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// replyKeyInfo namespaces the reply-key derivation so the derived key can never
// collide with a NIP-44 conversation key used for anything else.
const replyKeyInfo = "nipcash-reply-v1"

var (
	ErrResponseMalformed = errors.New("transport: response envelope is malformed")
	ErrResponseMismatch  = errors.New("transport: response answers a different request")
	ErrUnknownItemID     = errors.New("transport: response references an unknown item id")
)

// Result is one item's outcome. Exactly one of Result or Error is set.
type Result struct {
	ID         string          `json:"id"`
	ResultType string          `json:"result_type,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      *ResultError    `json:"error,omitempty"`
}

// ResultError mirrors NIP-47's own error shape so per-item failures read the same
// as a single-request failure does today.
type ResultError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
	// Detail is the error's optional machine-readable refinement (NIP-CASH
	// §Errors). It is kept raw here: a value outside the ones the spec lists is
	// read as no detail by whoever interprets it, never refused at decode.
	Detail string `json:"detail,omitempty"`
}

// ResponseEnvelope is the plaintext of a kind-23191 response.
//
// Results deliberately need not cover every item. An item whose target is
// unknown, or whose proof did not verify, is OMITTED rather than answered with an
// error — that is what keeps batching from becoming an existence oracle, since
// producing a verifying proof requires the connection secret in the first place.
// A caller reads an omission as "not served", which carries the same information
// an error would without confirming anything about what the hub holds.
type ResponseEnvelope struct {
	// ReqNonce ties this response to the request that produced it, so a client
	// cannot be confused by a response to something else.
	ReqNonce string `json:"req_nonce"`
	// Error is set only for an envelope-level rejection, where no item ran.
	Error   *ResultError `json:"error,omitempty"`
	Results []Result     `json:"results,omitempty"`
	// Seq and Total let one request be answered by several events, all sharing the
	// same reply_to tag (NIP-CASH §Chunked Replies). Seq counts from 1; a
	// single-event reply is 1 of 1.
	//
	// Total is load-bearing rather than decorative, for a reason specific to this
	// protocol: OMISSION is a valid final answer, so a client cannot simply collect
	// until every id it sent has been answered — that waits forever for an omitted
	// item, and is indistinguishable from waiting for a chunk still in flight.
	// Without an explicit total, "omitted" and "not arrived yet" cannot be told
	// apart, which would destroy the property the omission rule exists to provide.
	//
	// Relay end-of-stored-events cannot serve instead. A client subscribes BEFORE
	// publishing (these kinds are ephemeral, so a late subscription misses the
	// reply), and reply_to is fresh per envelope, so nothing stored can match it —
	// the relay says "nothing stored" before the hub has even seen the request. It
	// also describes the relay's storage rather than the hub's intent, and only the
	// hub knows how many chunks it produced.
	Seq   int    `json:"seq"`
	Total int    `json:"total"`
	Pad   string `json:"pad,omitempty"`
}

// MarshalJSON writes `"results": []` for a reply that answers no item and carries
// no envelope-level error.
//
// The empty list is load-bearing (NIP-CASH §Responses (kind 23191)): it is how a
// client tells a complete reply of omissions from a chunk that decided nothing,
// which makes the reply incomplete. omitempty alone would erase that difference.
func (r ResponseEnvelope) MarshalJSON() ([]byte, error) {
	type plain ResponseEnvelope
	w := struct {
		plain
		Results *[]Result `json:"results,omitempty"`
	}{plain: plain(r)}
	switch {
	case len(r.Results) > 0:
		w.Results = &r.Results
	case r.Error == nil:
		empty := []Result{}
		w.Results = &empty
	}
	return json.Marshal(w)
}

// DecodedChunk is one decoded kind-23191 chunk, kept as the hub sent it, with what
// was wrong in it reported instead of refused.
//
// A chunk is only ever refused whole for what makes it unusable (see
// DecodeResponseChunk). Everything else is a fact about the reply the caller has to
// weigh against the other chunks, which is why it is reported here: NIP-CASH
// §Chunked Replies makes a malformed set incomplete, not void, and an item answered
// twice indeterminate while its siblings keep their answers.
type DecodedChunk struct {
	*ResponseEnvelope
	// DuplicateIDs lists the ids answered more than once inside this chunk. Every
	// one of those answers is left in Results, so a caller counting answers per id
	// sees each of them.
	DuplicateIDs []string
	// AlienIDs lists the ids of results dropped because the request never sent
	// them (NIP-CASH §Responses: a client rejects results whose id it never sent).
	AlienIDs []string
}

// DecidesNothing reports a chunk carrying neither `results` nor an envelope-level
// error. Such a chunk decides no item and leaves the reply incomplete; it is never
// read as `"results": []`, which a hub sends for a complete reply of omissions.
func (c *DecodedChunk) DecidesNothing() bool {
	return c.Results == nil && c.Error == nil
}

// DecodeResponseChunk parses one chunk of a reply to the request identified by
// reqNonce.
//
// It refuses only what makes the whole chunk unusable: bad JSON, a req_nonce that
// is not the request's, or a plaintext over max(maxBytes, 65535) bytes. A result for
// an id the request never sent is dropped and listed in AlienIDs, and the rest of
// the chunk kept. An id answered twice is reported in DuplicateIDs, not fatal.
// seq and total are returned as sent, unchecked: a position outside 1 to total
// makes the reply incomplete, which only the caller holding every chunk can act on.
// A `v` field, gone from the wire, is ignored like any unknown field.
func DecodeResponseChunk(plaintext []byte, reqNonce string, requestedIDs []string, maxBytes int) (*DecodedChunk, error) {
	limit := max(maxBytes, MaxNIP44Plaintext)
	if len(plaintext) > limit {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrEnvelopeTooLarge, len(plaintext), limit)
	}
	var r ResponseEnvelope
	if err := json.Unmarshal(plaintext, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResponseMalformed, err)
	}
	if r.ReqNonce != reqNonce {
		return nil, fmt.Errorf("%w: req_nonce %q", ErrResponseMismatch, r.ReqNonce)
	}

	known := make(map[string]struct{}, len(requestedIDs))
	for _, id := range requestedIDs {
		known[id] = struct{}{}
	}
	out := &DecodedChunk{ResponseEnvelope: &r}
	if r.Results == nil {
		return out, nil
	}
	kept := make([]Result, 0, len(r.Results))
	count := make(map[string]int, len(r.Results))
	for _, result := range r.Results {
		if _, ok := known[result.ID]; !ok {
			out.AlienIDs = append(out.AlienIDs, result.ID)
			continue
		}
		count[result.ID]++
		if count[result.ID] == 2 {
			out.DuplicateIDs = append(out.DuplicateIDs, result.ID)
		}
		kept = append(kept, result)
	}
	r.Results = kept
	return out, nil
}

// DeriveReplyKey derives the key a response is encrypted under, from the
// request's own NIP-44 conversation key plus its reply_to tag.
//
// This is why reply_to is an opaque tag rather than a pubkey. Only the hub and
// the requester know the wrap conversation key, so a key derived from it
// authenticates the hub implicitly — no second ECDH, no ephemeral keypair, and
// (when the hub's transport key lives on its node) no extra node round trip per
// response. The relay still sees an exchange between two values that never recur.
func DeriveReplyKey(conversationKey [32]byte, replyTo string) ([32]byte, error) {
	var out [32]byte
	if len(replyTo) != keyHexLen || !isLowerHex(replyTo) {
		return out, fmt.Errorf("%w: reply_to must be %d lowercase hex characters",
			ErrEnvelopeMalformed, keyHexLen)
	}
	reader := hkdf.Expand(sha256.New, conversationKey[:], []byte(replyKeyInfo+replyTo))
	if _, err := io.ReadFull(reader, out[:]); err != nil {
		return out, fmt.Errorf("transport: derive reply key: %w", err)
	}
	return out, nil
}

// EncodeResponse serialises and pads a response, mirroring Envelope.Encode.
func (r ResponseEnvelope) EncodeResponse(limits Limits) ([]byte, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	// A reply echoes the request's nonce as sent. Only an envelope-level refusal
	// can answer a malformed one: NIP-CASH §Serving an Envelope E4 refuses an
	// envelope whose nonce is not 64 lowercase hex with BAD_REQUEST, and that
	// reply must still name the nonce the client sent.
	refusal := r.Error != nil && len(r.Results) == 0
	if (len(r.ReqNonce) != keyHexLen || !isLowerHex(r.ReqNonce)) && (!refusal || r.ReqNonce == "") {
		return nil, fmt.Errorf("%w: req_nonce must be %d lowercase hex characters",
			ErrResponseMalformed, keyHexLen)
	}
	// A zero pair means the single-reply case, which is by far the common one —
	// filled in rather than rejected so a hub answering in one event need not think
	// about chunking at all.
	if r.Seq == 0 && r.Total == 0 {
		r.Seq, r.Total = 1, 1
	}
	if r.Total < 1 || r.Seq < 1 || r.Seq > r.Total {
		return nil, fmt.Errorf("%w: seq %d of %d is not a position in a reply",
			ErrResponseMalformed, r.Seq, r.Total)
	}

	r.Pad = ""
	body, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("transport: marshal response: %w", err)
	}

	const padFieldOverhead = len(`,"pad":""`)
	// A reply pads to the Hub's bucket under NIP-44's ceiling, never to the
	// request's max_bytes, which bounds requests only.
	target, err := PaddedReplySize(len(body)+padFieldOverhead, limits.PadBucketBytes)
	if err != nil {
		return nil, err
	}
	fill := target - len(body) - padFieldOverhead
	if fill < 0 {
		fill = 0
	}
	r.Pad = strings.Repeat("0", fill)

	padded, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("transport: marshal padded response: %w", err)
	}
	if len(padded) > MaxNIP44Plaintext {
		return nil, fmt.Errorf("%w: %d bytes after padding, ceiling %d",
			ErrEnvelopeTooLarge, len(padded), MaxNIP44Plaintext)
	}
	return padded, nil
}

// DecodeResponse parses a response and checks it answers the request identified by
// reqNonce, with results referring only to ids that request actually contained.
//
// It is the strict reading of one reply event, kept for callers that hold a
// single-event reply: anything DecodeResponseChunk would merely report (an alien
// id, a duplicate id, an item with both a result and an error, a seq outside its
// total) is refused here. A client collecting a chunked reply uses
// DecodeResponseChunk instead, so one bad chunk never discards another's answers.
//
// requestedIDs is what closes a confusion vector: without it a hostile or buggy
// hub could return results for ids the client never sent, and a client demuxing
// by id would happily attribute them to something.
//
// limits.MaxEnvelopeBytes does not cap the reply: it bounds requests only. A
// plaintext is refused as too large only past 65535 bytes, the same ceiling
// EncodeResponse pads under.
func DecodeResponse(plaintext []byte, reqNonce string, requestedIDs []string, limits Limits) (*ResponseEnvelope, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	// The reply's ceiling is NIP-44's 65535 bytes, not the request's max_bytes:
	// a Hub pads each chunk against its own pad_bucket_bytes and 65535 (NIP-CASH
	// §Envelopes, `pad`), exactly as EncodeResponse does, so a full reply may be
	// larger than any request the Hub accepts. DecodeResponseChunk enforces it.
	chunk, err := DecodeResponseChunk(plaintext, reqNonce, requestedIDs, limits.MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	r := chunk.ResponseEnvelope
	// Tolerated on decode for the same reason it is filled in on encode: a hub that
	// answers in one event and omits the pair is not malformed, just terse.
	if r.Seq == 0 && r.Total == 0 {
		r.Seq, r.Total = 1, 1
	}
	if r.Total < 1 || r.Seq < 1 || r.Seq > r.Total {
		return nil, fmt.Errorf("%w: seq %d of %d is not a position in a reply",
			ErrResponseMalformed, r.Seq, r.Total)
	}
	if len(chunk.AlienIDs) > 0 {
		return nil, fmt.Errorf("%w: %q", ErrUnknownItemID, chunk.AlienIDs[0])
	}
	if len(chunk.DuplicateIDs) > 0 {
		return nil, fmt.Errorf("%w: duplicate result for %q", ErrResponseMalformed, chunk.DuplicateIDs[0])
	}
	for _, result := range r.Results {
		if result.HasBoth() {
			return nil, fmt.Errorf("%w: item %q carries both a result and an error",
				ErrResponseMalformed, result.ID)
		}
	}
	return r, nil
}

// HasBoth reports a result that carries both a result body and an error, which no
// reading can resolve. A JSON null body counts as none.
func (r Result) HasBoth() bool {
	return r.Error != nil && len(r.Result) > 0 && string(r.Result) != "null"
}

// Omitted reports the ids that were requested but not answered. A caller should
// treat these as "not served" — never as a definite statement about the bill,
// and in particular never as "spent".
func (r ResponseEnvelope) Omitted(requestedIDs []string) []string {
	answered := make(map[string]struct{}, len(r.Results))
	for _, result := range r.Results {
		answered[result.ID] = struct{}{}
	}
	var missing []string
	for _, id := range requestedIDs {
		if _, ok := answered[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}
