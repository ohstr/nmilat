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
	Version int `json:"v"`
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
	if r.Version != EnvelopeVersion {
		return nil, fmt.Errorf("%w: %d", ErrEnvelopeVersion, r.Version)
	}
	if len(r.ReqNonce) != keyHexLen || !isLowerHex(r.ReqNonce) {
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
	target, err := limits.PaddedSize(len(body) + padFieldOverhead)
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
	if len(padded) > limits.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: %d bytes after padding, limit %d",
			ErrEnvelopeTooLarge, len(padded), limits.MaxEnvelopeBytes)
	}
	return padded, nil
}

// DecodeResponse parses a response and checks it answers the request identified by
// reqNonce, with results referring only to ids that request actually contained.
//
// requestedIDs is what closes a confusion vector: without it a hostile or buggy
// hub could return results for ids the client never sent, and a client demuxing
// by id would happily attribute them to something.
func DecodeResponse(plaintext []byte, reqNonce string, requestedIDs []string, limits Limits) (*ResponseEnvelope, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if len(plaintext) > limits.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d",
			ErrEnvelopeTooLarge, len(plaintext), limits.MaxEnvelopeBytes)
	}

	var r ResponseEnvelope
	if err := json.Unmarshal(plaintext, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResponseMalformed, err)
	}
	if r.Version != EnvelopeVersion {
		return nil, fmt.Errorf("%w: %d", ErrEnvelopeVersion, r.Version)
	}
	if r.ReqNonce != reqNonce {
		return nil, fmt.Errorf("%w: req_nonce %q", ErrResponseMismatch, r.ReqNonce)
	}
	// Tolerated on decode for the same reason it is filled in on encode: a hub that
	// answers in one event and omits the pair is not malformed, just terse.
	if r.Seq == 0 && r.Total == 0 {
		r.Seq, r.Total = 1, 1
	}
	if r.Total < 1 || r.Seq < 1 || r.Seq > r.Total {
		return nil, fmt.Errorf("%w: seq %d of %d is not a position in a reply",
			ErrResponseMalformed, r.Seq, r.Total)
	}

	known := make(map[string]struct{}, len(requestedIDs))
	for _, id := range requestedIDs {
		known[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(r.Results))
	for _, result := range r.Results {
		if _, ok := known[result.ID]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownItemID, result.ID)
		}
		if _, dup := seen[result.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate result for %q", ErrResponseMalformed, result.ID)
		}
		seen[result.ID] = struct{}{}
		if result.Result != nil && result.Error != nil {
			return nil, fmt.Errorf("%w: item %q carries both a result and an error",
				ErrResponseMalformed, result.ID)
		}
	}
	return &r, nil
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
