package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ServeAction is what a Hub does with one kind-23190 event (NIP-CASH §Serving
// an Envelope).
type ServeAction int

const (
	// ServeRun runs the envelope's items; the caller marks the nonce served.
	ServeRun ServeAction = iota
	// ServeDrop runs nothing and sends no reply.
	ServeDrop
	// ServeRefuse replies with the envelope-level error Code and nothing runs.
	// An E4 refusal leaves the nonce unserved; one past E4 (E5, E6) does not:
	// once an envelope passes E4 its nonce counts as served, and the caller
	// marks it, as ServeVerdict.Served says.
	ServeRefuse
)

// ServeVerdict is ClassifyEnvelope's answer. Envelope is set for ServeRun, and
// for ServeRefuse whenever the header could be read (so the reply can be
// addressed); Code is BAD_REQUEST or QUOTA_EXCEEDED for ServeRefuse.
type ServeVerdict struct {
	Action   ServeAction
	Code     string
	Envelope *Envelope
	Reason   error
	// Served is set when the envelope passed E4, so its nonce now counts as
	// served and the caller marks it: every ServeRun, and an E5 or E6
	// ServeRefuse.
	Served bool
}

// NonceSeen reports a nonce the Hub has already served (and still remembers).
type NonceSeen func(nonce string) bool

// ClassifyEnvelope applies E1 to E6 in order to a decrypted plaintext:
//
//	E1 decrypt error, not an object, reply_to missing or not 64 lowercase hex → Drop
//	E2 not_after an integer that has passed → Drop
//	E3 nonce already served → Drop
//	E4 nonce not 64 lowercase hex; not_after missing, not an integer or more than
//	   H ahead; items not a non-empty array; two items sharing an id → BAD_REQUEST
//	E5 padded plaintext over max_bytes or more than max_items items → QUOTA_EXCEEDED
//	E6 more signature verifications than max_verify_budget → QUOTA_EXCEEDED
//
// A Run verdict carries the decoded envelope (Decode's per-item judgement
// included); the caller marks its nonce served. No version is read, and the PoW
// nonce and expiration tags of the event are not this function's business.
func ClassifyEnvelope(plaintext []byte, decryptErr error, limits Limits, now time.Time, seen NonceSeen) ServeVerdict {
	drop := func(err error) ServeVerdict { return ServeVerdict{Action: ServeDrop, Reason: err} }
	if decryptErr != nil {
		return drop(decryptErr)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &raw); err != nil || raw == nil {
		return drop(fmt.Errorf("%w: not a JSON object", ErrEnvelopeMalformed))
	}
	var replyTo string
	if json.Unmarshal(raw["reply_to"], &replyTo) != nil || len(replyTo) != keyHexLen || !isLowerHex(replyTo) {
		return drop(fmt.Errorf("%w: reply_to", ErrEnvelopeMalformed))
	}
	notAfter, notAfterOK := integerField(raw["not_after"])
	if notAfterOK && now.Unix() > notAfter {
		return drop(ErrEnvelopeExpired)
	}
	var nonce string
	_ = json.Unmarshal(raw["nonce"], &nonce)
	if seen != nil && seen(nonce) {
		return drop(errors.New("transport: nonce already served"))
	}
	header := &Envelope{Version: EnvelopeVersion, Nonce: nonce, ReplyTo: replyTo, NotAfter: notAfter}
	refuse := func(code string, err error) ServeVerdict {
		return ServeVerdict{Action: ServeRefuse, Code: code, Envelope: header, Reason: err}
	}
	var items []json.RawMessage
	switch {
	case len(nonce) != keyHexLen || !isLowerHex(nonce):
		return refuse("BAD_REQUEST", fmt.Errorf("%w: nonce", ErrEnvelopeMalformed))
	case !notAfterOK:
		return refuse("BAD_REQUEST", fmt.Errorf("%w: not_after is not an integer", ErrEnvelopeMalformed))
	case notAfter > now.Unix()+limits.MaxRequestAgeSeconds:
		return refuse("BAD_REQUEST", ErrEnvelopeTooFresh)
	case json.Unmarshal(raw["items"], &items) != nil || len(items) == 0:
		return refuse("BAD_REQUEST", ErrEnvelopeNoItems)
	case duplicateItemIDs(items):
		return refuse("BAD_REQUEST", ErrDuplicateItemID)
	}
	// Past E4 the nonce counts as served, refused or not.
	refuse = func(code string, err error) ServeVerdict {
		return ServeVerdict{Action: ServeRefuse, Code: code, Envelope: header, Reason: err, Served: true}
	}
	if len(plaintext) > limits.MaxEnvelopeBytes || len(items) > limits.MaxItems {
		return refuse("QUOTA_EXCEEDED", ErrEnvelopeTooLarge)
	}
	env, err := Decode(plaintext, limits)
	switch {
	case errors.Is(err, ErrVerifyBudgetExceeded):
		return refuse("QUOTA_EXCEEDED", err)
	case err != nil:
		return refuse("BAD_REQUEST", err)
	}
	return ServeVerdict{Action: ServeRun, Envelope: env, Served: true}
}

// integerField reads a JSON integer: digits with an optional leading minus, no
// fraction or exponent, not a string or bool.
func integerField(raw json.RawMessage) (int64, bool) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.ContainsAny(t, ".eE\"") {
		return 0, false
	}
	v, err := strconv.ParseInt(string(t), 10, 64)
	return v, err == nil
}
