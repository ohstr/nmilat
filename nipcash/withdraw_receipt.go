package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
)

// ReceiptFields are what a withdrawal receipt binds.
type ReceiptFields struct {
	// Wallet is the bill (d); QuoteID the quote's id (q); RequestID the call's
	// request_id as sent, hashed into request_hash.
	Wallet, QuoteID, RequestID, Address string
	PayoutMillis                        uint64
	SentBy                              int64
}

// RequestHash is a receipt's request_hash: the lowercase hex sha256 of the
// ASCII bytes of requestID as sent.
func RequestHash(requestID string) string {
	sum := sha256.Sum256([]byte(requestID))
	return hex.EncodeToString(sum[:])
}

var receiptTagNames = []string{"d", "q", "request_hash", "address", "payout_millis", "sent_by"}

// NewWithdrawReceiptEvent builds the Hub's receipt: kind 23188, created_at, the
// six tags in table order, empty content, signed by sign (the node identity).
func NewWithdrawReceiptEvent(f ReceiptFields, createdAt int64, sign func(*nip01.Event) error) (*nip01.Event, error) {
	switch {
	case !isLowerHex64(f.Wallet), !isLowerHex64(f.QuoteID), !ValidRequestID(f.RequestID):
		return nil, errors.New("nipcash: a receipt needs the bill, the quote id and the request_id")
	case f.Address == "", f.SentBy < 0, createdAt < 0:
		return nil, errors.New("nipcash: a receipt needs an address and non-negative times")
	}
	ev := &nip01.Event{Kind: KindWithdrawReceipt, CreatedAt: uint64(createdAt), Content: "", Tags: [][]string{
		{"d", f.Wallet}, {"q", f.QuoteID}, {"request_hash", RequestHash(f.RequestID)}, {"address", f.Address},
		{"payout_millis", strconv.FormatUint(f.PayoutMillis, 10)}, {"sent_by", strconv.FormatInt(f.SentBy, 10)},
	}}
	if err := sign(ev); err != nil {
		return nil, fmt.Errorf("nipcash: sign receipt: %w", err)
	}
	return ev, nil
}

// ReceiptExpectation is what a receipt must say: the Hub (x-only), the bill
// (Target), the quote id, the request_id as sent, and the quote's address,
// payout and sent_by. QuoteID "" (a call recovered from withdraw_request_id,
// which has no quote) skips only the q comparison; the caller then fills
// Address, PayoutMillis and SentBy from the done payout.
type ReceiptExpectation struct {
	HubXOnly, Target, QuoteID, RequestID, Address string
	PayoutMillis                                  uint64
	SentBy                                        int64
}

// ErrReceiptInvalid is a receipt that does not verify or does not match the
// call; it wraps the failing check's name, never a value.
var ErrReceiptInvalid = errors.New("nipcash: the withdrawal receipt is invalid")

// parseReceipt reads a receipt's structure: kind 23188 first, then empty
// content and the six tags each once.
func parseReceipt(raw string) (*nip01.Event, map[string][]string, error) {
	invalid := func(what string) error { return fmt.Errorf("%w: %s", ErrReceiptInvalid, what) }
	var ev nip01.Event
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return nil, nil, invalid("not an event")
	}
	if ev.Kind != KindWithdrawReceipt {
		return nil, nil, invalid("kind")
	}
	if ev.Content != "" {
		return nil, nil, invalid("content")
	}
	vals, err := uniqueTags(ev.Tags, receiptTagNames, nil)
	if err != nil {
		return nil, nil, invalid("tags")
	}
	if !isLowerHex64(vals["q"][0]) || !isLowerHex64(vals["d"][0]) || !isLowerHex64(vals["request_hash"][0]) {
		return nil, nil, invalid("tags")
	}
	return &ev, vals, nil
}

// VerifyWithdrawReceipt checks a receipt (NIP-CASH §Response): its kind
// first, then its recomputed id, its signature and its author (the Hub), then
// every tag against e. A failure is ErrReceiptInvalid.
func VerifyWithdrawReceipt(raw string, e ReceiptExpectation) error {
	invalid := func(what string) error { return fmt.Errorf("%w: %s", ErrReceiptInvalid, what) }
	ev, vals, err := parseReceipt(raw)
	if err != nil {
		return err
	}
	if ev.Verify(nip01.WithoutPowCheck()) != nil {
		return invalid("id or signature")
	}
	if !HubIdentityEqual(e.HubXOnly, ev.PubKey) {
		return invalid("author")
	}
	payout, ok1 := canonicalUint(vals["payout_millis"][0])
	sentBy, ok2 := canonicalUint(vals["sent_by"][0])
	switch {
	case vals["d"][0] != e.Target:
		return invalid("d")
	case e.QuoteID != "" && vals["q"][0] != e.QuoteID:
		return invalid("q")
	case vals["request_hash"][0] != RequestHash(e.RequestID):
		return invalid("request_hash")
	case vals["address"][0] != e.Address:
		return invalid("address")
	case !ok1 || payout != e.PayoutMillis:
		return invalid("payout_millis")
	case !ok2 || e.SentBy < 0 || sentBy != uint64(e.SentBy):
		return invalid("sent_by")
	}
	return nil
}

// ReceiptQuoteID is a receipt's q, which a call recovered from
// withdraw_request_id stores as its quote id once the receipt verified.
func ReceiptQuoteID(raw string) (string, error) {
	_, vals, err := parseReceipt(raw)
	if err != nil {
		return "", err
	}
	return vals["q"][0], nil
}
