// Package nip57 implements the spec-compliant NIP-57 Lightning Zaps
// request/receipt/LNURL flow (kinds 9734/9735): NewZapRequest,
// ParseZapRequest, ValidateZapRequest, NewZapReceipt, ParseZapReceipt,
// ValidateZapReceipt.
//
// See github.com/ohstr/nmilat/nipAZ for AltZap, an SDK extension of this
// same flow for zapping across L1 chains beyond Bitcoin.
package nip57

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Failure modes for the New*/Parse*/Validate* functions in this package,
// for callers that need to distinguish them (e.g. via errors.Is) rather
// than match on message text. Many of these are also returned by
// github.com/ohstr/nmilat/nipAZ, which reuses the values rather than
// defining parallel ones, so errors.Is works the same way across both
// packages. nipAZ enforces some of them more strictly than NIP-57 requires
// — see that package for which.
var (
	ErrWrongKind               = errors.New("nip57: wrong kind")
	ErrInvalidRelayURL         = errors.New("nip57: invalid relay url")
	ErrInvalidRelayScheme      = errors.New("nip57: relay url must use ws or wss scheme")
	ErrInvalidAmount           = errors.New("nip57: invalid amount tag")
	ErrInvalidLNURL            = errors.New("nip57: invalid lnurl tag")
	ErrInvalidEventTag         = errors.New("nip57: invalid e tag")
	ErrTooManyEventTags        = errors.New("nip57: at most one e tag allowed")
	ErrInvalidRecipientTag     = errors.New("nip57: invalid p tag")
	ErrRecipientTagCount       = errors.New("nip57: must have exactly one p tag")
	ErrInvalidSenderTag        = errors.New("nip57: invalid P tag")
	ErrTooManySenderTags       = errors.New("nip57: at most one P tag allowed")
	ErrMissingRelaysTag        = errors.New("nip57: missing relays tag")
	ErrMissingBolt11Tag        = errors.New("nip57: missing bolt11 tag")
	ErrMissingDescriptionTag   = errors.New("nip57: missing description tag")
	ErrInvalidDescriptionJSON  = errors.New("nip57: invalid description json")
	ErrInvalidEmbeddedRequest  = errors.New("nip57: invalid embedded zap request")
	ErrInvalidSignature        = errors.New("nip57: invalid signature")
	ErrInvalidAmountValue      = errors.New("nip57: amount must be positive")
	ErrAmountMismatch          = errors.New("nip57: amount mismatch")
	ErrDescriptionHashMismatch = errors.New("nip57: description hash mismatch")
	ErrMissingDescriptionHash  = errors.New("nip57: invoice has no description hash")
	ErrRecipientMismatch       = errors.New("nip57: recipient mismatch")
	ErrBolt11DecodeFailed      = errors.New("nip57: failed to decode bolt11")
	ErrMissingRecipientTag     = errors.New("nip57: missing p tag")
)

const (
	// KindZapRequest and KindZapReceipt are the spec kinds from NIP-57
	// Appendix A and E, respectively.
	KindZapRequest = 9734
	KindZapReceipt = 9735
)

// zapPolicy selects which of NIP-57's non-MUST rules a Parse*/Validate*
// call enforces. Everything MUST-level — kind, signatures, the required
// tags, amount and recipient cross-checks — is enforced under every policy
// and isn't represented here.
type zapPolicy struct {
	// strictLNURL requires the lnurl tag to carry the bech32 "lnurl1…"
	// form. NIP-57 Appendix A calls the tag "recommended, but optional"
	// and Appendix F makes matching it a SHOULD; in practice clients put a
	// LUD-16 lightning address there instead.
	strictLNURL bool
	// requireRelaysTag rejects a zap request carrying no relays tag.
	requireRelaysTag bool
	// requireDescriptionHash cross-checks sha256(description) against the
	// invoice's description hash. Appendix F lists no such rule for
	// validating a receipt — Appendix E only recommends the binding when
	// creating one — and a description re-serialized by the provider
	// legitimately fails it.
	requireDescriptionHash bool
}

var (
	// policyStrict is for callers building or settling their own zaps.
	policyStrict = zapPolicy{
		strictLNURL:            true,
		requireRelaysTag:       true,
		requireDescriptionHash: true,
	}
	// policyRelay is for relays ingesting someone else's zap events.
	policyRelay = zapPolicy{}
)

// ZapRequest is a parsed and validated NIP-57 zap request event (kind 9734).
type ZapRequest struct {
	*nip01.Event
	Relays     []string
	Amount     int64  // millisats; 0 if the optional "amount" tag is absent
	Lnurl      string // optional
	Author     string // "p" tag — recipient pubkey (required)
	OnBehalfOf string // optional "P" tag — true sender, when a custodial signer sends on their behalf
	EventID    string // optional "e" tag
	ATag       string // optional "a" tag (addressable event coordinate)
	KTag       string // optional "k" tag (target event kind)
}

// ParseZapRequest parses and validates a NIP-57 zap request event (kind 9734)
// per Appendix A/D.
func ParseZapRequest(event *nip01.Event) (*ZapRequest, error) {
	return parseZapRequest(event, policyStrict)
}

func parseZapRequest(event *nip01.Event, policy zapPolicy) (*ZapRequest, error) {
	if event.Kind != KindZapRequest {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindZapRequest)
	}

	zr := &ZapRequest{Event: event}
	var pTagCount, PTagCount, eTagCount int

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "relays":
			for _, r := range tag[1:] {
				u, err := url.ParseRequestURI(r)
				if err != nil {
					return nil, fmt.Errorf("%w %q: %w", ErrInvalidRelayURL, r, err)
				}
				if u.Scheme != "wss" && u.Scheme != "ws" {
					return nil, fmt.Errorf("%w: %q", ErrInvalidRelayScheme, u.Scheme)
				}
				zr.Relays = append(zr.Relays, r)
			}
		case "amount":
			var a int64
			n, err := fmt.Sscanf(tag[1], "%d", &a)
			if err != nil || n != 1 {
				return nil, fmt.Errorf("%w: %q", ErrInvalidAmount, tag[1])
			}
			if a <= 0 {
				return nil, fmt.Errorf("%w: %d", ErrInvalidAmountValue, a)
			}
			zr.Amount = a
		case "lnurl":
			if policy.strictLNURL {
				if err := utils.ValidateLNURL(tag[1]); err != nil {
					return nil, fmt.Errorf("%w %q: %w", ErrInvalidLNURL, tag[1], err)
				}
			}
			zr.Lnurl = tag[1]
		case "e":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w %q: %w", ErrInvalidEventTag, tag[1], err)
			}
			zr.EventID = tag[1]
			eTagCount++
		case "a":
			zr.ATag = tag[1]
		case "k":
			zr.KTag = tag[1]
		case "p":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w %q: %w", ErrInvalidRecipientTag, tag[1], err)
			}
			zr.Author = tag[1]
			pTagCount++
		case "P":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w %q: %w", ErrInvalidSenderTag, tag[1], err)
			}
			zr.OnBehalfOf = tag[1]
			PTagCount++
		}
	}

	if pTagCount != 1 {
		return nil, ErrRecipientTagCount
	}
	if PTagCount > 1 {
		return nil, ErrTooManySenderTags
	}
	if eTagCount > 1 {
		return nil, ErrTooManyEventTags
	}
	if policy.requireRelaysTag && len(zr.Relays) == 0 {
		return nil, ErrMissingRelaysTag
	}

	return zr, nil
}

// ValidateZapRequest checks that event is a well-formed, signed NIP-57 zap
// request. If expectedAmountMsat > 0 and the request carries an "amount"
// tag, the two must match — NIP-57 Appendix D: "If there is an amount tag,
// it MUST be equal to the amount query parameter."
func ValidateZapRequest(event *nip01.Event, expectedAmountMsat int64) error {
	return validateZapRequest(event, expectedAmountMsat, policyStrict)
}

// ValidateZapRequestForRelay checks a zap request (kind 9734) for relay
// ingest. It enforces every MUST-level rule in NIP-57 Appendix A/D — kind,
// signature, a single valid "p" tag, well-formed relay URLs and a positive
// amount — but tolerates the rules the spec states as SHOULD or optional:
// an "lnurl" tag in any form (clients commonly send a LUD-16 lightning
// address rather than the bech32 encoding), and a missing "relays" tag.
//
// Use ValidateZapRequest instead when building or settling your own zap,
// where the stricter reading is the useful one.
func ValidateZapRequestForRelay(event *nip01.Event) error {
	return validateZapRequest(event, 0, policyRelay)
}

func validateZapRequest(event *nip01.Event, expectedAmountMsat int64, policy zapPolicy) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	zr, err := parseZapRequest(event, policy)
	if err != nil {
		return err
	}

	if expectedAmountMsat > 0 && zr.Amount > 0 && zr.Amount != expectedAmountMsat {
		return fmt.Errorf("%w: expected %d msat, got %d msat", ErrAmountMismatch, expectedAmountMsat, zr.Amount)
	}

	return nil
}

// ZapReceipt is a parsed and validated NIP-57 zap receipt event (kind 9735).
type ZapReceipt struct {
	*nip01.Event
	Recipient   string // "p" tag (required)
	OnBehalfOf  string // "P" tag (optional), mirrored from the zap request
	EventID     string // "e" tag (optional), mirrored from the zap request
	ATag        string // "a" tag (optional), mirrored from the zap request
	KTag        string // "k" tag (optional), mirrored from the zap request
	Bolt11      string // "bolt11" tag (required)
	Preimage    string // "preimage" tag (optional)
	Description string // "description" tag (required) — JSON-encoded zap request
	Request     *ZapRequest
}

// ParseZapReceipt parses and validates a NIP-57 zap receipt event (kind
// 9735) per Appendix E.
func ParseZapReceipt(event *nip01.Event) (*ZapReceipt, error) {
	return parseZapReceipt(event, policyStrict)
}

func parseZapReceipt(event *nip01.Event, policy zapPolicy) (*ZapReceipt, error) {
	if event.Kind != KindZapReceipt {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindZapReceipt)
	}

	zr := &ZapReceipt{Event: event}

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			zr.Recipient = tag[1]
		case "P":
			zr.OnBehalfOf = tag[1]
		case "e":
			zr.EventID = tag[1]
		case "a":
			zr.ATag = tag[1]
		case "k":
			zr.KTag = tag[1]
		case "bolt11":
			zr.Bolt11 = tag[1]
		case "preimage":
			zr.Preimage = tag[1]
		case "description":
			zr.Description = tag[1]
		}
	}

	if zr.Recipient == "" {
		return nil, ErrMissingRecipientTag
	}
	if zr.Bolt11 == "" {
		return nil, ErrMissingBolt11Tag
	}
	if zr.Description == "" {
		return nil, ErrMissingDescriptionTag
	}

	var reqEvent nip01.Event
	if err := json.Unmarshal([]byte(zr.Description), &reqEvent); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDescriptionJSON, err)
	}
	if err := reqEvent.Verify(); err != nil {
		return nil, fmt.Errorf("%w: embedded request signature invalid: %w", ErrInvalidEmbeddedRequest, err)
	}
	req, err := parseZapRequest(&reqEvent, policy)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEmbeddedRequest, err)
	}
	zr.Request = req

	return zr, nil
}

// ValidateZapReceipt checks the receipt's signature and cross-checks it
// against its embedded zap request and paid invoice, per NIP-57 Appendix F.
// It does not (and cannot, on its own) verify that the receipt's pubkey
// matches the recipient's LNURL-declared nostrPubkey — that check requires
// external LNURL data and is the caller's responsibility.
func ValidateZapReceipt(receipt *nip01.Event) error {
	return validateZapReceipt(receipt, policyStrict)
}

// ValidateZapReceiptForRelay checks a zap receipt (kind 9735) for relay
// ingest. It enforces every MUST-level rule in NIP-57 Appendix E/F — kind,
// the receipt's own signature, the required "p", "bolt11" and "description"
// tags, a decodable invoice, the embedded request's signature and structure,
// and the amount and recipient cross-checks — but tolerates the rules the
// spec states as SHOULD or optional:
//
//   - the embedded request's "lnurl" tag in any form, or absent;
//   - the embedded request's "relays" tag being absent;
//   - the invoice's description hash being absent or not matching
//     sha256(description).
//
// A relay stores receipts settled by someone else, and a receipt is the
// record that a payment happened; rejecting one at ingest over a
// SHOULD-level deviation silently loses that record. Use ValidateZapReceipt
// instead when checking a zap you are settling or accounting for yourself.
func ValidateZapReceiptForRelay(receipt *nip01.Event) error {
	return validateZapReceipt(receipt, policyRelay)
}

func validateZapReceipt(receipt *nip01.Event, policy zapPolicy) error {
	if err := receipt.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	zr, err := parseZapReceipt(receipt, policy)
	if err != nil {
		return err
	}

	invoice, err := DecodeBolt11(zr.Bolt11)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBolt11DecodeFailed, err)
	}

	if policy.requireDescriptionHash {
		if err := checkDescriptionHash(zr.Description, invoice); err != nil {
			return err
		}
	}

	if zr.Request.Amount > 0 && invoice.AmountMloki != zr.Request.Amount {
		return fmt.Errorf("%w: invoice=%d request=%d", ErrAmountMismatch, invoice.AmountMloki, zr.Request.Amount)
	}

	if zr.Recipient != zr.Request.Author {
		return fmt.Errorf("%w: receipt=%s request_author=%s", ErrRecipientMismatch, zr.Recipient, zr.Request.Author)
	}

	return nil
}

// checkDescriptionHash verifies that the invoice's description hash binds
// the receipt's description tag, i.e. the zap request it claims to have
// paid.
func checkDescriptionHash(description string, invoice *Invoice) error {
	descHash := sha256.Sum256([]byte(description))
	descHashHex := hex.EncodeToString(descHash[:])
	if invoice.DescriptionHash == "" {
		return fmt.Errorf("%w: want=%s", ErrMissingDescriptionHash, descHashHex)
	}
	if invoice.DescriptionHash != descHashHex {
		return fmt.Errorf("%w: have=%s want=%s", ErrDescriptionHashMismatch, invoice.DescriptionHash, descHashHex)
	}
	return nil
}

// ZapRequestParams describes a NIP-57 zap request (kind 9734). Recipient and
// Relays are required per Appendix A; AmountMsat and Lnurl are recommended
// but optional; the rest are optional.
type ZapRequestParams struct {
	Recipient  string   // "p" tag — recipient pubkey
	Relays     []string // relays the zap receipt should be published to
	AmountMsat int64    // optional, amount in millisats
	Lnurl      string   // optional, recipient's LNURL-pay endpoint
	OnBehalfOf string   // optional "P" tag — true sender, when a custodial signer sends on their behalf
	EventID    *string  // optional "e" tag — zapped event ID
	ATag       string   // optional "a" tag — zapped addressable event coordinate
	KTag       string   // optional "k" tag — zapped event's kind
	Content    string   // optional public note attached to the zap
}

// NewZapRequest creates a new NIP-57 zap request event (kind 9734).
func NewZapRequest(p ZapRequestParams) *nip01.Event {
	tags := [][]string{{"p", p.Recipient}}

	if len(p.Relays) > 0 {
		tags = append(tags, append([]string{"relays"}, p.Relays...))
	}
	if p.AmountMsat > 0 {
		tags = append(tags, []string{"amount", fmt.Sprintf("%d", p.AmountMsat)})
	}
	if p.Lnurl != "" {
		tags = append(tags, []string{"lnurl", p.Lnurl})
	}
	if p.OnBehalfOf != "" {
		tags = append(tags, []string{"P", p.OnBehalfOf})
	}
	if p.EventID != nil {
		tags = append(tags, []string{"e", *p.EventID})
	}
	if p.ATag != "" {
		tags = append(tags, []string{"a", p.ATag})
	}
	if p.KTag != "" {
		tags = append(tags, []string{"k", p.KTag})
	}

	return &nip01.Event{
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindZapRequest,
		Tags:      tags,
		Content:   p.Content,
	}
}

// ZapReceiptParams describes a NIP-57 zap receipt (kind 9735), issued by the
// recipient's LNURL provider once the invoice is paid. ProviderPubkey,
// Recipient, Bolt11, and Description are required per Appendix E.
type ZapReceiptParams struct {
	ProviderPubkey string  // the receipt signer — must match the LNURL endpoint's nostrPubkey
	Recipient      string  // "p" tag
	Bolt11         string  // "bolt11" tag — the paid invoice
	Description    string  // "description" tag — JSON-encoded zap request
	OnBehalfOf     string  // optional "P" tag, mirrored from the zap request
	EventID        string  // optional "e" tag, mirrored from the zap request
	ATag           string  // optional "a" tag, mirrored from the zap request
	KTag           string  // optional "k" tag, mirrored from the zap request
	Preimage       *string // optional payment proof
}

// NewZapReceipt creates a new NIP-57 zap receipt event (kind 9735).
func NewZapReceipt(p ZapReceiptParams) *nip01.Event {
	tags := [][]string{
		{"p", p.Recipient},
		{"bolt11", p.Bolt11},
		{"description", p.Description},
	}
	if p.OnBehalfOf != "" {
		tags = append(tags, []string{"P", p.OnBehalfOf})
	}
	if p.EventID != "" {
		tags = append(tags, []string{"e", p.EventID})
	}
	if p.ATag != "" {
		tags = append(tags, []string{"a", p.ATag})
	}
	if p.KTag != "" {
		tags = append(tags, []string{"k", p.KTag})
	}
	if p.Preimage != nil {
		tags = append(tags, []string{"preimage", *p.Preimage})
	}

	return &nip01.Event{
		PubKey:    p.ProviderPubkey,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindZapReceipt,
		Tags:      tags,
		Content:   "",
	}
}
