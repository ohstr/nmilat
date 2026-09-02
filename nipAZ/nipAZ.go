// Package nipAZ implements NIP-AZ (AltZap): an SDK extension of NIP-57
// (github.com/ohstr/nmilat/nip57) for zapping across L1 chains beyond
// Bitcoin. It adds a mandatory "chain" tag for cross-chain replay safety
// and its own event kinds (5520-5523), so it is not wire-compatible with
// vanilla NIP-57 and does not claim to be.
package nipAZ

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/utils"
)

// Failure modes specific to NIP-AZ; nipAZ also returns the shared
// nip57.Err* values above for checks common to both flows (signature,
// amount, description-hash, etc.) — see nip57.go.
var (
	ErrMissingSenderTag          = errors.New("nipAZ: missing P tag denoting the true sender")
	ErrInvalidZapTag             = errors.New("nipAZ: invalid zap tag")
	ErrMissingChainTag           = errors.New("nipAZ: missing chain tag")
	ErrDirectPaymentHasRecipient = errors.New("nipAZ: direct-payment request must not have a p tag")
	ErrMissingLNURLTag           = errors.New("nipAZ: missing lnurl tag")
	ErrMissingPreimageTag        = errors.New("nipAZ: missing preimage tag")
	ErrHashLockMismatch          = errors.New("nipAZ: bolt11 hash-lock mismatch")
	ErrInvalidInvoiceAmount      = errors.New("nipAZ: invalid or missing amount in bolt11 invoice")
)

const (
	// AltZap kinds — not the standard NIP-57 9734/9735 pair; see the
	// package doc comment for why.
	KindAltZapRequest         = 5520
	KindAltZapReceipt         = 5521
	KindAltZapDirectPayment   = 5522
	KindAltZapOnBehalfRequest = 5523
)

// AltZapRequest is a parsed and validated AltZap request event (kinds 5520,
// 5522, or 5523).
type AltZapRequest struct {
	*nip01.Event
	Relays         []string
	Amount         int64
	Lnurl          string
	Bolt11         string // for kind 5522 direct payments
	Chain          string // required, to prevent cross-chain replay
	EventID        string // e tag
	ATag           string // a tag coordinate
	KTag           string // k tag kind limit
	Author         string // p tag (recipient pubkey or hash)
	Provider       string // p tag (recipient web identity platform name)
	Sender         string // P tag (sender pubkey or hash)
	SenderProvider string // P tag (sender web identity platform name)
}

// ParseAltZapRequest parses and validates an AltZap request event (kinds
// 5520, 5522, or 5523).
func ParseAltZapRequest(event *nip01.Event) (*AltZapRequest, error) {
	if event.Kind != KindAltZapRequest && event.Kind != KindAltZapOnBehalfRequest && event.Kind != KindAltZapDirectPayment {
		return nil, fmt.Errorf("%w: got %d, want 5520, 5522, or 5523", nip57.ErrWrongKind, event.Kind)
	}

	zr := &AltZapRequest{Event: event}
	var pTagCount, eTagCount, PTagCount int

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "relays":
			// Validate relays
			for _, r := range tag[1:] {
				u, err := url.ParseRequestURI(r)
				if err != nil {
					return nil, fmt.Errorf("%w %q: %w", nip57.ErrInvalidRelayURL, r, err)
				}
				if u.Scheme != "wss" && u.Scheme != "ws" {
					return nil, fmt.Errorf("%w: %q", nip57.ErrInvalidRelayScheme, u.Scheme)
				}
				zr.Relays = append(zr.Relays, r)
			}
		case "amount":
			// Validate amount
			var a int64
			n, err := fmt.Sscanf(tag[1], "%d", &a)
			if err != nil || n != 1 {
				return nil, fmt.Errorf("%w: %q", nip57.ErrInvalidAmount, tag[1])
			}
			if a <= 0 {
				return nil, fmt.Errorf("%w: %d", nip57.ErrInvalidAmountValue, a)
			}
			zr.Amount = a
		case "lnurl":
			if err := utils.ValidateLNURL(tag[1]); err != nil {
				return nil, fmt.Errorf("%w %q: %w", nip57.ErrInvalidLNURL, tag[1], err)
			}
			zr.Lnurl = tag[1]
		case "e":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w %q: %w", nip57.ErrInvalidEventTag, tag[1], err)
			}
			zr.EventID = tag[1]
			eTagCount++
		case "bolt11":
			zr.Bolt11 = tag[1]
		case "chain":
			zr.Chain = tag[1]
		case "a":
			zr.ATag = tag[1]
		case "k":
			zr.KTag = tag[1]
		case "p":
			zr.Author = tag[1]
			if len(tag) > 2 && tag[2] != "" {
				zr.Provider = tag[2]
			} else {
				zr.Provider = "nostr" // Default per AltZap convention
			}
			pTagCount++
		case "P":
			zr.Sender = tag[1]
			if len(tag) > 2 && tag[2] != "" {
				zr.SenderProvider = tag[2]
			} else {
				zr.SenderProvider = "nostr" // Default per AltZap convention
			}
			PTagCount++
		case "zap":
			if len(tag) < 3 {
				return nil, ErrInvalidZapTag
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: pubkey %q: %w", ErrInvalidZapTag, tag[1], err)
			}
			u, err := url.ParseRequestURI(tag[2])
			if err != nil {
				return nil, fmt.Errorf("%w: relay url %q: %w", ErrInvalidZapTag, tag[2], err)
			}
			if u.Scheme != "wss" && u.Scheme != "ws" {
				return nil, fmt.Errorf("%w: relay scheme %q", ErrInvalidZapTag, u.Scheme)
			}
			if len(tag) > 3 {
				if _, err := strconv.Atoi(tag[3]); err != nil {
					return nil, fmt.Errorf("%w: weight %q: %w", ErrInvalidZapTag, tag[3], err)
				}
			}
		}
	}

	// Protocol enforcements
	if zr.Chain == "" {
		return nil, ErrMissingChainTag
	}

	if event.Kind == KindAltZapDirectPayment { // 5522
		if pTagCount > 0 {
			return nil, ErrDirectPaymentHasRecipient
		}
		if zr.Bolt11 == "" {
			return nil, nip57.ErrMissingBolt11Tag
		}
	} else { // 5520, 5523
		if pTagCount != 1 {
			return nil, fmt.Errorf("%w: kind %d", nip57.ErrRecipientTagCount, event.Kind)
		}
		if zr.Lnurl == "" {
			return nil, fmt.Errorf("%w: kind %d", ErrMissingLNURLTag, event.Kind)
		}
	}

	if event.Kind == KindAltZapOnBehalfRequest && PTagCount == 0 {
		return nil, ErrMissingSenderTag
	}

	// e tag is optional (0 or 1)
	if eTagCount > 1 {
		return nil, nip57.ErrTooManyEventTags
	}

	// Relays tag required
	if len(zr.Relays) == 0 {
		return nil, nip57.ErrMissingRelaysTag
	}

	return zr, nil
}

// ValidateAltZapRequest checks if the event is a valid AltZap request and
// optionally enforces the amount.
func ValidateAltZapRequest(event *nip01.Event, expectedAmountMloki int64) error {
	// 1. Signature check
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", nip57.ErrInvalidSignature, err)
	}

	// 2. Parse and structure check
	zr, err := ParseAltZapRequest(event)
	if err != nil {
		return err
	}

	// 3. Amount check
	if zr.Amount <= 0 {
		return nip57.ErrInvalidAmountValue
	}

	if expectedAmountMloki > 0 && zr.Amount != expectedAmountMloki {
		return fmt.Errorf("%w: expected %d mloki, got %d mloki", nip57.ErrAmountMismatch, expectedAmountMloki, zr.Amount)
	}

	// 4. Kind 5522 specific cryptographic hash lock Rule
	if event.Kind == KindAltZapDirectPayment {
		inv, err := nip57.DecodeBolt11(zr.Bolt11)
		if err != nil {
			return fmt.Errorf("%w: 5522 request: %w", nip57.ErrBolt11DecodeFailed, err)
		}

		eventJSON, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("nip57: failed to marshal 5522 event for hash validation: %w", err)
		}

		descHash := sha256.Sum256(eventJSON)
		descHashHex := hex.EncodeToString(descHash[:])

		if inv.DescriptionHash != descHashHex {
			return fmt.Errorf("%w: bolt11 description hash %s does not match event hash %s", ErrHashLockMismatch, inv.DescriptionHash, descHashHex)
		}
	}

	return nil
}

// AltZapReceipt is a parsed and validated AltZap receipt event (kind 5521).
type AltZapReceipt struct {
	*nip01.Event
	Recipient            string // p tag
	RecipientProvider    string
	Sender               string // P tag
	SenderProvider       string
	ResolvedPubkey       string // r tag
	ResolvedSenderPubkey string // R tag
	Bolt11               string
	Chain                string
	Preimage             string
	Description          string
	Request              *AltZapRequest
}

// ParseAltZapReceipt parses and validates an AltZap receipt event (kind 5521).
func ParseAltZapReceipt(event *nip01.Event) (*AltZapReceipt, error) {
	if event.Kind != KindAltZapReceipt {
		return nil, fmt.Errorf("%w: got %d, want %d", nip57.ErrWrongKind, event.Kind, KindAltZapReceipt)
	}

	zr := &AltZapReceipt{Event: event}

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			zr.Recipient = tag[1]
			if len(tag) > 2 && tag[2] != "" {
				zr.RecipientProvider = tag[2]
			} else {
				zr.RecipientProvider = "nostr"
			}
		case "P":
			zr.Sender = tag[1]
			if len(tag) > 2 && tag[2] != "" {
				zr.SenderProvider = tag[2]
			} else {
				zr.SenderProvider = "nostr"
			}
		case "r":
			zr.ResolvedPubkey = tag[1]
		case "R":
			zr.ResolvedSenderPubkey = tag[1]
		case "bolt11":
			zr.Bolt11 = tag[1]
		case "chain":
			zr.Chain = tag[1]
		case "preimage":
			zr.Preimage = tag[1]
		case "description":
			zr.Description = tag[1]
		case "zap":
			if len(tag) < 3 {
				return nil, ErrInvalidZapTag
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: pubkey %q: %w", ErrInvalidZapTag, tag[1], err)
			}
			u, err := url.ParseRequestURI(tag[2])
			if err != nil {
				return nil, fmt.Errorf("%w: relay url %q: %w", ErrInvalidZapTag, tag[2], err)
			}
			if u.Scheme != "wss" && u.Scheme != "ws" {
				return nil, fmt.Errorf("%w: relay scheme %q", ErrInvalidZapTag, u.Scheme)
			}
			if len(tag) > 3 {
				if _, err := strconv.Atoi(tag[3]); err != nil {
					return nil, fmt.Errorf("%w: weight %q: %w", ErrInvalidZapTag, tag[3], err)
				}
			}
		}
	}

	if zr.Chain == "" {
		return nil, ErrMissingChainTag
	}
	if zr.Preimage == "" {
		return nil, ErrMissingPreimageTag
	}
	if zr.Recipient == "" && zr.Description != "" {
		// Only 5522 can have no p tag, and 5522 has no description.
		// If description exists, it must have a p tag.
		return nil, nip57.ErrMissingRecipientTag
	}
	if zr.Bolt11 == "" {
		return nil, nip57.ErrMissingBolt11Tag
	}

	// Parse embedded request if description is present
	if zr.Description != "" {
		var reqEvent nip01.Event
		if err := json.Unmarshal([]byte(zr.Description), &reqEvent); err != nil {
			return nil, fmt.Errorf("%w: %w", nip57.ErrInvalidDescriptionJSON, err)
		}

		// Verify signature of the embedded zap request (sender identity)
		if err := reqEvent.Verify(); err != nil {
			return nil, fmt.Errorf("%w: embedded request signature invalid: %w", nip57.ErrInvalidEmbeddedRequest, err)
		}

		req, err := ParseAltZapRequest(&reqEvent)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", nip57.ErrInvalidEmbeddedRequest, err)
		}
		zr.Request = req
	}

	return zr, nil
}

// ValidateAltZapReceipt checks if the receipt is valid against the request
// and invoice.
func ValidateAltZapReceipt(receipt *nip01.Event) error {
	// 1. Signature
	if err := receipt.Verify(); err != nil {
		return fmt.Errorf("%w: %w", nip57.ErrInvalidSignature, err)
	}

	// 2. Parse
	zr, err := ParseAltZapReceipt(receipt)
	if err != nil {
		return err
	}

	// 3. Verify Invoice
	invoice, err := nip57.DecodeBolt11(zr.Bolt11)
	if err != nil {
		return fmt.Errorf("%w: %w", nip57.ErrBolt11DecodeFailed, err)
	}

	// 4. Validate Logic (Strict for Zaps, relaxed for Direct Payments)
	if zr.Description != "" {
		if zr.Request == nil {
			return nip57.ErrInvalidEmbeddedRequest
		}

		// A. Verify description hash (CRITICAL)
		// SHA256(description) == invoice.DescriptionHash
		descHash := sha256.Sum256([]byte(zr.Description))
		descHashHex := hex.EncodeToString(descHash[:])

		if invoice.DescriptionHash != descHashHex {
			return fmt.Errorf("%w: have=%s want=%s", nip57.ErrDescriptionHashMismatch, descHashHex, invoice.DescriptionHash)
		}

		// B. Verify amounts match
		// Invoice amount mloki == Request amount mloki
		if invoice.AmountMloki != zr.Request.Amount {
			return fmt.Errorf("%w: invoice=%d request=%d", nip57.ErrAmountMismatch, invoice.AmountMloki, zr.Request.Amount)
		}

		// C. Verify Recipients match
		if zr.Recipient != zr.Request.Author {
			return fmt.Errorf("%w: receipt=%s request_author=%s", nip57.ErrRecipientMismatch, zr.Recipient, zr.Request.Author)
		}
	} else {
		// Direct Payment (no Zap Request description)
		if invoice.AmountMloki <= 0 {
			return ErrInvalidInvoiceAmount
		}
	}

	return nil
}

// AltZapRequestParams describes an AltZap request (kind 5520, or 5523 when
// built via NewAltZapOnBehalfRequest). Chain, Recipient, Lnurl, AmountMloki,
// and Relays are required; the rest are optional.
type AltZapRequestParams struct {
	Chain             string   // e.g. "flokicoin" — prevents cross-chain replay
	Recipient         string   // recipient pubkey ("p" tag)
	RecipientProvider string   // optional web identity platform name for the recipient, e.g. "nostr"
	Lnurl             string   // recipient's LNURL-pay endpoint
	AmountMloki       int64    // amount in mloki (milli-loki)
	Relays            []string // relays the zap receipt should be published to
	Sender            string   // optional sender pubkey ("P" tag)
	SenderProvider    string   // optional web identity platform name for the sender
	EventID           *string  // optional zapped event ID ("e" tag)
}

// NewAltZapRequest creates a new AltZap request event (kind 5520).
func NewAltZapRequest(p AltZapRequestParams) *nip01.Event {
	pTag := []string{"p", p.Recipient}
	if p.RecipientProvider != "" {
		pTag = append(pTag, p.RecipientProvider)
	}

	tags := [][]string{
		pTag,
		{"amount", fmt.Sprintf("%d", p.AmountMloki)},
		{"lnurl", p.Lnurl},
		{"chain", p.Chain},
	}

	if p.Sender != "" {
		PTag := []string{"P", p.Sender}
		if p.SenderProvider != "" {
			PTag = append(PTag, p.SenderProvider)
		}
		tags = append(tags, PTag)
	}

	if len(p.Relays) > 0 {
		relayTag := []string{"relays"}
		relayTag = append(relayTag, p.Relays...)
		tags = append(tags, relayTag)
	}

	if p.EventID != nil {
		tags = append(tags, []string{"e", *p.EventID})
	}

	return &nip01.Event{
		PubKey:    p.Sender,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindAltZapRequest,
		Tags:      tags,
		Content:   "",
	}
}

// NewAltZapOnBehalfRequest creates a new proxy AltZap request event (kind
// 5523) — used when a service is zapping on behalf of another identified
// sender (set via AltZapRequestParams.Sender).
func NewAltZapOnBehalfRequest(p AltZapRequestParams) *nip01.Event {
	event := NewAltZapRequest(p)
	event.Kind = KindAltZapOnBehalfRequest
	return event
}

// AltZapDirectPaymentParams describes a direct-payment AltZap request (kind
// 5522) — a bolt11 invoice paid directly, bypassing the LNURL/zap-request
// flow. Chain, Bolt11, AmountMloki, and Relays are required.
type AltZapDirectPaymentParams struct {
	Chain          string
	Bolt11         string
	AmountMloki    int64
	Relays         []string
	Sender         string // optional sender pubkey ("P" tag)
	SenderProvider string // optional web identity platform name for the sender
}

// NewAltZapDirectPaymentRequest creates a new direct-payment AltZap request
// event (kind 5522).
func NewAltZapDirectPaymentRequest(p AltZapDirectPaymentParams) *nip01.Event {
	tags := [][]string{
		{"amount", fmt.Sprintf("%d", p.AmountMloki)},
		{"bolt11", p.Bolt11},
		{"chain", p.Chain},
	}

	if p.Sender != "" {
		PTag := []string{"P", p.Sender}
		if p.SenderProvider != "" {
			PTag = append(PTag, p.SenderProvider)
		}
		tags = append(tags, PTag)
	}

	if len(p.Relays) > 0 {
		relayTag := []string{"relays"}
		relayTag = append(relayTag, p.Relays...)
		tags = append(tags, relayTag)
	}

	return &nip01.Event{
		PubKey:    p.Sender,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindAltZapDirectPayment,
		Tags:      tags,
		Content:   "",
	}
}

// AltZapReceiptParams describes an AltZap receipt (kind 5521), issued by the
// LNURL provider once the invoice is paid. ProviderPubkey and Bolt11 are
// required; RecipientPubkey is omitted for anonymous kind-5522 receipts.
//
// ResolvedRecipientPubkey/ResolvedSenderPubkey/Coordinate/EventID are for
// callers whose p/P tags carry a non-Nostr identity (e.g. a hashed
// ConnectionKey rather than a raw pubkey) and need to mirror the resolved
// native pubkey ("r"/"R" tags) and/or the zapped event/addressable-event
// coordinate ("e"/"a" tags) onto the receipt directly, independent of
// whatever the embedded request's Description happens to carry.
type AltZapReceiptParams struct {
	Chain                   string
	ProviderPubkey          string
	RecipientPubkey         string
	SenderPubkey            string
	Bolt11                  string
	Description             string // JSON of the embedded AltZap request, if any
	Preimage                *string
	ResolvedRecipientPubkey string // optional "r" tag
	ResolvedSenderPubkey    string // optional "R" tag
	Coordinate              string // optional "a" tag
	EventID                 string // optional "e" tag
}

// NewAltZapReceipt creates a new AltZap receipt event (kind 5521).
func NewAltZapReceipt(p AltZapReceiptParams) (*nip01.Event, error) {
	tags := [][]string{
		{"bolt11", p.Bolt11},
		{"chain", p.Chain},
	}

	if p.RecipientPubkey != "" {
		tags = append(tags, []string{"p", p.RecipientPubkey})
	}

	if p.Description != "" {
		tags = append(tags, []string{"description", p.Description})
	}

	// Decode bolt11 and add the amount tag.
	inv, err := nip57.DecodeBolt11(p.Bolt11)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", nip57.ErrBolt11DecodeFailed, err)
	}
	tags = append(tags, []string{"amount", fmt.Sprintf("%d", inv.AmountMloki)})

	if p.SenderPubkey != "" {
		tags = append(tags, []string{"P", p.SenderPubkey})
	}

	if p.Preimage != nil {
		tags = append(tags, []string{"preimage", *p.Preimage})
	}

	if p.ResolvedRecipientPubkey != "" {
		tags = append(tags, []string{"r", p.ResolvedRecipientPubkey})
	}

	if p.ResolvedSenderPubkey != "" {
		tags = append(tags, []string{"R", p.ResolvedSenderPubkey})
	}

	if p.EventID != "" {
		tags = append(tags, []string{"e", p.EventID})
	}

	if p.Coordinate != "" {
		tags = append(tags, []string{"a", p.Coordinate})
	}

	// Extract tags from the description request if possible
	var req nip01.Event
	if err := json.Unmarshal([]byte(p.Description), &req); err == nil {
		for _, tag := range req.Tags {
			if len(tag) < 2 {
				continue
			}
			key := tag[0]
			if key == "e" || key == "a" || key == "tbd" || key == "r" || key == "p" || key == "P" {
				// We overwrite our default basic 'p' and 'P' tags with the detailed ones from the request
				if key == "p" || key == "P" {
					for i, existingTag := range tags {
						if len(existingTag) > 0 && existingTag[0] == key {
							tags[i] = tag // Replace basic tag with the fully detailed tag (containing provider)
							break
						}
					}
					// If it wasn't there at all, append it
					found := false
					for _, existingTag := range tags {
						if len(existingTag) > 0 && existingTag[0] == key {
							found = true
							break
						}
					}
					if !found {
						tags = append(tags, tag)
					}
					continue
				}
				tags = append(tags, tag)
			}
		}
	}

	return &nip01.Event{
		PubKey:    p.ProviderPubkey,
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindAltZapReceipt,
		Tags:      tags,
		Content:   "",
	}, nil
}
