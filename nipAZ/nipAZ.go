// Package nipAZ implements NIP-AZ (AltZap): an SDK extension of NIP-57
// (github.com/ohstr/nmilat/nip57) for zapping across L1 chains beyond
// Bitcoin. It adds a mandatory "chain" tag for cross-chain replay safety
// and its own event kinds (9520, 9521 and 9523), so it is not wire-compatible
// with vanilla NIP-57 and does not claim to be.
//
// nipAZ depends on nipIC (github.com/ohstr/nmilat/nipIC) for the
// Identity/WebIdentity/ConnectionKey types — NIP-AZ's own spec says NIP-IC
// owns the ConnectionKey concept a p/P tag may carry instead of a raw
// pubkey. WebIdentity and ConnectionKey are re-exported here under nipAZ's
// own names so a caller who only touches AltZap doesn't have to import
// nipIC directly for the common case.
//
// Spec: https://github.com/ohstr/nips/blob/main/NIP-AZ.md
package nipAZ

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/utils"
)

// Failure modes specific to NIP-AZ; nipAZ also returns the shared
// nip57.Err* values above for checks common to both flows (signature,
// amount, description-hash, etc.) — see nip57.go.
var (
	ErrMissingSenderTag     = errors.New("nipAZ: missing P tag denoting the true sender")
	ErrSenderTagCount       = errors.New("nipAZ: on-behalf request must have exactly one P tag")
	ErrSenderTagNotAllowed  = errors.New("nipAZ: a 9520 request must not have a P tag; the signer is the sender")
	ErrChainMismatch        = errors.New("nipAZ: receipt chain does not match the request or the invoice")
	ErrHashLockMismatch     = errors.New("nipAZ: SHA256(preimage) does not match the invoice payment hash")
	ErrInvalidZapTag        = errors.New("nipAZ: invalid zap tag")
	ErrMissingChainTag      = errors.New("nipAZ: missing chain tag")
	ErrMissingLNURLTag      = errors.New("nipAZ: missing lnurl tag")
	ErrMissingPreimageTag   = errors.New("nipAZ: missing preimage tag")
	ErrInvalidInvoiceAmount = errors.New("nipAZ: invalid or missing amount in bolt11 invoice")
)

const (
	// AltZap kinds — not the standard NIP-57 9734/9735 pair; see the
	// package doc comment for why.
	KindAltZapRequest         = 9520
	KindAltZapReceipt         = 9521
	KindAltZapOnBehalfRequest = 9523
)

// DescriptionHash computes SHA256(description), hex-encoded — the value an
// LNURL server must put in a BOLT11 invoice's description_hash so it
// cryptographically binds to a specific AltZap request (NIP-AZ.md's
// "Description-hash binding" rule). description is hashed verbatim: for a
// kind 9521 receipt's "description" tag this is the exact wire string being
// stored (never re-marshaled — a receiver later hashes that same stored
// string to verify, so any re-serialization here would break the match).
func DescriptionHash(description string) string {
	sum := sha256.Sum256([]byte(description))
	return hex.EncodeToString(sum[:])
}

// Chain identifies which Lightning-routable network a request/receipt
// settles on. Open string type, no predefined values — a different consumer
// of this SDK may settle on an entirely different set of chains than any
// particular deployment does today. An application that wants named
// constants for its own known chains defines them itself, on top of this type.
type Chain string

// InvoiceCurrencies maps a chain to the BOLT11 currency prefixes its invoices
// carry (nip57.Invoice.Currency). ValidateAltZapReceipt rejects a receipt
// whose invoice is not on its chain; chains missing from the map are not
// checked. Add entries for other chains before validating their receipts.
var InvoiceCurrencies = map[Chain][]string{
	"flokicoin": {"fc"},
	"bitcoin":   {"bc", "tb", "tbs", "bcrt"},
}

// WebIdentity and ConnectionKey are re-exported from nipIC — see the
// package doc comment.
type (
	WebIdentity   = nipIC.WebIdentity
	ConnectionKey = nipIC.ConnectionKey
)

// Identity is a p/P tag value: either a native Nostr pubkey or a
// ConnectionKey scoped to a WebIdentity platform, with an optional stable
// display handle. Build one with Pubkey or Connection — never construct the
// underlying tag array by hand.
type Identity struct {
	value       string
	webIdentity WebIdentity
	handle      string
}

// Pubkey builds an Identity for a native Nostr recipient/sender.
func Pubkey(hex string) Identity {
	return Identity{value: hex}
}

// Connection builds an Identity for a recipient/sender on a platform with a
// canonical user-id form (x, discord, email, dns) who has no Nostr keypair yet,
// computing its ConnectionKey from typed input with nipIC.NewConnectionKey. A
// value that is not canonical, or a platform without a canonical form, is an
// error: such a key comes from the recipient's attestation or nconnection
// (ResolvedConnection).
func Connection(platform WebIdentity, typed string) (Identity, error) {
	key, err := nipIC.NewConnectionKey(platform, typed)
	if err != nil {
		return Identity{}, err
	}
	return Identity{value: key.String(), webIdentity: platform}, nil
}

// ResolvedConnection builds an Identity from a ConnectionKey the caller has
// already computed (e.g. resolved earlier in a request-handling pipeline and
// passed through several layers) — unlike Connection, it does not hash
// anything, so a caller who already has the key avoids computing the same
// SHA256 twice for one logical identity.
func ResolvedConnection(key ConnectionKey, platform WebIdentity) Identity {
	return Identity{value: key.String(), webIdentity: platform}
}

// WithHandle attaches a stable, human-readable display handle (e.g. a
// Discord username) to a receipt's Identity. Informational only — MUST NOT
// be used for identity resolution (NIP-AZ.md). Has no effect on request-side
// tags (9520/9523 never emit a 4th tag element; see AltZapRequestParams).
func (id Identity) WithHandle(handle string) Identity {
	id.handle = handle
	return id
}

// IsZero reports whether id is the zero Identity — i.e. absent. Used for
// optional identities (a request's Sender, a receipt's Recipient on an
// anonymous direct payment).
func (id Identity) IsZero() bool { return id.value == "" }

// WebIdentity returns the platform id is scoped to, or the zero value for a
// native Nostr identity.
func (id Identity) WebIdentity() WebIdentity { return id.webIdentity }

// Value returns the hex pubkey or ConnectionKey hex.
func (id Identity) Value() string { return id.value }

// Handle returns the stable display handle, or "" if none was set.
func (id Identity) Handle() string { return id.handle }

// toSlice renders id as a Nostr tag array under key ("p" or "P"). Requests
// never include a handle even if one is set on id (9520/9523 cap at 3
// elements, matching NIP-AZ's request format); receipts do, via includeHandle.
func (id Identity) toSlice(key string, includeHandle bool) []string {
	if id.webIdentity == "" {
		return []string{key, id.value}
	}
	if includeHandle && id.handle != "" {
		return []string{key, id.value, string(id.webIdentity), id.handle}
	}
	return []string{key, id.value, string(id.webIdentity)}
}

// identityFromRequestTag builds an Identity from a parsed p/P tag on a
// request (2 or 3 elements — requests never carry a handle). An empty or
// literal "nostr" platform element both mean "native pubkey", matching
// NIP-AZ.md's own rule that an omitted platform element defaults to nostr.
func identityFromRequestTag(tag []string) Identity {
	id := Identity{value: tag[1]}
	if len(tag) > 2 && tag[2] != "" && tag[2] != "nostr" {
		id.webIdentity = WebIdentity(tag[2])
	}
	return id
}

// identityFromReceiptTag is identityFromRequestTag plus an optional 4th
// element handle, which only receipts carry.
func identityFromReceiptTag(tag []string) Identity {
	id := identityFromRequestTag(tag)
	if len(tag) > 3 && tag[3] != "" {
		id.handle = tag[3]
	}
	return id
}

// altZapPolicy selects which actor's subset of NIP-AZ's Verification
// Algorithm a Parse*/Validate* call enforces. Rules marked MUST for a relay —
// signatures, the p/P tag rules, a receipt's hash lock, chain and
// description binding — hold under every policy.
type altZapPolicy struct {
	// relay tolerates the rules NIP-AZ marks SHOULD or MAY at relay ingest:
	// the lnurl, relays, amount, chain and e tags of a request, the amount
	// cross-checks of a receipt, and malformed zap-split tags.
	relay bool
}

var (
	// policyStrict is for LNURL servers settling a request and for callers
	// building their own events.
	policyStrict = altZapPolicy{}
	// policyRelay is for relays ingesting events someone else signed.
	policyRelay = altZapPolicy{relay: true}
)

// AltZapRequest is a parsed and validated AltZap request event (kind 9520
// or 9523).
type AltZapRequest struct {
	*nip01.Event
	Relays    []string
	Amount    int64
	Lnurl     string
	Chain     Chain    // required, to prevent cross-chain replay
	EventID   string   // e tag
	ATag      string   // a tag coordinate
	KTag      string   // k tag kind limit
	Recipient Identity // p tag
	Sender    Identity // P tag
}

// ParseAltZapRequest parses and validates an AltZap request event (kind
// 9520 or 9523).
func ParseAltZapRequest(event *nip01.Event) (*AltZapRequest, error) {
	return parseAltZapRequest(event, policyStrict)
}

func parseAltZapRequest(event *nip01.Event, policy altZapPolicy) (*AltZapRequest, error) {
	if event.Kind != KindAltZapRequest && event.Kind != KindAltZapOnBehalfRequest {
		return nil, fmt.Errorf("%w: got %d, want %d or %d", nip57.ErrWrongKind, event.Kind, KindAltZapRequest, KindAltZapOnBehalfRequest)
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
					if policy.relay {
						continue
					}
					return nil, fmt.Errorf("%w %q: %w", nip57.ErrInvalidRelayURL, r, err)
				}
				if u.Scheme != "wss" && u.Scheme != "ws" {
					if policy.relay {
						continue
					}
					return nil, fmt.Errorf("%w: %q", nip57.ErrInvalidRelayScheme, u.Scheme)
				}
				zr.Relays = append(zr.Relays, r)
			}
		case "amount":
			// Validate amount
			var a int64
			n, err := fmt.Sscanf(tag[1], "%d", &a)
			if err != nil || n != 1 {
				if policy.relay {
					continue
				}
				return nil, fmt.Errorf("%w: %q", nip57.ErrInvalidAmount, tag[1])
			}
			if a <= 0 && !policy.relay {
				return nil, fmt.Errorf("%w: %d", nip57.ErrInvalidAmountValue, a)
			}
			zr.Amount = a
		case "lnurl":
			if err := utils.ValidateLNURL(tag[1]); err != nil && !policy.relay {
				return nil, fmt.Errorf("%w %q: %w", nip57.ErrInvalidLNURL, tag[1], err)
			}
			zr.Lnurl = tag[1]
		case "e":
			if err := utils.Validate32Key(tag[1]); err != nil && !policy.relay {
				return nil, fmt.Errorf("%w %q: %w", nip57.ErrInvalidEventTag, tag[1], err)
			}
			zr.EventID = tag[1]
			eTagCount++
		case "chain":
			zr.Chain = Chain(tag[1])
		case "a":
			zr.ATag = tag[1]
		case "k":
			zr.KTag = tag[1]
		case "p":
			zr.Recipient = identityFromRequestTag(tag)
			pTagCount++
		case "P":
			zr.Sender = identityFromRequestTag(tag)
			PTagCount++
		case "zap":
			if policy.relay {
				continue
			}
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
	if zr.Chain == "" && !policy.relay {
		return nil, ErrMissingChainTag
	}

	if pTagCount != 1 {
		return nil, fmt.Errorf("%w: kind %d", nip57.ErrRecipientTagCount, event.Kind)
	}
	if zr.Lnurl == "" && !policy.relay {
		return nil, fmt.Errorf("%w: kind %d", ErrMissingLNURLTag, event.Kind)
	}

	switch {
	case event.Kind == KindAltZapOnBehalfRequest && PTagCount == 0:
		return nil, ErrMissingSenderTag
	case event.Kind == KindAltZapOnBehalfRequest && PTagCount > 1:
		return nil, fmt.Errorf("%w: got %d", ErrSenderTagCount, PTagCount)
	case event.Kind == KindAltZapRequest && PTagCount > 0:
		return nil, ErrSenderTagNotAllowed
	}

	// e tag is optional (0 or 1)
	if eTagCount > 1 && !policy.relay {
		return nil, nip57.ErrTooManyEventTags
	}

	// Relays tag required
	if len(zr.Relays) == 0 && !policy.relay {
		return nil, nip57.ErrMissingRelaysTag
	}

	return zr, nil
}

// ValidateAltZapRequest checks if the event is a valid AltZap request and
// optionally enforces the amount.
func ValidateAltZapRequest(event *nip01.Event, expectedAmountMloki int64) error {
	return validateAltZapRequest(event, expectedAmountMloki, policyStrict)
}

// ValidateAltZapRequestForRelay is ValidateAltZapRequest for a relay
// ingesting a request someone else signed: it enforces only the rules NIP-AZ
// marks MUST for a relay (signature, exactly one p, the P rules).
func ValidateAltZapRequestForRelay(event *nip01.Event) error {
	return validateAltZapRequest(event, 0, policyRelay)
}

func validateAltZapRequest(event *nip01.Event, expectedAmountMloki int64, policy altZapPolicy) error {
	// 1. Signature check
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", nip57.ErrInvalidSignature, err)
	}

	// 2. Parse and structure check
	zr, err := parseAltZapRequest(event, policy)
	if err != nil {
		return err
	}
	if policy.relay {
		return nil
	}

	// 3. Amount check
	if zr.Amount <= 0 {
		return nip57.ErrInvalidAmountValue
	}

	if expectedAmountMloki > 0 && zr.Amount != expectedAmountMloki {
		return fmt.Errorf("%w: expected %d mloki, got %d mloki", nip57.ErrAmountMismatch, expectedAmountMloki, zr.Amount)
	}

	return nil
}

// AltZapReceipt is a parsed and validated AltZap receipt event (kind 9521).
type AltZapReceipt struct {
	*nip01.Event
	Recipient            Identity // p tag
	Sender               Identity // P tag
	ResolvedPubkey       string   // r tag
	ResolvedSenderPubkey string   // R tag
	Bolt11               string
	Chain                Chain
	Preimage             string
	Description          string
	Request              *AltZapRequest
}

// ParseAltZapReceipt parses and validates an AltZap receipt event (kind 9521).
func ParseAltZapReceipt(event *nip01.Event) (*AltZapReceipt, error) {
	return parseAltZapReceipt(event, policyStrict)
}

func parseAltZapReceipt(event *nip01.Event, policy altZapPolicy) (*AltZapReceipt, error) {
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
			zr.Recipient = identityFromReceiptTag(tag)
		case "P":
			zr.Sender = identityFromReceiptTag(tag)
		case "r":
			zr.ResolvedPubkey = tag[1]
		case "R":
			zr.ResolvedSenderPubkey = tag[1]
		case "bolt11":
			zr.Bolt11 = tag[1]
		case "chain":
			zr.Chain = Chain(tag[1])
		case "preimage":
			zr.Preimage = tag[1]
		case "description":
			zr.Description = tag[1]
		case "zap":
			if policy.relay {
				continue
			}
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
	if zr.Recipient.IsZero() && zr.Description != "" {
		// A receipt for a plain LNURL payment (no description) may omit p;
		// one carrying a request must name its recipient.
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

		req, err := parseAltZapRequest(&reqEvent, policy)
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
	return validateAltZapReceipt(receipt, policyStrict)
}

// ValidateAltZapReceiptForRelay is ValidateAltZapReceipt for a relay
// ingesting a receipt: it still rejects a forged receipt (signature, hash
// lock, chain, description binding, recipient and chain cross-checks) but
// keeps one whose amounts disagree, since the payment did happen.
func ValidateAltZapReceiptForRelay(receipt *nip01.Event) error {
	return validateAltZapReceipt(receipt, policyRelay)
}

func validateAltZapReceipt(receipt *nip01.Event, policy altZapPolicy) error {
	// 1. Signature
	if err := receipt.Verify(); err != nil {
		return fmt.Errorf("%w: %w", nip57.ErrInvalidSignature, err)
	}

	// 2. Parse
	zr, err := parseAltZapReceipt(receipt, policy)
	if err != nil {
		return err
	}

	// 3. Verify Invoice
	invoice, err := nip57.DecodeBolt11(zr.Bolt11)
	if err != nil {
		return fmt.Errorf("%w: %w", nip57.ErrBolt11DecodeFailed, err)
	}

	// Hash lock: the preimage must be the one that paid this invoice.
	preimage, err := hex.DecodeString(zr.Preimage)
	if err != nil {
		return fmt.Errorf("%w: preimage is not hex", ErrHashLockMismatch)
	}
	if sum := sha256.Sum256(preimage); !strings.EqualFold(hex.EncodeToString(sum[:]), invoice.PaymentHash) {
		return ErrHashLockMismatch
	}

	// The invoice must be on the receipt's chain, when the chain is known.
	if prefixes, known := InvoiceCurrencies[zr.Chain]; known && !slices.Contains(prefixes, invoice.Currency) {
		return fmt.Errorf("%w: chain %q, invoice currency %q", ErrChainMismatch, zr.Chain, invoice.Currency)
	}

	// 4. Validate Logic (Strict for Zaps, relaxed for Direct Payments)
	if zr.Description != "" {
		if zr.Request == nil {
			return nip57.ErrInvalidEmbeddedRequest
		}

		// A. Verify description hash (CRITICAL)
		// SHA256(description) == invoice.DescriptionHash
		descHashHex := DescriptionHash(zr.Description)

		if invoice.DescriptionHash != descHashHex {
			return fmt.Errorf("%w: have=%s want=%s", nip57.ErrDescriptionHashMismatch, descHashHex, invoice.DescriptionHash)
		}

		// B. Verify amounts match
		// Invoice amount mloki == Request amount mloki
		if !policy.relay && invoice.AmountMloki != zr.Request.Amount {
			return fmt.Errorf("%w: invoice=%d request=%d", nip57.ErrAmountMismatch, invoice.AmountMloki, zr.Request.Amount)
		}

		// C. Verify Recipients match
		if zr.Recipient.Value() != zr.Request.Recipient.Value() {
			return fmt.Errorf("%w: receipt=%s request_author=%s", nip57.ErrRecipientMismatch, zr.Recipient.Value(), zr.Request.Recipient.Value())
		}

		// D. The receipt settles on the chain the request asked for.
		if zr.Chain != zr.Request.Chain {
			return fmt.Errorf("%w: receipt %q, request %q", ErrChainMismatch, zr.Chain, zr.Request.Chain)
		}
	} else {
		// Direct Payment (no Zap Request description)
		if !policy.relay && invoice.AmountMloki <= 0 {
			return ErrInvalidInvoiceAmount
		}
	}

	return nil
}

// AltZapRequestParams describes an AltZap request (kind 9520, or 9523 when
// built via NewAltZapOnBehalfRequest). PrivateKey, Chain, Recipient, Lnurl,
// AmountMloki, and Relays are required; the rest are optional. The event is
// signed with PrivateKey internally — the caller never calls .Sign()
// themselves.
type AltZapRequestParams struct {
	PrivateKey  string   // sender's (or proxy agent's, for on-behalf) nsec hex
	Chain       Chain    // e.g. "flokicoin" — prevents cross-chain replay
	Recipient   Identity // recipient ("p" tag) — required
	Lnurl       string   // recipient's LNURL-pay endpoint
	AmountMloki int64    // amount in mloki (milli-loki)
	Relays      []string // relays the zap receipt should be published to
	Sender      Identity // "P" tag — only for 9523; NewAltZapOnBehalfRequest sets it, NewAltZapRequest rejects it
	Content     string   // optional note content
	EventID     *string  // optional zapped event ID ("e" tag)
}

// NewAltZapRequest creates, signs, and returns a new AltZap request event
// (kind 9520). The signer is the sender, so p.Sender must be zero.
func NewAltZapRequest(p AltZapRequestParams) (*nip01.Event, error) {
	if !p.Sender.IsZero() {
		return nil, ErrSenderTagNotAllowed
	}
	return newAltZapRequest(KindAltZapRequest, p)
}

// newAltZapRequest builds and signs a request of the given kind, so the
// signature always covers the final kind.
func newAltZapRequest(kind int, p AltZapRequestParams) (*nip01.Event, error) {
	tags := [][]string{
		p.Recipient.toSlice("p", false),
		{"amount", fmt.Sprintf("%d", p.AmountMloki)},
		{"lnurl", p.Lnurl},
		{"chain", string(p.Chain)},
	}

	if !p.Sender.IsZero() {
		tags = append(tags, p.Sender.toSlice("P", false))
	}

	if len(p.Relays) > 0 {
		relayTag := []string{"relays"}
		relayTag = append(relayTag, p.Relays...)
		tags = append(tags, relayTag)
	}

	if p.EventID != nil {
		tags = append(tags, []string{"e", *p.EventID})
	}

	event := &nip01.Event{
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      kind,
		Tags:      tags,
		Content:   p.Content,
	}
	if err := event.Sign(p.PrivateKey); err != nil {
		return nil, fmt.Errorf("nipAZ: sign request: %w", err)
	}
	return event, nil
}

// NewAltZapOnBehalfRequest creates, signs, and returns a new proxy AltZap
// request event (kind 9523) — used when a Proxy Agent (e.g. a bot) signs on
// behalf of an identified sender who does not hold the signing key. sender
// is required (not an optional params field) so it is impossible to build
// an invalid 9523 at construction time — kind 9523 mandates a P tag.
func NewAltZapOnBehalfRequest(sender Identity, p AltZapRequestParams) (*nip01.Event, error) {
	if sender.IsZero() {
		return nil, ErrMissingSenderTag
	}
	p.Sender = sender
	return newAltZapRequest(KindAltZapOnBehalfRequest, p)
}

// AltZapReceiptParams describes an AltZap receipt (kind 9521), issued by the
// LNURL server once the invoice is paid. PrivateKey and Bolt11 are required;
// Recipient is the zero Identity for a plain LNURL payment settled without
// a signed request.
//
// ResolvedRecipientPubkey/ResolvedSenderPubkey/Coordinate/EventID are for
// callers whose p/P tags carry a non-Nostr identity (e.g. a ConnectionKey)
// and need to mirror the resolved native pubkey ("r"/"R" tags) and/or the
// zapped event/addressable-event coordinate ("e"/"a" tags) onto the receipt.
//
// Recipient/Sender (including any handle attached via Identity.WithHandle)
// are always authoritative — never re-derived or overridden from Description,
// even when Description embeds different-looking p/P tags. Description is
// stored verbatim for auditability only.
type AltZapReceiptParams struct {
	PrivateKey              string // LNURL server's nsec hex — required, derives the event pubkey and signs
	Chain                   Chain
	Recipient               Identity
	Sender                  Identity
	Bolt11                  string
	Description             string // JSON of the embedded AltZap request, if any
	Preimage                *string
	ResolvedRecipientPubkey string // optional "r" tag
	ResolvedSenderPubkey    string // optional "R" tag
	Coordinate              string // optional "a" tag
	EventID                 string // optional "e" tag
}

// NewAltZapReceipt creates, signs, and returns a new AltZap receipt event
// (kind 9521).
func NewAltZapReceipt(p AltZapReceiptParams) (*nip01.Event, error) {
	tags := [][]string{
		{"bolt11", p.Bolt11},
		{"chain", string(p.Chain)},
	}

	if !p.Recipient.IsZero() {
		tags = append(tags, p.Recipient.toSlice("p", true))
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

	if !p.Sender.IsZero() {
		tags = append(tags, p.Sender.toSlice("P", true))
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

	event := &nip01.Event{
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindAltZapReceipt,
		Tags:      tags,
		Content:   "",
	}
	if err := event.Sign(p.PrivateKey); err != nil {
		return nil, fmt.Errorf("nipAZ: sign receipt: %w", err)
	}
	return event, nil
}
