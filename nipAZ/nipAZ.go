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

	// ErrInvalidIdentityTag: a p or P tag whose [1] is not 64 lowercase hex,
	// or whose [2] is neither empty, "nostr" nor a NIP-IC platform name. The
	// value is refused, never lowercased or repaired.
	ErrInvalidIdentityTag = errors.New("nipAZ: p/P tag must carry 64 lowercase hex and a valid platform name")
	// ErrInvalidIATag: an ia tag that is repeated or not 64 lowercase hex.
	ErrInvalidIATag = errors.New("nipAZ: at most one ia tag, 64 lowercase hex")
	// ErrIARequired: p is a ConnectionKey on a platform without a canonical
	// form, so the request must name the IA that attested it.
	ErrIARequired = errors.New("nipAZ: a ConnectionKey on a platform without a canonical form needs an ia tag")
	// ErrIANotAllowed: an ia tag beside a pubkey p.
	ErrIANotAllowed = errors.New("nipAZ: a request to a Nostr pubkey must not carry an ia tag")
	// ErrUntrustedIA: the request's ia names an IA the LNURL server does not trust.
	ErrUntrustedIA = errors.New("nipAZ: ia names an untrusted IA")
	// ErrChainNotAdvertised: the request's chain is not one the endpoint advertises.
	ErrChainNotAdvertised = errors.New("nipAZ: chain is not advertised by this endpoint")
	// ErrLnurlNotOwnEndpoint: the request's lnurl decodes to another endpoint.
	ErrLnurlNotOwnEndpoint = errors.New("nipAZ: lnurl does not name this LNURL server's endpoint")
	// ErrTooManyATags: more than one a tag on a request.
	ErrTooManyATags = errors.New("nipAZ: at most one a tag allowed")
	// ErrDuplicateTag: a single-valued tag (chain, amount, lnurl, bolt11,
	// preimage, description, p, P) appears twice.
	ErrDuplicateTag = errors.New("nipAZ: tag appears more than once")
	// ErrUnknownChain: a receipt's chain has no entry in InvoiceCurrencies, so
	// its invoice cannot be shown to belong to it.
	ErrUnknownChain = errors.New("nipAZ: no invoice currency is known for this chain")
	// ErrSenderMismatch: a receipt's P differs from the embedded request's
	// sender.
	ErrSenderMismatch = errors.New("nipAZ: receipt P does not match the embedded request's sender")
	// ErrIAMismatch: a receipt's ia differs from the embedded request's.
	ErrIAMismatch = errors.New("nipAZ: receipt ia does not match the embedded request's")
	// ErrReceiptSigner: the receipt is not signed by the nostrPubkey of the
	// endpoint the embedded request's lnurl names (receipt rule 10).
	ErrReceiptSigner = errors.New("nipAZ: receipt is not signed by the endpoint's nostrPubkey")
	// ErrNostrPubkeyUnknown: receipt rule 10 could not be evaluated, because
	// ReceiptPolicy.NostrPubkeyFor is nil or failed.
	ErrNostrPubkeyUnknown = errors.New("nipAZ: the endpoint's nostrPubkey is unknown")
	// ErrLinkNotAuthorized: an r or R tag was asked for without the user's
	// authorization to make the ConnectionKey-to-pubkey link public.
	ErrLinkNotAuthorized = errors.New("nipAZ: r/R need the user's authorization to publish the link")
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
// carry (nip57.Invoice.Currency). Receipt validation rejects a receipt whose
// invoice is not on its chain, and one whose chain is missing from the map
// (ErrUnknownChain): without a mapping nothing shows the invoice belongs to
// it. Add an entry (e.g. "examplecoin": {"ex"}) before validating receipts of
// another chain.
var InvoiceCurrencies = map[Chain][]string{
	"flokicoin": {"fc"},
	"bitcoin":   {"bc"},
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
// SHA256 twice for one logical identity. platform must be a NIP-IC platform
// name, never "nostr": the builders refuse any other (ErrInvalidIdentityTag).
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

// EconomicSender returns who pays: the P tag of a 9523, never its Proxy Agent
// signer, and the signer of a 9520.
func (r *AltZapRequest) EconomicSender() Identity {
	if r.Kind == KindAltZapOnBehalfRequest {
		return r.Sender
	}
	return Pubkey(r.PubKey)
}

// sameIdentity compares two identities by [1] and [2] (an empty platform and
// "nostr" are the same), ignoring any handle.
func sameIdentity(a, b Identity) bool {
	return a.value == b.value && a.webIdentity == b.webIdentity
}

// checkPlatform refuses an identity a receiver would misread: a platform other
// than a NIP-IC platform name, "nostr" included, which every receiver reads as
// a native pubkey even when the value is a ConnectionKey.
func (id Identity) checkPlatform(key string) error {
	if id.webIdentity != "" && !nipIC.ValidPlatformName(id.webIdentity) {
		return fmt.Errorf("%w: %s tag platform", ErrInvalidIdentityTag, key)
	}
	return nil
}

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

// identityFromTag builds an Identity from a p/P tag, enforcing NIP-AZ's
// 3-element identity tag: [1] is 64 lowercase hex; [2] omitted, empty or
// "nostr" means a native pubkey, anything else must be a NIP-IC platform name.
// Nothing is lowercased or repaired. Only receipts read a 4th element (the
// handle), and it is display only.
func identityFromTag(tag []string, withHandle bool) (Identity, error) {
	if len(tag) < 2 || !isLowerHex64(tag[1]) {
		return Identity{}, fmt.Errorf("%w: %s tag value", ErrInvalidIdentityTag, tag[0])
	}
	id := Identity{value: tag[1]}
	if len(tag) > 2 && tag[2] != "" && tag[2] != "nostr" {
		if !nipIC.ValidPlatformName(WebIdentity(tag[2])) {
			return Identity{}, fmt.Errorf("%w: %s tag platform", ErrInvalidIdentityTag, tag[0])
		}
		id.webIdentity = WebIdentity(tag[2])
	}
	if withHandle && len(tag) > 3 && tag[3] != "" {
		id.handle = tag[3]
	}
	return id, nil
}

// isLowerHex64 reports 64 characters of 0-9a-f.
func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parseAmount reads a positive decimal integer: ^[1-9][0-9]*$ that fits an
// int64. "0", "-1", "+1", "01", "1.5", "1e6" and "" are refused.
func parseAmount(s string) (int64, bool) {
	if s == "" || s[0] < '1' || s[0] > '9' {
		return 0, false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// decodeLnurlTag decodes a bech32 lnurl tag (either case, never mixed) to its
// URL and normalises it with NormalizeEndpoint. A lightning address is not
// bech32 and is refused.
func decodeLnurlTag(s string) (string, error) {
	if s != strings.ToLower(s) && s != strings.ToUpper(s) {
		return "", errors.New("mixed-case bech32")
	}
	raw, err := utils.DecodeLNURL(s)
	if err != nil {
		return "", err
	}
	return NormalizeEndpoint(raw)
}

// NormalizeEndpoint parses an LNURL-pay endpoint URL and lowercases its scheme
// and host, the form ServerPolicy.OwnEndpoint and AltZapRequest.Endpoint are
// compared in.
func NormalizeEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("endpoint is not an absolute URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

// checkZapSplitTag validates a zap-split tag on a request or receipt.
func checkZapSplitTag(tag []string) error {
	if len(tag) < 3 {
		return ErrInvalidZapTag
	}
	if err := utils.Validate32Key(tag[1]); err != nil {
		return fmt.Errorf("%w: pubkey %q: %w", ErrInvalidZapTag, tag[1], err)
	}
	u, err := url.ParseRequestURI(tag[2])
	if err != nil {
		return fmt.Errorf("%w: relay url %q: %w", ErrInvalidZapTag, tag[2], err)
	}
	if u.Scheme != "wss" && u.Scheme != "ws" {
		return fmt.Errorf("%w: relay scheme %q", ErrInvalidZapTag, u.Scheme)
	}
	if len(tag) > 3 {
		if _, err := strconv.Atoi(tag[3]); err != nil {
			return fmt.Errorf("%w: weight %q: %w", ErrInvalidZapTag, tag[3], err)
		}
	}
	return nil
}

// AltZapRequest is a parsed and validated AltZap request event (kind 9520
// or 9523).
type AltZapRequest struct {
	*nip01.Event
	Relays    []string
	Amount    int64
	Lnurl     string // the lnurl tag as received
	Endpoint  string // Lnurl decoded and normalised (NormalizeEndpoint); "" when not checked
	Chain     Chain  // required, to prevent cross-chain replay
	EventID   string // e tag
	ATag      string // a tag coordinate
	KTag      string // k tag kind limit
	IA        string // ia tag: the IA that attested a ConnectionKey p, "" when absent
	Recipient Identity
	Sender    Identity // P tag (9523 only); see EconomicSender
}

// ParseAltZapRequest parses an AltZap request event (kind 9520 or 9523) and
// checks every rule of NIP-AZ's request table that needs neither the
// signature nor the LNURL server's own settings: the p, P and ia rules, a
// present chain, a positive integer amount, a well-formed lnurl, the relays and
// the e and a tags. It does not verify the signature; ValidateAltZapRequest
// does, and adds the server's rules.
func ParseAltZapRequest(event *nip01.Event) (*AltZapRequest, error) {
	return parseAltZapRequest(event, false)
}

// parseAltZapRequest checks rules 2 and 3 (MUST for everyone), the presence
// part of 4, the positive-integer part of 5, 8 and 9 (SHOULD for a relay,
// enforced here for both), and with relay false the well-formed part of 6, 7
// and the zap-split tags.
func parseAltZapRequest(event *nip01.Event, relay bool) (*AltZapRequest, error) {
	if event == nil {
		return nil, fmt.Errorf("%w: nil event", nip57.ErrWrongKind)
	}
	if event.Kind != KindAltZapRequest && event.Kind != KindAltZapOnBehalfRequest {
		return nil, fmt.Errorf("%w: got %d, want %d or %d", nip57.ErrWrongKind, event.Kind, KindAltZapRequest, KindAltZapOnBehalfRequest)
	}

	zr := &AltZapRequest{Event: event}
	var nP, nSender, nE, nA, nIA, nChain, nAmount, nLnurl, nRelays int
	var amount string

	for _, tag := range event.Tags {
		if len(tag) == 0 {
			continue
		}
		if len(tag) < 2 {
			if tag[0] == "p" || tag[0] == "P" {
				return nil, fmt.Errorf("%w: %s tag has no value", ErrInvalidIdentityTag, tag[0])
			}
			continue
		}
		switch tag[0] {
		case "relays":
			nRelays++
			for _, r := range tag[1:] {
				u, err := url.ParseRequestURI(r)
				if err != nil {
					if relay {
						continue
					}
					return nil, fmt.Errorf("%w %q: %w", nip57.ErrInvalidRelayURL, r, err)
				}
				if u.Scheme != "wss" && u.Scheme != "ws" {
					if relay {
						continue
					}
					return nil, fmt.Errorf("%w: %q", nip57.ErrInvalidRelayScheme, u.Scheme)
				}
				zr.Relays = append(zr.Relays, r)
			}
		case "amount":
			nAmount++
			amount = tag[1]
		case "lnurl":
			nLnurl++
			zr.Lnurl = tag[1]
		case "e":
			nE++
			if !isLowerHex64(tag[1]) {
				return nil, fmt.Errorf("%w: not 64 lowercase hex", nip57.ErrInvalidEventTag)
			}
			zr.EventID = tag[1]
		case "a":
			nA++
			zr.ATag = tag[1]
		case "k":
			zr.KTag = tag[1]
		case "chain":
			nChain++
			zr.Chain = Chain(tag[1])
		case "ia":
			nIA++
			zr.IA = tag[1]
		case "p":
			nP++
			id, err := identityFromTag(tag, false)
			if err != nil {
				return nil, err
			}
			zr.Recipient = id
		case "P":
			nSender++
			id, err := identityFromTag(tag, false)
			if err != nil {
				return nil, err
			}
			zr.Sender = id
		case "zap":
			if relay {
				continue
			}
			if err := checkZapSplitTag(tag); err != nil {
				return nil, err
			}
		}
	}

	// Rule 2: exactly one p (each p and P was checked as it was read).
	if nP != 1 {
		return nil, fmt.Errorf("%w: kind %d has %d", nip57.ErrRecipientTagCount, event.Kind, nP)
	}
	// Rule 3: no P on a 9520, exactly one on a 9523.
	switch {
	case event.Kind == KindAltZapOnBehalfRequest && nSender == 0:
		return nil, ErrMissingSenderTag
	case event.Kind == KindAltZapOnBehalfRequest && nSender > 1:
		return nil, fmt.Errorf("%w: got %d", ErrSenderTagCount, nSender)
	case event.Kind == KindAltZapRequest && nSender > 0:
		return nil, ErrSenderTagNotAllowed
	}
	// Rule 4, presence.
	if nChain > 1 {
		return nil, fmt.Errorf("%w: chain", ErrDuplicateTag)
	}
	if zr.Chain == "" {
		return nil, ErrMissingChainTag
	}
	// Rule 5, a positive integer.
	switch {
	case nAmount == 0:
		return nil, fmt.Errorf("%w: missing", nip57.ErrInvalidAmount)
	case nAmount > 1:
		return nil, fmt.Errorf("%w: amount", ErrDuplicateTag)
	}
	a, ok := parseAmount(amount)
	if !ok {
		return nil, fmt.Errorf("%w: %q", nip57.ErrInvalidAmount, amount)
	}
	zr.Amount = a
	// Rule 8.
	if nE > 1 {
		return nil, nip57.ErrTooManyEventTags
	}
	if nA > 1 {
		return nil, ErrTooManyATags
	}
	// Rule 9.
	if nIA > 1 || (nIA == 1 && !isLowerHex64(zr.IA)) {
		return nil, ErrInvalidIATag
	}
	switch platform := zr.Recipient.webIdentity; {
	case platform == "" && nIA > 0:
		return nil, ErrIANotAllowed
	case platform != "" && !nipIC.HasCanonicalForm(platform) && nIA == 0:
		return nil, fmt.Errorf("%w: platform %q", ErrIARequired, platform)
	}
	if relay {
		return zr, nil
	}

	// Rule 6, well formed.
	switch {
	case nLnurl == 0:
		return nil, fmt.Errorf("%w: kind %d", ErrMissingLNURLTag, event.Kind)
	case nLnurl > 1:
		return nil, fmt.Errorf("%w: lnurl", ErrDuplicateTag)
	}
	endpoint, err := decodeLnurlTag(zr.Lnurl)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", nip57.ErrInvalidLNURL, err)
	}
	zr.Endpoint = endpoint
	// Rule 7.
	if nRelays == 0 || len(zr.Relays) == 0 {
		return nil, nip57.ErrMissingRelaysTag
	}
	return zr, nil
}

// ServerPolicy is what an LNURL server checks a request against at its
// callback: the chains it advertises, its own endpoint (the decoded URL its
// lnurl encodes) and the IAs it trusts. A nil TrustedIA trusts none.
type ServerPolicy struct {
	Chains      []Chain
	OwnEndpoint string
	TrustedIA   func(ia string) bool
}

// ValidateAltZapRequest runs every rule of NIP-AZ's request table, as an
// LNURL server must before it issues an invoice: the signature first (rule
// 1), then the tag rules of ParseAltZapRequest, and the server's own rules:
// chain advertised (4), amount equal to the callback's amount parameter (5),
// lnurl decoding to p.OwnEndpoint (6) and ia trusted (10).
func ValidateAltZapRequest(event *nip01.Event, p ServerPolicy, callbackAmount int64) (*AltZapRequest, error) {
	if event == nil {
		return nil, fmt.Errorf("%w: nil event", nip57.ErrWrongKind)
	}
	if err := event.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %w", nip57.ErrInvalidSignature, err)
	}
	zr, err := parseAltZapRequest(event, false)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(p.Chains, zr.Chain) {
		return nil, fmt.Errorf("%w: %q", ErrChainNotAdvertised, zr.Chain)
	}
	if zr.Amount != callbackAmount {
		return nil, fmt.Errorf("%w: callback %d, tag %d", nip57.ErrAmountMismatch, callbackAmount, zr.Amount)
	}
	own, err := NormalizeEndpoint(p.OwnEndpoint)
	if err != nil || own != zr.Endpoint {
		return nil, ErrLnurlNotOwnEndpoint
	}
	if zr.IA != "" && (p.TrustedIA == nil || !p.TrustedIA(zr.IA)) {
		return nil, ErrUntrustedIA
	}
	return zr, nil
}

// ValidateAltZapRequestForRelay is the relay subset of the request table: it
// rejects a forged event (rule 1) and a broken p, P or ia (rules 2, 3, 9), a
// missing chain (4), a non-positive or malformed amount (5) and repeated e or
// a tags (8). It does not check the lnurl or relays tags (MAY), nor anything
// only the LNURL server knows.
func ValidateAltZapRequestForRelay(event *nip01.Event) error {
	if event == nil {
		return fmt.Errorf("%w: nil event", nip57.ErrWrongKind)
	}
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", nip57.ErrInvalidSignature, err)
	}
	_, err := parseAltZapRequest(event, true)
	return err
}

// SupportsAltZap reports whether an LNURL-pay endpoint accepts AltZap
// requests: allowsNostr is true and its metadata lists at least one
// chain/<name> entry. chains are the advertised names, in order. A client
// must not send a 9520 or 9523 to an endpoint for which ok is false.
func SupportsAltZap(pr utils.PayResponse) (chains []Chain, ok bool) {
	if !pr.AllowsNostr {
		return nil, false
	}
	var entries [][]any
	if err := json.Unmarshal([]byte(pr.Metadata), &entries); err != nil {
		return nil, false
	}
	for _, entry := range entries {
		if len(entry) == 0 {
			continue
		}
		tag, isString := entry[0].(string)
		name, found := strings.CutPrefix(tag, "chain/")
		if !isString || !found || name == "" || slices.Contains(chains, Chain(name)) {
			continue
		}
		chains = append(chains, Chain(name))
	}
	return chains, len(chains) > 0
}

// AltZapReceipt is a parsed and validated AltZap receipt event (kind 9521).
type AltZapReceipt struct {
	*nip01.Event
	Recipient            Identity // p tag
	Sender               Identity // P tag
	ResolvedPubkey       string   // r tag
	ResolvedSenderPubkey string   // R tag
	IA                   string   // ia tag, copied from the request
	Amount               int64    // amount tag; 0 when absent
	Bolt11               string
	Chain                Chain
	Preimage             string
	Description          string
	Request              *AltZapRequest
}

// ParseAltZapReceipt parses an AltZap receipt event (kind 9521): its tags,
// and the embedded request, whose signature it verifies and whose tag rules
// it checks as ParseAltZapRequest does. It verifies neither the receipt's
// signature nor the invoice; ValidateAltZapReceipt does.
func ParseAltZapReceipt(event *nip01.Event) (*AltZapReceipt, error) {
	return parseAltZapReceipt(event, false)
}

func parseAltZapReceipt(event *nip01.Event, relay bool) (*AltZapReceipt, error) {
	if event == nil {
		return nil, fmt.Errorf("%w: nil event", nip57.ErrWrongKind)
	}
	if event.Kind != KindAltZapReceipt {
		return nil, fmt.Errorf("%w: got %d, want %d", nip57.ErrWrongKind, event.Kind, KindAltZapReceipt)
	}

	zr := &AltZapReceipt{Event: event}
	seen := map[string]int{}
	var amount string

	for _, tag := range event.Tags {
		if len(tag) == 0 {
			continue
		}
		if len(tag) < 2 {
			if tag[0] == "p" || tag[0] == "P" {
				return nil, fmt.Errorf("%w: %s tag has no value", ErrInvalidIdentityTag, tag[0])
			}
			continue
		}
		seen[tag[0]]++
		var err error
		switch tag[0] {
		case "p":
			zr.Recipient, err = identityFromTag(tag, true)
		case "P":
			zr.Sender, err = identityFromTag(tag, true)
		case "r":
			zr.ResolvedPubkey = tag[1]
		case "R":
			zr.ResolvedSenderPubkey = tag[1]
		case "ia":
			zr.IA = tag[1]
		case "amount":
			amount = tag[1]
		case "bolt11":
			zr.Bolt11 = tag[1]
		case "chain":
			zr.Chain = Chain(tag[1])
		case "preimage":
			zr.Preimage = tag[1]
		case "description":
			zr.Description = tag[1]
		case "zap":
			if !relay {
				err = checkZapSplitTag(tag)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"p", "P", "amount", "bolt11", "chain", "preimage", "description"} {
		if seen[name] > 1 {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateTag, name)
		}
	}
	if seen["ia"] > 1 || (seen["ia"] == 1 && !isLowerHex64(zr.IA)) {
		return nil, ErrInvalidIATag
	}
	if seen["amount"] == 1 {
		a, ok := parseAmount(amount)
		if !ok {
			return nil, fmt.Errorf("%w: receipt amount %q", nip57.ErrInvalidAmount, amount)
		}
		zr.Amount = a
	}

	// Rule 2.
	if zr.Bolt11 == "" {
		return nil, nip57.ErrMissingBolt11Tag
	}
	if zr.Chain == "" {
		return nil, ErrMissingChainTag
	}
	if zr.Preimage == "" {
		return nil, ErrMissingPreimageTag
	}
	if zr.Recipient.IsZero() && seen["description"] > 0 {
		// A receipt for a plain LNURL payment (no description) may omit p;
		// one carrying a request must name its recipient.
		return nil, nip57.ErrMissingRecipientTag
	}

	// Rule 5, first half: the description embeds a validly signed request.
	if seen["description"] > 0 {
		var reqEvent nip01.Event
		if err := json.Unmarshal([]byte(zr.Description), &reqEvent); err != nil {
			return nil, fmt.Errorf("%w: %w", nip57.ErrInvalidDescriptionJSON, err)
		}
		if err := reqEvent.Verify(); err != nil {
			return nil, fmt.Errorf("%w: embedded request signature invalid: %w", nip57.ErrInvalidEmbeddedRequest, err)
		}
		req, err := parseAltZapRequest(&reqEvent, relay)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", nip57.ErrInvalidEmbeddedRequest, err)
		}
		zr.Request = req
	}
	return zr, nil
}

// ReceiptPolicy is what receipt rule 10 needs: the nostrPubkey the
// LNURL-pay endpoint at a decoded, normalised lnurl URL advertises (fetched
// or cached by the caller).
type ReceiptPolicy struct {
	NostrPubkeyFor func(lnurlDecoded string) (string, error)
}

// ValidateAltZapReceipt runs every rule of NIP-AZ's receipt table, as the
// LNURL server must before publishing and a client must before displaying a
// receipt as a payment. Rule 10 calls p.NostrPubkeyFor with the embedded
// request's decoded lnurl; a nil NostrPubkeyFor fails a receipt that has a
// description (ErrNostrPubkeyUnknown) rather than skip the rule.
func ValidateAltZapReceipt(receipt *nip01.Event, p ReceiptPolicy) (*AltZapReceipt, error) {
	return validateAltZapReceipt(receipt, false, &p, true)
}

// ValidateAltZapReceiptForRelay is the relay subset of the receipt table:
// rules 1 to 6 (MUST) and 7 to 9 (SHOULD); rule 10 is skipped. The embedded
// request is held to the relay subset of the request table, so a receipt
// whose request carries a lightning address in lnurl is still stored.
func ValidateAltZapReceiptForRelay(receipt *nip01.Event) error {
	_, err := validateAltZapReceipt(receipt, true, nil, true)
	return err
}

// validateAltZapReceipt runs rules 1 (when checkSig) to 9, and rule 10 when
// policy is set.
func validateAltZapReceipt(receipt *nip01.Event, relay bool, policy *ReceiptPolicy, checkSig bool) (*AltZapReceipt, error) {
	if receipt == nil {
		return nil, fmt.Errorf("%w: nil event", nip57.ErrWrongKind)
	}
	// 1. Signature, before any tag is read.
	if checkSig {
		if err := receipt.Verify(); err != nil {
			return nil, fmt.Errorf("%w: %w", nip57.ErrInvalidSignature, err)
		}
	}
	// 2. Required tags (and the embedded request's signature and tags).
	zr, err := parseAltZapReceipt(receipt, relay)
	if err != nil {
		return nil, err
	}
	invoice, err := nip57.DecodeBolt11(zr.Bolt11)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", nip57.ErrBolt11DecodeFailed, err)
	}
	// 3. Hash lock: the preimage must be the one that paid this invoice.
	preimage, err := hex.DecodeString(zr.Preimage)
	if err != nil {
		return nil, fmt.Errorf("%w: preimage is not hex", ErrHashLockMismatch)
	}
	if sum := sha256.Sum256(preimage); !strings.EqualFold(hex.EncodeToString(sum[:]), invoice.PaymentHash) {
		return nil, ErrHashLockMismatch
	}
	// 4. The invoice is on the receipt's chain; an unknown chain proves nothing.
	prefixes, known := InvoiceCurrencies[zr.Chain]
	if !known {
		return nil, fmt.Errorf("%w: %q", ErrUnknownChain, zr.Chain)
	}
	if !slices.Contains(prefixes, invoice.Currency) {
		return nil, fmt.Errorf("%w: chain %q, invoice currency %q", ErrChainMismatch, zr.Chain, invoice.Currency)
	}

	if req := zr.Request; req != nil {
		// 5. The invoice binds the description exactly as stored.
		if invoice.DescriptionHash == "" {
			return nil, fmt.Errorf("%w: %w", nip57.ErrDescriptionHashMismatch, nip57.ErrMissingDescriptionHash)
		}
		if descHash := DescriptionHash(zr.Description); invoice.DescriptionHash != descHash {
			return nil, fmt.Errorf("%w: have=%s want=%s", nip57.ErrDescriptionHashMismatch, descHash, invoice.DescriptionHash)
		}
		// 6. p, chain, ia and P are the request's.
		if !sameIdentity(zr.Recipient, req.Recipient) {
			return nil, fmt.Errorf("%w: receipt p differs from the request's", nip57.ErrRecipientMismatch)
		}
		if zr.Chain != req.Chain {
			return nil, fmt.Errorf("%w: receipt %q, request %q", ErrChainMismatch, zr.Chain, req.Chain)
		}
		if zr.IA != req.IA {
			return nil, ErrIAMismatch
		}
		switch req.Kind {
		case KindAltZapOnBehalfRequest:
			if !sameIdentity(zr.Sender, req.Sender) {
				return nil, ErrSenderMismatch
			}
		default:
			if !zr.Sender.IsZero() && !sameIdentity(zr.Sender, Pubkey(req.PubKey)) {
				return nil, ErrSenderMismatch
			}
		}
		// 7. The invoice settles the requested amount.
		if invoice.AmountMloki != req.Amount {
			return nil, fmt.Errorf("%w: invoice=%d request=%d", nip57.ErrAmountMismatch, invoice.AmountMloki, req.Amount)
		}
	} else if invoice.AmountMloki <= 0 {
		// 8. A plain payment settled without a request is still positive.
		return nil, ErrInvalidInvoiceAmount
	}
	// 9. An amount tag states the invoice amount.
	if zr.Amount != 0 && zr.Amount != invoice.AmountMloki {
		return nil, fmt.Errorf("%w: amount tag %d, invoice %d", nip57.ErrAmountMismatch, zr.Amount, invoice.AmountMloki)
	}
	// 10. Signed by the nostrPubkey of the endpoint the request named.
	if policy != nil && zr.Request != nil {
		if policy.NostrPubkeyFor == nil {
			return nil, ErrNostrPubkeyUnknown
		}
		want, err := policy.NostrPubkeyFor(zr.Request.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNostrPubkeyUnknown, err)
		}
		if want != receipt.PubKey {
			return nil, ErrReceiptSigner
		}
	}
	return zr, nil
}

// AltZapRequestParams describes an AltZap request (kind 9520, or 9523 when
// built via NewAltZapOnBehalfRequest). PrivateKey, Chain, Recipient, Lnurl,
// AmountMloki, and Relays are required; IA is required when Recipient is a
// ConnectionKey on a platform without a canonical form, and refused beside a
// pubkey; the rest are optional. The event is signed with PrivateKey
// internally — the caller never calls .Sign() themselves.
type AltZapRequestParams struct {
	PrivateKey  string   // sender's (or proxy agent's, for on-behalf) private key hex
	Chain       Chain    // e.g. "examplecoin" — prevents cross-chain replay
	Recipient   Identity // recipient ("p" tag) — required
	IA          string   // "ia" tag: the IA whose attestation or nconnection the recipient's key came from
	Lnurl       string   // recipient's LNURL-pay endpoint, bech32 "lnurl1..."
	AmountMloki int64    // amount in the chain's milli-units
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

// newAltZapRequest builds a request of the given kind, checks it against the
// same tag rules a receiver applies (ParseAltZapRequest), and only then signs
// it, so the signature always covers the final kind.
func newAltZapRequest(kind int, p AltZapRequestParams) (*nip01.Event, error) {
	if err := p.Recipient.checkPlatform("p"); err != nil {
		return nil, err
	}
	if err := p.Sender.checkPlatform("P"); err != nil {
		return nil, err
	}
	tags := [][]string{
		p.Recipient.toSlice("p", false),
		{"amount", strconv.FormatInt(p.AmountMloki, 10)},
		{"lnurl", p.Lnurl},
		{"chain", string(p.Chain)},
	}
	if p.IA != "" {
		tags = append(tags, []string{"ia", p.IA})
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
	if _, err := parseAltZapRequest(event, false); err != nil {
		return nil, fmt.Errorf("nipAZ: build request: %w", err)
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
// LNURL server once the invoice is paid. PrivateKey, Chain, Bolt11 and
// Preimage are required; Recipient is the zero Identity for a plain LNURL
// payment settled without a signed request. IA is the request's ia tag,
// copied unchanged ("" when it had none).
//
// ResolvedRecipientPubkey/ResolvedSenderPubkey ("r"/"R") publicly link a
// ConnectionKey to a Nostr pubkey. Set them only from ResolveIdentity's result
// and only with LinkAuthorized: the user authorized publishing that link. An
// indexed 35521 for the key is not that authorization; without it the receipt
// goes out without r/R. Coordinate/EventID mirror the request's "a"/"e".
//
// Recipient/Sender (including any handle attached via Identity.WithHandle)
// are always authoritative — never re-derived or overridden from Description;
// NewAltZapReceipt refuses a receipt whose p, P, chain or ia differ from the
// embedded request's. Description is stored verbatim.
type AltZapReceiptParams struct {
	PrivateKey              string // LNURL server's private key hex — required, derives the event pubkey and signs
	Chain                   Chain
	Recipient               Identity
	Sender                  Identity
	IA                      string // "ia" tag, copied from the request
	Bolt11                  string
	Description             string // the embedded AltZap request exactly as received, if any
	Preimage                *string
	ResolvedRecipientPubkey string // optional "r" tag; needs LinkAuthorized
	ResolvedSenderPubkey    string // optional "R" tag; needs LinkAuthorized
	LinkAuthorized          bool   // the user authorized publishing the ConnectionKey-to-pubkey link
	Coordinate              string // optional "a" tag
	EventID                 string // optional "e" tag
}

// NewAltZapReceipt creates, signs, and returns a new AltZap receipt event
// (kind 9521). It refuses r/R without LinkAuthorized (ErrLinkNotAuthorized)
// and a receipt failing receipt rules 2 to 9; nothing is signed then. Rule 10
// holds by construction when PrivateKey is the endpoint's nostrPubkey key.
func NewAltZapReceipt(p AltZapReceiptParams) (*nip01.Event, error) {
	if (p.ResolvedRecipientPubkey != "" || p.ResolvedSenderPubkey != "") && !p.LinkAuthorized {
		return nil, ErrLinkNotAuthorized
	}
	if err := p.Recipient.checkPlatform("p"); err != nil {
		return nil, err
	}
	if err := p.Sender.checkPlatform("P"); err != nil {
		return nil, err
	}
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
	if inv.AmountMloki > 0 {
		tags = append(tags, []string{"amount", strconv.FormatInt(inv.AmountMloki, 10)})
	}
	if !p.Sender.IsZero() {
		tags = append(tags, p.Sender.toSlice("P", true))
	}
	if p.IA != "" {
		tags = append(tags, []string{"ia", p.IA})
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
	if _, err := validateAltZapReceipt(event, false, nil, false); err != nil {
		return nil, fmt.Errorf("nipAZ: build receipt: %w", err)
	}
	if err := event.Sign(p.PrivateKey); err != nil {
		return nil, fmt.Errorf("nipAZ: sign receipt: %w", err)
	}
	return event, nil
}
