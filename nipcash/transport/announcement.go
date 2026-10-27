package transport

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
)

// KindHubAnnouncement is where a hub publishes its private-transport inbox key.
//
// Replaceable (10000-19999) rather than ephemeral, because a client must be able
// to fetch the current one at any time — unlike the transport kinds themselves,
// which are ephemeral precisely so no ciphertext archive accumulates. Addressed by
// author, so {kinds:[11190], authors:[node_xonly]} returns exactly one event and no
// "d" tag is needed. Numbered to mirror the 23190 transport block.
const KindHubAnnouncement = 11190

var (
	ErrAnnouncementMalformed = errors.New("transport: hub announcement is malformed")
	ErrAnnouncementAuthor    = errors.New("transport: hub announcement was not signed by the expected node identity")
	ErrAnnouncementSignature = errors.New("transport: hub announcement signature is invalid")
	// ErrHubUnusable is a Hub a client sends no bill-creating call to: its
	// announcement carries no max_request_age of at least 60 seconds, or its newest
	// announcement was rejected.
	ErrHubUnusable = errors.New("transport: the hub is unusable for calls carrying a request_id")
	// ErrHubNonConforming is an announced policy no conforming Hub announces, such
	// as a max_consolidate_sources whose largest item cannot fit max_bytes.
	ErrHubNonConforming = errors.New("transport: the hub's announced limits do not conform")
	// ErrBadAddr is an addr a Hub was asked to announce that is not host:port with
	// an IPv4, bracketed IPv6 or onion host.
	ErrBadAddr = errors.New("transport: addr must be host:port with an IPv4, bracketed IPv6 or onion host")
)

// Tag names and limit names of the kind-11190 announcement (NIP-CASH §The Hub
// Announcement).
const (
	annTagInbox = "inbox"
	annTagLimit = "limit"
	annTagRelay = "r"
	annTagAddr  = "addr"

	LimitMaxBytes              = "max_bytes"
	LimitMaxItems              = "max_items"
	LimitMaxConsolidateSources = "max_consolidate_sources"
	LimitPadBucketBytes        = "pad_bucket_bytes"
	LimitMaxVerifyBudget       = "max_verify_budget"
	LimitMaxRequestAge         = "max_request_age"
)

// MinMaxRequestAge is the smallest horizon H a Hub may announce, in seconds.
const MinMaxRequestAge = 60

// Announcement is what a hub publishes so clients can reach its private
// transport: its inbox, its envelope limits, the relays it reads its inbox on
// and, optionally, where its Lightning node listens. On the wire every field is
// a tag and content is empty; the kind is the version.
type Announcement struct {
	// Inbox is the x-only pubkey clients NIP-44 encrypt envelopes to and p-tag.
	// A client uses whatever it says; it may equal the announcing identity.
	Inbox  string
	Limits AnnouncedLimits
	// Relays are the r tags, in the Hub's order.
	Relays []string
	// Addrs are the well-formed addr tags, display and connect hints only; a
	// malformed one is dropped, never fatal.
	Addrs []string
	// CreatedAt is the announcing event's created_at. Every announcement the hub
	// ever published stays validly signed, so a client orders candidates by it and
	// never moves backwards.
	CreatedAt int64
}

// AnnouncedLimits are the limit tags.
type AnnouncedLimits struct {
	MaxBytes              int
	MaxItems              int
	MaxConsolidateSources int
	PadBucketBytes        int
	MaxVerifyBudget       int
	// MaxRequestAge is H, in seconds; 0 when the Hub announced none.
	MaxRequestAge int64
}

// Limits converts the announced values into the type the codec enforces.
func (a AnnouncedLimits) Limits() Limits {
	return Limits{
		MaxEnvelopeBytes:      a.MaxBytes,
		MaxItems:              a.MaxItems,
		MaxConsolidateSources: a.MaxConsolidateSources,
		PadBucketBytes:        a.PadBucketBytes,
		MaxVerifyBudget:       a.MaxVerifyBudget,
		MaxRequestAgeSeconds:  a.MaxRequestAge,
	}
}

// ValidateForBillCalls is the client's check before a call carrying a
// request_id: the Hub must announce max_request_age of at least 60 seconds, or
// it is ErrHubUnusable.
func (a Announcement) ValidateForBillCalls() error {
	if a.Limits.MaxRequestAge < MinMaxRequestAge {
		return fmt.Errorf("%w: max_request_age %d, want at least %d", ErrHubUnusable, a.Limits.MaxRequestAge, MinMaxRequestAge)
	}
	return nil
}

func limitTags(l Limits) [][]string {
	n := func(v int64) string { return strconv.FormatInt(v, 10) }
	return [][]string{
		{annTagLimit, LimitMaxBytes, n(int64(l.MaxEnvelopeBytes))},
		{annTagLimit, LimitMaxItems, n(int64(l.MaxItems))},
		{annTagLimit, LimitMaxConsolidateSources, n(int64(l.MaxConsolidateSources))},
		{annTagLimit, LimitPadBucketBytes, n(int64(l.PadBucketBytes))},
		{annTagLimit, LimitMaxVerifyBudget, n(int64(l.MaxVerifyBudget))},
		{annTagLimit, LimitMaxRequestAge, n(l.MaxRequestAgeSeconds)},
	}
}

// NewAnnouncement builds an UNSIGNED kind-11190 announcement with its ID
// computed, ready for the caller to have the node sign that ID: content "", one
// inbox tag, one limit tag per limit, the r relays in order, then each addr.
//
// It refuses a policy ValidateAnnounced refuses (so a max_request_age below 60
// and a max_bytes above 65535), a relay that is not a ws:// or wss:// URL, an
// addr that is not host:port (ErrBadAddr), and the node identity as inbox. It
// parses its own event before returning it, so a Hub never publishes an
// announcement a client would reject.
//
// It returns an unsigned event on purpose: the node identity signs, and the node
// never releases that key, so the Hub asks the node for a BIP340 signature over
// ev.ID and attaches it.
func NewAnnouncement(nodeXOnly, inbox string, limits Limits, relays []string, addrs ...string) (*nip01.Event, error) {
	if len(nodeXOnly) != keyHexLen || !isLowerHex(nodeXOnly) {
		return nil, fmt.Errorf("%w: node pubkey must be %d lowercase hex characters",
			ErrAnnouncementMalformed, keyHexLen)
	}
	if !validInbox(inbox) {
		return nil, fmt.Errorf("%w: inbox must be a 64 lowercase hex x-only pubkey", ErrAnnouncementMalformed)
	}
	if err := limits.ValidateAnnounced(); err != nil {
		return nil, fmt.Errorf("refusing to announce an invalid envelope policy: %w", err)
	}
	// Announcing the node's own key as its inbox would mean the hub cannot decrypt
	// what clients send it — the node will not perform the ECDH.
	if inbox == nodeXOnly {
		return nil, fmt.Errorf("%w: inbox must not be the node identity key", ErrAnnouncementMalformed)
	}
	tags := [][]string{{annTagInbox, inbox}}
	tags = append(tags, limitTags(limits)...)
	for _, r := range relays {
		if !validRelayURL(r) {
			return nil, fmt.Errorf("%w: relay %q is not a ws:// or wss:// URL", ErrAnnouncementMalformed, r)
		}
		tags = append(tags, []string{annTagRelay, r})
	}
	for _, a := range addrs {
		if !ValidAddr(a) {
			return nil, fmt.Errorf("%w: %q", ErrBadAddr, a)
		}
		tags = append(tags, []string{annTagAddr, a})
	}

	ev := nip01.NewUnsignedEvent(KindHubAnnouncement, nodeXOnly, "")
	ev.Tags = tags
	id, err := ev.HashID()
	if err != nil {
		return nil, fmt.Errorf("transport: compute announcement id: %w", err)
	}
	ev.ID = hex.EncodeToString(id)
	if _, err := announcementFromTags(ev); err != nil {
		return nil, fmt.Errorf("transport: built an announcement a client would reject: %w", err)
	}
	return ev, nil
}

// AnnouncementDigest returns the 32 bytes that actually get signed: the event's
// own ID. Use this with a signer you hand a private key to.
//
// Do NOT send this to a signer that hashes its input for you — see
// AnnouncementSigningPayload.
func AnnouncementDigest(ev *nip01.Event) ([]byte, error) {
	id, err := hex.DecodeString(ev.ID)
	if err != nil || len(id) != 32 {
		return nil, fmt.Errorf("%w: event id is not 32 bytes of hex", ErrAnnouncementMalformed)
	}
	return id, nil
}

// AnnouncementSigningPayload returns what to hand a signer that hashes its own
// input — which is the case for an LN node's signrpc.
//
// This distinction is easy to get wrong and fails silently when you do. flnd's
// SignMessageSchnorr computes sha256(msg) and signs THAT, so passing the event ID
// would have it sign sha256(id) — a perfectly valid signature over the wrong
// digest, which then fails verification with nothing pointing at the cause. Pass
// the serialization and the node arrives at the ID on its own.
//
// sha256(AnnouncementSigningPayload(ev)) == AnnouncementDigest(ev), always.
func AnnouncementSigningPayload(ev *nip01.Event) ([]byte, error) {
	if ev == nil {
		return nil, fmt.Errorf("%w: no event", ErrAnnouncementMalformed)
	}
	payload, err := ev.Serialize()
	if err != nil {
		return nil, fmt.Errorf("transport: serialize announcement: %w", err)
	}
	return payload, nil
}

// ParseAnnouncement verifies an announcement and returns what it declares.
//
// expectedNodeXOnly is REQUIRED and is the security property. A client recovers the
// node identity from its bill's mint signature and passes it here; without that
// check, anyone could publish "that hub's inbox is my key" and read every envelope
// sent to it. The chain is bill -> node key -> announcement -> inbox key, and this
// function is the link that refuses to be skipped.
func ParseAnnouncement(ev *nip01.Event, expectedNodeXOnly string) (*Announcement, error) {
	if ev == nil {
		return nil, fmt.Errorf("%w: no event", ErrAnnouncementMalformed)
	}
	if ev.Kind != KindHubAnnouncement {
		return nil, fmt.Errorf("%w: kind %d, want %d", ErrAnnouncementMalformed, ev.Kind, KindHubAnnouncement)
	}
	if len(expectedNodeXOnly) != keyHexLen || !isLowerHex(expectedNodeXOnly) {
		return nil, fmt.Errorf("%w: expected node pubkey must be %d lowercase hex characters",
			ErrAnnouncementMalformed, keyHexLen)
	}
	if ev.PubKey != expectedNodeXOnly {
		return nil, fmt.Errorf("%w: signed by %q", ErrAnnouncementAuthor, ev.PubKey)
	}
	// Only now, with the author confirmed, is the signature worth the secp256k1
	// time — and it is what makes the author claim mean anything.
	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAnnouncementSignature, err)
	}

	a, err := announcementFromTags(ev)
	if err != nil {
		return nil, err
	}
	a.CreatedAt = int64(ev.CreatedAt) //nolint:gosec // event timestamps are seconds
	return a, nil
}

// announcementFromTags reads an announcement's tags: exactly one inbox, at most
// one limit of each name, well-formed inbox, limit and r values; unknown tags,
// unknown limit names and malformed addrs are ignored. The announced envelope
// policy must be one a client can adopt.
func announcementFromTags(ev *nip01.Event) (*Announcement, error) {
	a := &Announcement{}
	inboxes := 0
	seenLimit := map[string]bool{}
	for _, tag := range ev.Tags {
		if len(tag) == 0 {
			continue
		}
		switch tag[0] {
		case annTagInbox:
			inboxes++
			if len(tag) < 2 || !validInbox(tag[1]) {
				return nil, fmt.Errorf("%w: malformed inbox", ErrAnnouncementMalformed)
			}
			a.Inbox = tag[1]
		case annTagLimit:
			if len(tag) < 3 {
				return nil, fmt.Errorf("%w: malformed limit tag", ErrAnnouncementMalformed)
			}
			name := tag[1]
			if seenLimit[name] {
				return nil, fmt.Errorf("%w: two %q limits", ErrAnnouncementMalformed, name)
			}
			seenLimit[name] = true
			v, ok := parseDecimal(tag[2])
			if !ok {
				return nil, fmt.Errorf("%w: limit %q value %q is not unsigned decimal", ErrAnnouncementMalformed, name, tag[2])
			}
			switch name {
			case LimitMaxBytes:
				a.Limits.MaxBytes = clampInt(v)
			case LimitMaxItems:
				a.Limits.MaxItems = clampInt(v)
			case LimitMaxConsolidateSources:
				a.Limits.MaxConsolidateSources = clampInt(v)
			case LimitPadBucketBytes:
				a.Limits.PadBucketBytes = clampInt(v)
			case LimitMaxVerifyBudget:
				a.Limits.MaxVerifyBudget = clampInt(v)
			case LimitMaxRequestAge:
				a.Limits.MaxRequestAge = int64(min(v, 1<<31)) //nolint:gosec // bounded
			}
		case annTagRelay:
			if len(tag) < 2 || !validRelayURL(tag[1]) {
				return nil, fmt.Errorf("%w: malformed r tag", ErrAnnouncementMalformed)
			}
			a.Relays = append(a.Relays, tag[1])
		case annTagAddr:
			if len(tag) >= 2 && ValidAddr(tag[1]) {
				a.Addrs = append(a.Addrs, tag[1])
			}
		}
	}
	if inboxes != 1 {
		return nil, fmt.Errorf("%w: %d inbox tags, want exactly 1", ErrAnnouncementMalformed, inboxes)
	}
	// A hostile or misconfigured hub must not be able to talk a client into
	// building something unencryptable, so the announced policy is validated
	// rather than adopted. max_request_age is checked apart, by
	// ValidateForBillCalls, since a Hub without one still answers reads.
	if err := a.EffectiveLimits().validateAdoptable(); err != nil {
		if errors.Is(err, ErrConsolidateCapTooHigh) {
			return nil, fmt.Errorf("%w: %w: %v", ErrAnnouncementMalformed, ErrHubNonConforming, err)
		}
		return nil, fmt.Errorf("%w: announced limits are unusable: %v", ErrAnnouncementMalformed, err)
	}
	return a, nil
}

// EffectiveLimits are the limits a client sizes envelopes against: the announced
// ones, max_bytes clamped to NIP-44's 65535 (a larger announced value is never a
// reason to reject the announcement).
func (a Announcement) EffectiveLimits() Limits {
	l := a.Limits.Limits()
	l.MaxEnvelopeBytes = min(l.MaxEnvelopeBytes, MaxNIP44Plaintext)
	return l
}

// parseDecimal reads unsigned decimal with no leading zeros.
func parseDecimal(s string) (uint64, bool) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, false
	}
	return v, true
}

func clampInt(v uint64) int { return int(min(v, 1<<31)) } //nolint:gosec // bounded

func validInbox(s string) bool {
	if len(s) != keyHexLen || !isLowerHex(s) {
		return false
	}
	_, err := schnorr.ParsePubKey(mustHex(s))
	return err == nil
}

func validRelayURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "ws" || u.Scheme == "wss") && u.Host != ""
}

// ValidAddr reports host:port with an IPv4 address, a bracketed IPv6 address or
// an onion address as the host, and a port from 1 to 65535.
func ValidAddr(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 || strconv.FormatUint(p, 10) != port {
		return false
	}
	if strings.HasSuffix(host, ".onion") {
		label := strings.TrimSuffix(host, ".onion")
		if len(label) != 56 && len(label) != 16 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
				return false
			}
		}
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return !strings.HasPrefix(s, "[")
	}
	return strings.HasPrefix(s, "[")
}

// mustHex decodes hex already known to be well formed by a length and charset check.
func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
