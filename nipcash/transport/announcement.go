package transport

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

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

// AnnouncementVersion is the only version this package emits.
const AnnouncementVersion = 1

var (
	ErrAnnouncementMalformed = errors.New("transport: hub announcement is malformed")
	ErrAnnouncementAuthor    = errors.New("transport: hub announcement was not signed by the expected node identity")
	ErrAnnouncementVersion   = errors.New("transport: unsupported hub announcement version")
	ErrAnnouncementSignature = errors.New("transport: hub announcement signature is invalid")
)

// Announcement is what a hub publishes so clients can reach its private transport.
//
// It carries the envelope limits as well as the inbox key, because a client that
// guesses the limits gets a rejection it could have predicted locally. This is the
// channel through which "ask the hub, do not assume" actually happens.
type Announcement struct {
	Version int `json:"v"`
	// Inbox is the x-only pubkey clients NIP-44 encrypt envelopes to and p-tag.
	// NOT the node identity: see keys.GetPrivateTransportKey for why the node key
	// can sign but cannot decrypt.
	Inbox  string          `json:"inbox"`
	Limits AnnouncedLimits `json:"limits"`
	Relays []string        `json:"relays,omitempty"`
}

// AnnouncedLimits is Limits on the wire. Spelled out separately so the JSON names
// are part of the protocol rather than an accident of Go field names.
type AnnouncedLimits struct {
	MaxBytes              int `json:"max_bytes"`
	MaxItems              int `json:"max_items"`
	MaxConsolidateSources int `json:"max_consolidate_sources"`
	PadBucketBytes        int `json:"pad_bucket_bytes"`
	MaxVerifyBudget       int `json:"max_verify_budget"`
}

// Limits converts the announced values into the type the codec enforces.
func (a AnnouncedLimits) Limits() Limits {
	return Limits{
		MaxEnvelopeBytes:      a.MaxBytes,
		MaxItems:              a.MaxItems,
		MaxConsolidateSources: a.MaxConsolidateSources,
		PadBucketBytes:        a.PadBucketBytes,
		MaxVerifyBudget:       a.MaxVerifyBudget,
	}
}

func announcedFrom(l Limits) AnnouncedLimits {
	return AnnouncedLimits{
		MaxBytes:              l.MaxEnvelopeBytes,
		MaxItems:              l.MaxItems,
		MaxConsolidateSources: l.MaxConsolidateSources,
		PadBucketBytes:        l.PadBucketBytes,
		MaxVerifyBudget:       l.MaxVerifyBudget,
	}
}

// NewAnnouncement builds an UNSIGNED announcement event with its ID computed, ready
// for the caller to have the node sign that ID.
//
// It returns an unsigned event on purpose. The announcement must be signed by the
// Lightning node identity, and the node never releases that private key — so the
// hub takes ev.ID, asks the node for a BIP340 signature over it, and attaches the
// result. That indirection is the whole reason this is split from signing: no
// in-process key can produce this signature.
//
// nodeXOnly is the node's identity pubkey in x-only form (its compressed form with
// the 02/03 prefix dropped), which is what a client recovers from a bill's mint
// signature.
func NewAnnouncement(nodeXOnly, inbox string, limits Limits, relays []string) (*nip01.Event, error) {
	if len(nodeXOnly) != keyHexLen || !isLowerHex(nodeXOnly) {
		return nil, fmt.Errorf("%w: node pubkey must be %d lowercase hex characters",
			ErrAnnouncementMalformed, keyHexLen)
	}
	if len(inbox) != keyHexLen || !isLowerHex(inbox) {
		return nil, fmt.Errorf("%w: inbox pubkey must be %d lowercase hex characters",
			ErrAnnouncementMalformed, keyHexLen)
	}
	if err := limits.Validate(); err != nil {
		return nil, fmt.Errorf("refusing to announce an invalid envelope policy: %w", err)
	}
	// Announcing the node's own key as its inbox would mean the hub cannot decrypt
	// what clients send it — the node will not perform the ECDH. Catch it here
	// rather than in production silence.
	if inbox == nodeXOnly {
		return nil, fmt.Errorf("%w: inbox must not be the node identity key", ErrAnnouncementMalformed)
	}

	content, err := json.Marshal(Announcement{
		Version: AnnouncementVersion,
		Inbox:   inbox,
		Limits:  announcedFrom(limits),
		Relays:  relays,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: marshal announcement: %w", err)
	}

	ev := nip01.NewUnsignedEvent(KindHubAnnouncement, nodeXOnly, string(content))
	id, err := ev.HashID()
	if err != nil {
		return nil, fmt.Errorf("transport: compute announcement id: %w", err)
	}
	ev.ID = hex.EncodeToString(id)
	return ev, nil
}

// AnnouncementDigest returns the 32 bytes the node must sign for ev.
func AnnouncementDigest(ev *nip01.Event) ([]byte, error) {
	id, err := hex.DecodeString(ev.ID)
	if err != nil || len(id) != 32 {
		return nil, fmt.Errorf("%w: event id is not 32 bytes of hex", ErrAnnouncementMalformed)
	}
	return id, nil
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

	var a Announcement
	if err := json.Unmarshal([]byte(ev.Content), &a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAnnouncementMalformed, err)
	}
	if a.Version != AnnouncementVersion {
		return nil, fmt.Errorf("%w: %d", ErrAnnouncementVersion, a.Version)
	}
	if len(a.Inbox) != keyHexLen || !isLowerHex(a.Inbox) {
		return nil, fmt.Errorf("%w: inbox pubkey must be %d lowercase hex characters",
			ErrAnnouncementMalformed, keyHexLen)
	}
	if _, err := schnorr.ParsePubKey(mustHex(a.Inbox)); err != nil {
		return nil, fmt.Errorf("%w: inbox is not a valid x-only pubkey: %v", ErrAnnouncementMalformed, err)
	}
	if a.Inbox == expectedNodeXOnly {
		return nil, fmt.Errorf("%w: inbox must not be the node identity key", ErrAnnouncementMalformed)
	}
	// A hostile or misconfigured hub must not be able to talk a client into
	// building something unencryptable, so the announced policy is validated
	// rather than adopted.
	if err := a.Limits.Limits().Validate(); err != nil {
		return nil, fmt.Errorf("%w: announced limits are unusable: %v", ErrAnnouncementMalformed, err)
	}
	return &a, nil
}

// mustHex decodes hex already known to be well formed by a length and charset check.
func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
