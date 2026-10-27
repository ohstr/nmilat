package nipIC

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// AttestationRef is the "e" tag on a Kind 35521 event: a reference to (not
// an embed of) the witnessing Kind 35522. A client fetches the attestation
// from RelayURL on demand (a Deep Check) rather than trusting the reference.
type AttestationRef struct {
	EventID  string
	RelayURL string
}

// IdentityConnection is a parsed and validated Kind 35521 event. On its own it
// is an unverified claim: see Evaluate.
type IdentityConnection struct {
	*nip01.Event
	ConnectionKey ConnectionKey
	Platform      WebIdentity
	Attestations  []AttestationRef // one or more (multi-IA stacking)
}

// ParseIdentityConnection parses and validates a Kind 35521 event: kind,
// signature, d once as a bare ConnectionKey (64 lowercase hex), platform once as
// a valid name, and at least one e reference.
func ParseIdentityConnection(event *nip01.Event) (*IdentityConnection, error) {
	if event == nil {
		return nil, fmt.Errorf("%w: event is nil", ErrInvalidTag)
	}
	if event.Kind != KindIdentityConnection {
		return nil, fmt.Errorf("%w: expected kind %d, got %d", ErrWrongKind, KindIdentityConnection, event.Kind)
	}
	if err := event.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	tags, err := singleTags(event, TagDTag, TagPlatform)
	if err != nil {
		return nil, err
	}
	d, platform := tags[TagDTag], WebIdentity(tags[TagPlatform])
	if d == "" {
		return nil, fmt.Errorf("%w: #d tag is required for Kind 35521", ErrMissingTag)
	}
	if strings.Contains(d, ":") {
		return nil, fmt.Errorf("%w: %q", ErrPlatformPrefixed, d)
	}
	if !isLowerHex64(d) {
		return nil, fmt.Errorf("%w: d is not a ConnectionKey", ErrInvalidTag)
	}
	if platform == "" {
		return nil, fmt.Errorf("%w: platform tag is required for Kind 35521", ErrMissingTag)
	}
	if !ValidPlatformName(platform) {
		return nil, ErrPlatformName
	}
	var refs []AttestationRef
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != TagEventRef {
			continue
		}
		ref := AttestationRef{EventID: tag[1]}
		if len(tag) >= 3 {
			ref.RelayURL = tag[2]
		}
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("%w: a 35521 references at least one attestation (e)", ErrMissingTag)
	}
	return &IdentityConnection{Event: event, ConnectionKey: ConnectionKey(d), Platform: platform, Attestations: refs}, nil
}

// ValidateIdentityConnection is a convenience wrapper for callers that only
// need a pass/fail check and don't need the parsed IdentityConnection itself.
func ValidateIdentityConnection(event *nip01.Event) error {
	_, err := ParseIdentityConnection(event)
	return err
}

// AttestationLink is one attestation a 35521 references, with the IA relay it is
// fetched from.
type AttestationLink struct {
	Attestation *Attestation
	Relay       string
}

// Profile is display metadata a user adds to a 35521's content. user_id and
// username are copied from the attestation's evidence, never taken from here.
type Profile struct{ DisplayName, Picture string }

// profileContent is the 35521 content JSON.
type profileContent struct {
	DisplayName string `json:"display_name,omitempty"`
	Picture     string `json:"picture,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Username    string `json:"username,omitempty"`
}

// NewIdentityConnection builds and signs the user's Kind 35521 linking their
// pubkey to one or more attestations by reference (NIP-IC §Event Lifecycle,
// Linking). Every link must name the user in p and share one d and platform,
// and every relay must be a ws:// or wss:// URL; one e tag per link, in order.
// The attestation itself is never embedded.
func NewIdentityConnection(userPrivHex string, links []AttestationLink, profile Profile) (*nip01.Event, error) {
	if len(links) == 0 {
		return nil, fmt.Errorf("%w: no attestation to link", ErrMissingTag)
	}
	user, err := utils.GetPublicKey(userPrivHex)
	if err != nil {
		return nil, fmt.Errorf("nipIC: user key: %w", err)
	}
	first := links[0].Attestation
	tags := [][]string{}
	for _, l := range links {
		a := l.Attestation
		if a == nil || a.Event == nil {
			return nil, fmt.Errorf("%w: a link has no attestation", ErrInvalidTag)
		}
		if _, err := ParseAttestation(a.Event); err != nil {
			return nil, err
		}
		if a.ConnectionKey != first.ConnectionKey || a.Platform != first.Platform {
			return nil, fmt.Errorf("%w: links name different accounts", ErrInvalidTag)
		}
		if a.UserPubkey != user {
			return nil, fmt.Errorf("%w: an attestation names another pubkey", ErrInvalidTag)
		}
		u, err := url.Parse(l.Relay)
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
			return nil, fmt.Errorf("%w: relay %q is not a ws:// or wss:// URL", ErrInvalidTag, l.Relay)
		}
		tags = append(tags, []string{TagEventRef, a.ID, l.Relay})
	}
	content, err := json.Marshal(profileContent{DisplayName: profile.DisplayName, Picture: profile.Picture,
		UserID: first.Evidence.UserID, Username: first.Evidence.Username})
	if err != nil {
		return nil, err
	}
	tags = append([][]string{{TagDTag, string(first.ConnectionKey)}}, tags...)
	tags = append(tags, []string{TagPlatform, string(first.Platform)})
	ev := &nip01.Event{Kind: KindIdentityConnection, CreatedAt: uint64(time.Now().Unix()), Tags: tags, Content: string(content)} //nolint:gosec // a unix time is positive
	if err := ev.Sign(userPrivHex); err != nil {
		return nil, fmt.Errorf("nipIC: sign identity connection: %w", err)
	}
	return ev, nil
}
