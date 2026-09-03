package nipIC

import (
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

// AttestationRef is the "e" tag on a Kind 35521 event: a reference to (not
// an embed of) the witnessing Kind 35522, so the 35521 event stays small.
// A client fetches the attestation from RelayURL on demand (a "Deep Check")
// rather than trusting the reference blindly.
type AttestationRef struct {
	EventID  string
	RelayURL string
}

// IdentityConnection is a parsed and validated Kind 35521 event. On its own
// it is an unverified claim — see NIP-IC.md's Verification Model: a client
// must fetch and check at least one of Attestations before trusting it.
type IdentityConnection struct {
	*nip01.Event
	ConnectionKey ConnectionKey
	Platform      WebIdentity
	Attestations  []AttestationRef // may be empty, may have multiple (multi-IA stacking)
}

// ParseIdentityConnection parses and validates a Kind 35521 event: correct
// kind, valid signature, #d present and not platform-prefixed.
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

	var dValue, platformValue string
	var refs []AttestationRef
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case TagDTag:
			dValue = tag[1]
		case TagPlatform:
			platformValue = tag[1]
		case TagEventRef:
			ref := AttestationRef{EventID: tag[1]}
			if len(tag) >= 3 {
				ref.RelayURL = tag[2]
			}
			refs = append(refs, ref)
		}
	}

	if dValue == "" {
		return nil, fmt.Errorf("%w: #d tag is required for Kind 35521", ErrMissingTag)
	}
	if strings.Contains(dValue, ":") {
		return nil, fmt.Errorf("%w: %q", ErrPlatformPrefixed, dValue)
	}

	return &IdentityConnection{
		Event:         event,
		ConnectionKey: ConnectionKey(dValue),
		Platform:      WebIdentity(platformValue),
		Attestations:  refs,
	}, nil
}

// ValidateIdentityConnection is a convenience wrapper for callers that only
// need a pass/fail check and don't need the parsed IdentityConnection itself.
func ValidateIdentityConnection(event *nip01.Event) error {
	_, err := ParseIdentityConnection(event)
	return err
}
