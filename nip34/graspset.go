package nip34

import (
	"fmt"

	"github.com/ohstr/nmilat/nip01"
)

// GraspServerList is a parsed kind:10317 user grasp-server list event: the
// grasp (git-relay) servers a user prefers for NIP-34-related activity, in
// order of preference. It's the git-hosting analogue of a NIP-65 relay
// list or NIP-B7 Blossom server list.
type GraspServerList struct {
	*nip01.Event
	Servers []string // "g" tag values, in preference order; may be empty
}

// ParseGraspServerList parses and structurally validates a kind:10317
// event.
func ParseGraspServerList(event *nip01.Event) (*GraspServerList, error) {
	if event.Kind != KindGraspServerList {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindGraspServerList)
	}

	gl := &GraspServerList{Event: event}
	for _, tag := range event.Tags {
		if len(tag) > 1 && tag[0] == "g" {
			gl.Servers = append(gl.Servers, tag[1])
		}
	}
	return gl, nil
}

// ValidateGraspServerList checks the signature and structure of a grasp
// server list event.
func ValidateGraspServerList(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseGraspServerList(event)
	return err
}

// NewGraspServerList builds an unsigned kind:10317 event. servers may be
// empty or nil, per the spec's "zero or more grasp server urls". Caller
// must sign it.
func NewGraspServerList(pubkey string, servers []string) *nip01.Event {
	var tags [][]string
	for _, s := range servers {
		tags = append(tags, []string{"g", s})
	}
	return nip01.NewUnsignedEvent(KindGraspServerList, pubkey, "", tags...)
}
