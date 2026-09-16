package nip34

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Failure modes specific to RepositoryAnnouncement/RepositoryState, for
// callers that need to distinguish them (e.g. via errors.Is) rather than
// match on message text.
var (
	ErrInvalidRelayURL    = errors.New("nip34: invalid relay url")
	ErrInvalidRelayScheme = errors.New("nip34: relay url must use ws or wss scheme")
)

// UpstreamFork is the optional "u" tag on a RepositoryAnnouncement,
// indicating this repository is a subordinate fork.
type UpstreamFork struct {
	// Pointer is either a nip34 "a" tag address ("30617:<pubkey>:<id>") of
	// the upstream repository's own announcement, or a plain
	// (preferably https) git URL, per the spec's own alternation between
	// the two forms.
	Pointer      string
	RelayHint    string
	AuthorPubkey string
}

// RepositoryAnnouncement is a parsed kind:30617 repository announcement
// event, an addressable event (see nip33) keyed by Identifier.
type RepositoryAnnouncement struct {
	*nip01.Event
	Identifier  string // "d" tag; the only required tag per the spec
	Name        string
	Description string
	// Web is a list of webpage URLs for browsing the repository, if the
	// git server used provides one.
	Web []string
	// Clone is a list of URLs suitable for `git clone`.
	Clone []string
	// Relays is where patches/issues for this repository should be sent.
	Relays []string
	// EarliestUniqueCommit is the "r" tag marked "euc": the commit id of
	// the repo's earliest unique commit, used to group this repository
	// with other copies of essentially the same project hosted elsewhere.
	EarliestUniqueCommit string
	// Maintainers holds pubkeys of maintainers recognized in addition to
	// this event's author.
	Maintainers []string
	// Upstream is set when this repository is a subordinate fork.
	Upstream *UpstreamFork
	// Hashtags are "t" tags labelling the repository.
	Hashtags []string
}

// ParseRepositoryAnnouncement parses and structurally validates a
// kind:30617 event.
func ParseRepositoryAnnouncement(event *nip01.Event) (*RepositoryAnnouncement, error) {
	if event.Kind != KindRepositoryAnnouncement {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindRepositoryAnnouncement)
	}

	ra := &RepositoryAnnouncement{Event: event}
	for _, tag := range event.Tags {
		if len(tag) < 1 {
			continue
		}
		switch tag[0] {
		case "d":
			if len(tag) > 1 {
				ra.Identifier = tag[1]
			}
		case "name":
			if len(tag) > 1 {
				ra.Name = tag[1]
			}
		case "description":
			if len(tag) > 1 {
				ra.Description = tag[1]
			}
		case "web":
			ra.Web = append(ra.Web, tag[1:]...)
		case "clone":
			ra.Clone = append(ra.Clone, tag[1:]...)
		case "relays":
			for _, r := range tag[1:] {
				if err := validateRelayURL(r); err != nil {
					return nil, err
				}
				ra.Relays = append(ra.Relays, r)
			}
		case "r":
			if len(tag) > 2 && tag[2] == "euc" {
				ra.EarliestUniqueCommit = tag[1]
			}
		case "maintainers":
			for _, m := range tag[1:] {
				if err := utils.Validate32Key(m); err != nil {
					return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, m, err)
				}
				ra.Maintainers = append(ra.Maintainers, m)
			}
		case "u":
			if len(tag) < 2 {
				continue
			}
			uf := &UpstreamFork{Pointer: tag[1]}
			if len(tag) > 2 {
				uf.RelayHint = tag[2]
			}
			if len(tag) > 3 {
				uf.AuthorPubkey = tag[3]
			}
			ra.Upstream = uf
		case "t":
			if len(tag) > 1 {
				ra.Hashtags = append(ra.Hashtags, tag[1])
			}
		}
	}

	if ra.Identifier == "" {
		return nil, ErrMissingIdentifier
	}
	return ra, nil
}

// ValidateRepositoryAnnouncement checks the signature and structure of a
// repository announcement event.
func ValidateRepositoryAnnouncement(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseRepositoryAnnouncement(event)
	return err
}

// RepositoryAnnouncementParams describes a repository announcement to
// build. Pubkey and Identifier are required; everything else is optional.
type RepositoryAnnouncementParams struct {
	Pubkey               string
	Identifier           string
	Name                 string
	Description          string
	Web                  []string
	Clone                []string
	Relays               []string
	EarliestUniqueCommit string
	Maintainers          []string
	Upstream             *UpstreamFork
	Hashtags             []string
}

// NewRepositoryAnnouncement builds an unsigned kind:30617 event. Caller
// must sign it.
func NewRepositoryAnnouncement(p RepositoryAnnouncementParams) (*nip01.Event, error) {
	if p.Identifier == "" {
		return nil, ErrMissingIdentifier
	}
	for _, m := range p.Maintainers {
		if err := utils.Validate32Key(m); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, m, err)
		}
	}
	for _, r := range p.Relays {
		if err := validateRelayURL(r); err != nil {
			return nil, err
		}
	}

	tags := [][]string{{"d", p.Identifier}}
	if p.Name != "" {
		tags = append(tags, []string{"name", p.Name})
	}
	if p.Description != "" {
		tags = append(tags, []string{"description", p.Description})
	}
	if len(p.Web) > 0 {
		tags = append(tags, append([]string{"web"}, p.Web...))
	}
	if len(p.Clone) > 0 {
		tags = append(tags, append([]string{"clone"}, p.Clone...))
	}
	if len(p.Relays) > 0 {
		tags = append(tags, append([]string{"relays"}, p.Relays...))
	}
	if p.EarliestUniqueCommit != "" {
		tags = append(tags, []string{"r", p.EarliestUniqueCommit, "euc"})
	}
	if len(p.Maintainers) > 0 {
		tags = append(tags, append([]string{"maintainers"}, p.Maintainers...))
	}
	if p.Upstream != nil {
		u := []string{"u", p.Upstream.Pointer}
		if p.Upstream.RelayHint != "" || p.Upstream.AuthorPubkey != "" {
			u = append(u, p.Upstream.RelayHint)
		}
		if p.Upstream.AuthorPubkey != "" {
			u = append(u, p.Upstream.AuthorPubkey)
		}
		tags = append(tags, u)
	}
	for _, t := range p.Hashtags {
		tags = append(tags, []string{"t", t})
	}

	return nip01.NewUnsignedEvent(KindRepositoryAnnouncement, p.Pubkey, "", tags...), nil
}

func validateRelayURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("%w %q: %w", ErrInvalidRelayURL, raw, err)
	}
	if u.Scheme != "wss" && u.Scheme != "ws" {
		return fmt.Errorf("%w: %q has scheme %q", ErrInvalidRelayScheme, raw, u.Scheme)
	}
	return nil
}

// Ref is one "refs/<heads|tags>/<name>" entry in a RepositoryState.
type Ref struct {
	// Name is the full ref path, e.g. "refs/heads/main" or
	// "refs/tags/v1.0.0".
	Name     string
	CommitID string
}

// RepositoryState is a parsed kind:30618 repository state event, an
// addressable event (see nip33) keyed by Identifier. It's an optional
// source of truth for the state of branches and tags in a repository.
type RepositoryState struct {
	*nip01.Event
	Identifier string // "d" tag; matches the corresponding announcement's Identifier
	Refs       []Ref
	// Head is the target of the "HEAD" tag (e.g. "refs/heads/main"), with
	// its "ref: " prefix stripped. Empty if the event carries no HEAD tag.
	Head string
}

// ParseRepositoryState parses and structurally validates a kind:30618
// event.
func ParseRepositoryState(event *nip01.Event) (*RepositoryState, error) {
	if event.Kind != KindRepositoryState {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindRepositoryState)
	}

	rs := &RepositoryState{Event: event}
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch {
		case tag[0] == "d":
			rs.Identifier = tag[1]
		case tag[0] == "HEAD":
			rs.Head = strings.TrimPrefix(tag[1], "ref: ")
		case strings.HasPrefix(tag[0], "refs/"):
			rs.Refs = append(rs.Refs, Ref{Name: tag[0], CommitID: tag[1]})
		}
	}

	if rs.Identifier == "" {
		return nil, ErrMissingIdentifier
	}
	return rs, nil
}

// ValidateRepositoryState checks the signature and structure of a
// repository state event.
func ValidateRepositoryState(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseRepositoryState(event)
	return err
}

// RepositoryStateParams describes a repository state event to build.
// Pubkey and Identifier are required; Refs and Head are optional.
type RepositoryStateParams struct {
	Pubkey     string
	Identifier string
	Refs       []Ref
	// Head is the target ref (e.g. "refs/heads/main"), without a "ref: "
	// prefix -- NewRepositoryState adds it.
	Head string
}

// NewRepositoryState builds an unsigned kind:30618 event. Caller must sign
// it.
func NewRepositoryState(p RepositoryStateParams) (*nip01.Event, error) {
	if p.Identifier == "" {
		return nil, ErrMissingIdentifier
	}

	tags := [][]string{{"d", p.Identifier}}
	for _, ref := range p.Refs {
		tags = append(tags, []string{ref.Name, ref.CommitID})
	}
	if p.Head != "" {
		tags = append(tags, []string{"HEAD", "ref: " + p.Head})
	}

	return nip01.NewUnsignedEvent(KindRepositoryState, p.Pubkey, "", tags...), nil
}
