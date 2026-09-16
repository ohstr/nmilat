package nip34

import (
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Issue is a parsed kind:1621 issue event. Content holds markdown text: a
// bug report, feature request, question, or comment of any kind related to
// the repository.
type Issue struct {
	*nip01.Event
	RepoAddress     string   // "a" tag; SHOULD be set, not required
	RepositoryOwner string   // "p" tag
	Subject         string   // "subject" tag, for a header
	Labels          []string // "t" tags
}

// ParseIssue parses and structurally validates a kind:1621 event.
func ParseIssue(event *nip01.Event) (*Issue, error) {
	if event.Kind != KindIssue {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindIssue)
	}

	iss := &Issue{Event: event}
	for _, tag := range event.Tags {
		if len(tag) < 1 {
			continue
		}
		switch tag[0] {
		case "a":
			if len(tag) < 2 {
				continue
			}
			if _, _, _, err := utils.ParseATag(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidRepoAddress, tag[1], err)
			}
			iss.RepoAddress = tag[1]
		case "p":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, tag[1], err)
			}
			iss.RepositoryOwner = tag[1]
		case "subject":
			if len(tag) > 1 {
				iss.Subject = tag[1]
			}
		case "t":
			if len(tag) > 1 {
				iss.Labels = append(iss.Labels, tag[1])
			}
		}
	}

	return iss, nil
}

// ValidateIssue checks the signature and structure of an issue event.
func ValidateIssue(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseIssue(event)
	return err
}

// IssueParams describes an issue event to build. Pubkey and Content are
// required; everything else is optional.
type IssueParams struct {
	Pubkey          string
	Content         string
	RepoAddress     string
	RepositoryOwner string
	Subject         string
	Labels          []string
}

// NewIssue builds an unsigned kind:1621 event. Caller must sign it.
func NewIssue(p IssueParams) (*nip01.Event, error) {
	if p.RepoAddress != "" {
		if _, _, _, err := utils.ParseATag(p.RepoAddress); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidRepoAddress, p.RepoAddress, err)
		}
	}
	if p.RepositoryOwner != "" {
		if err := utils.Validate32Key(p.RepositoryOwner); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, p.RepositoryOwner, err)
		}
	}

	var tags [][]string
	if p.RepoAddress != "" {
		tags = append(tags, []string{"a", p.RepoAddress})
	}
	if p.RepositoryOwner != "" {
		tags = append(tags, []string{"p", p.RepositoryOwner})
	}
	if p.Subject != "" {
		tags = append(tags, []string{"subject", p.Subject})
	}
	for _, label := range p.Labels {
		tags = append(tags, []string{"t", label})
	}

	return nip01.NewUnsignedEvent(KindIssue, p.Pubkey, p.Content, tags...), nil
}
