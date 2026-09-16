package nip34

import (
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// PullRequest is a parsed kind:1618 pull request event. Content holds
// markdown text describing the change.
type PullRequest struct {
	*nip01.Event
	RepoAddress          string   // "a" tag; SHOULD be set, not required
	EarliestUniqueCommit string   // "r" tag
	RepositoryOwner      string   // first "p" tag
	Recipients           []string // remaining "p" tags
	Subject              string   // "subject" tag
	Labels               []string // "t" tags
	Commit               string   // "c" tag: tip of the PR branch
	CloneURLs            []string // "clone" tag
	BranchName           string   // "branch-name" tag
	// RevisesPatch is the "e" tag's event id, set when this PR is a
	// revision of an existing patch (which should then be closed).
	RevisesPatch string
	MergeBase    string // "merge-base" tag
}

// ParsePullRequest parses and structurally validates a kind:1618 event.
func ParsePullRequest(event *nip01.Event) (*PullRequest, error) {
	if event.Kind != KindPullRequest {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindPullRequest)
	}

	pr := &PullRequest{Event: event}
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
			pr.RepoAddress = tag[1]
		case "r":
			if len(tag) > 1 {
				pr.EarliestUniqueCommit = tag[1]
			}
		case "p":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, tag[1], err)
			}
			if pr.RepositoryOwner == "" {
				pr.RepositoryOwner = tag[1]
			} else {
				pr.Recipients = append(pr.Recipients, tag[1])
			}
		case "subject":
			if len(tag) > 1 {
				pr.Subject = tag[1]
			}
		case "t":
			if len(tag) > 1 {
				pr.Labels = append(pr.Labels, tag[1])
			}
		case "c":
			if len(tag) > 1 {
				pr.Commit = tag[1]
			}
		case "clone":
			pr.CloneURLs = append(pr.CloneURLs, tag[1:]...)
		case "branch-name":
			if len(tag) > 1 {
				pr.BranchName = tag[1]
			}
		case "e":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, tag[1], err)
			}
			pr.RevisesPatch = tag[1]
		case "merge-base":
			if len(tag) > 1 {
				pr.MergeBase = tag[1]
			}
		}
	}

	return pr, nil
}

// ValidatePullRequest checks the signature and structure of a pull
// request event.
func ValidatePullRequest(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParsePullRequest(event)
	return err
}

// PullRequestParams describes a pull request event to build. Pubkey and
// Content are required; everything else is optional.
type PullRequestParams struct {
	Pubkey               string
	Content              string
	RepoAddress          string
	EarliestUniqueCommit string
	RepositoryOwner      string
	Recipients           []string
	Subject              string
	Labels               []string
	Commit               string
	CloneURLs            []string
	BranchName           string
	RevisesPatch         string
	MergeBase            string
}

// NewPullRequest builds an unsigned kind:1618 event. Caller must sign it.
func NewPullRequest(p PullRequestParams) (*nip01.Event, error) {
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
	for _, r := range p.Recipients {
		if err := utils.Validate32Key(r); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, r, err)
		}
	}
	if p.RevisesPatch != "" {
		if err := utils.Validate32Key(p.RevisesPatch); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, p.RevisesPatch, err)
		}
	}

	var tags [][]string
	if p.RepoAddress != "" {
		tags = append(tags, []string{"a", p.RepoAddress})
	}
	if p.EarliestUniqueCommit != "" {
		tags = append(tags, []string{"r", p.EarliestUniqueCommit})
	}
	if p.RepositoryOwner != "" {
		tags = append(tags, []string{"p", p.RepositoryOwner})
	}
	for _, r := range p.Recipients {
		tags = append(tags, []string{"p", r})
	}
	if p.Subject != "" {
		tags = append(tags, []string{"subject", p.Subject})
	}
	for _, label := range p.Labels {
		tags = append(tags, []string{"t", label})
	}
	if p.Commit != "" {
		tags = append(tags, []string{"c", p.Commit})
	}
	if len(p.CloneURLs) > 0 {
		tags = append(tags, append([]string{"clone"}, p.CloneURLs...))
	}
	if p.BranchName != "" {
		tags = append(tags, []string{"branch-name", p.BranchName})
	}
	if p.RevisesPatch != "" {
		tags = append(tags, []string{"e", p.RevisesPatch})
	}
	if p.MergeBase != "" {
		tags = append(tags, []string{"merge-base", p.MergeBase})
	}

	return nip01.NewUnsignedEvent(KindPullRequest, p.Pubkey, p.Content, tags...), nil
}

// PullRequestUpdate is a parsed kind:1619 pull request update event,
// changing the tip of a referenced PR.
type PullRequestUpdate struct {
	*nip01.Event
	RepoAddress          string
	EarliestUniqueCommit string
	RepositoryOwner      string
	Recipients           []string
	PullRequestEventID   string // "E" tag (NIP-22-style root pointer)
	PullRequestAuthor    string // "P" tag
	Commit               string // "c" tag: updated tip of the PR
	CloneURLs            []string
	MergeBase            string
}

// ParsePullRequestUpdate parses and structurally validates a kind:1619
// event.
func ParsePullRequestUpdate(event *nip01.Event) (*PullRequestUpdate, error) {
	if event.Kind != KindPullRequestUpdate {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindPullRequestUpdate)
	}

	u := &PullRequestUpdate{Event: event}
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
			u.RepoAddress = tag[1]
		case "r":
			if len(tag) > 1 {
				u.EarliestUniqueCommit = tag[1]
			}
		case "p":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, tag[1], err)
			}
			if u.RepositoryOwner == "" {
				u.RepositoryOwner = tag[1]
			} else {
				u.Recipients = append(u.Recipients, tag[1])
			}
		case "E":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, tag[1], err)
			}
			u.PullRequestEventID = tag[1]
		case "P":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, tag[1], err)
			}
			u.PullRequestAuthor = tag[1]
		case "c":
			if len(tag) > 1 {
				u.Commit = tag[1]
			}
		case "clone":
			u.CloneURLs = append(u.CloneURLs, tag[1:]...)
		case "merge-base":
			if len(tag) > 1 {
				u.MergeBase = tag[1]
			}
		}
	}

	if u.PullRequestEventID == "" {
		return nil, ErrInvalidEventTag
	}
	return u, nil
}

// ValidatePullRequestUpdate checks the signature and structure of a pull
// request update event.
func ValidatePullRequestUpdate(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParsePullRequestUpdate(event)
	return err
}

// PullRequestUpdateParams describes a pull request update event to build.
// Pubkey and PullRequestEventID are required; everything else is
// optional.
type PullRequestUpdateParams struct {
	Pubkey               string
	RepoAddress          string
	EarliestUniqueCommit string
	RepositoryOwner      string
	Recipients           []string
	PullRequestEventID   string
	PullRequestAuthor    string
	Commit               string
	CloneURLs            []string
	MergeBase            string
}

// NewPullRequestUpdate builds an unsigned kind:1619 event. Caller must
// sign it.
func NewPullRequestUpdate(p PullRequestUpdateParams) (*nip01.Event, error) {
	if p.PullRequestEventID == "" {
		return nil, ErrInvalidEventTag
	}
	if err := utils.Validate32Key(p.PullRequestEventID); err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, p.PullRequestEventID, err)
	}
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
	for _, r := range p.Recipients {
		if err := utils.Validate32Key(r); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, r, err)
		}
	}
	if p.PullRequestAuthor != "" {
		if err := utils.Validate32Key(p.PullRequestAuthor); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, p.PullRequestAuthor, err)
		}
	}

	var tags [][]string
	if p.RepoAddress != "" {
		tags = append(tags, []string{"a", p.RepoAddress})
	}
	if p.EarliestUniqueCommit != "" {
		tags = append(tags, []string{"r", p.EarliestUniqueCommit})
	}
	if p.RepositoryOwner != "" {
		tags = append(tags, []string{"p", p.RepositoryOwner})
	}
	for _, r := range p.Recipients {
		tags = append(tags, []string{"p", r})
	}
	tags = append(tags, []string{"E", p.PullRequestEventID})
	if p.PullRequestAuthor != "" {
		tags = append(tags, []string{"P", p.PullRequestAuthor})
	}
	if p.Commit != "" {
		tags = append(tags, []string{"c", p.Commit})
	}
	if len(p.CloneURLs) > 0 {
		tags = append(tags, append([]string{"clone"}, p.CloneURLs...))
	}
	if p.MergeBase != "" {
		tags = append(tags, []string{"merge-base", p.MergeBase})
	}

	return nip01.NewUnsignedEvent(KindPullRequestUpdate, p.Pubkey, "", tags...), nil
}
