package nip34

import (
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// ErrMissingRootTag is returned when a Status event has no "e" tag
// identifying the issue/PR/patch it applies to.
var ErrMissingRootTag = errors.New("nip34: status event missing root e tag")

// QuotedPatch is a "q" tag on a KindStatusApplied event, citing one of the
// patches applied/merged.
type QuotedPatch struct {
	EventID   string
	RelayHint string
	Pubkey    string
}

// Status is a parsed kind:1630-1633 status event, setting the status of a
// root patch, PR, or issue (default status is "Open").
type Status struct {
	*nip01.Event
	// Kind mirrors Event.Kind: one of KindStatusOpen/Applied/Closed/Draft.
	Kind int
	// RootID is the "e" tag (marked "root", or unmarked) identifying the
	// issue/PR/original root patch this status applies to.
	RootID string
	// AcceptedRevisionID is the "e" tag marked "reply", set when a patch
	// revision (rather than the original root patch) was the one applied.
	AcceptedRevisionID string
	// RepositoryOwner, RootAuthor, and RevisionAuthor are the "p" tags, in
	// the order the spec lists them. Nothing on the wire marks which "p"
	// tag is which beyond that order.
	RepositoryOwner string
	RootAuthor      string
	RevisionAuthor  string
	RepoAddress     string // "a" tag; optional, for subscription efficiency
	// CommitRefs holds every "r" tag value. The spec overloads this tag
	// across an EarliestUniqueCommit hint, a KindStatusApplied
	// merge-commit mirror, and per-commit KindStatusApplied
	// applied-as-commits mirrors; nothing on the wire distinguishes them.
	CommitRefs []string
	// AppliedPatches lists the "q"-tagged patches applied/merged
	// (KindStatusApplied only).
	AppliedPatches []QuotedPatch
	// MergeCommit is the "merge-commit" tag (KindStatusApplied, merge
	// case).
	MergeCommit string
	// AppliedAsCommits are the "applied-as-commits" tag's commit ids
	// (KindStatusApplied, apply case).
	AppliedAsCommits []string
}

// ParseStatus parses and structurally validates a kind:1630-1633 event.
func ParseStatus(event *nip01.Event) (*Status, error) {
	if !IsStatusKind(event.Kind) {
		return nil, fmt.Errorf("%w: got %d, want one of %d/%d/%d/%d", ErrWrongKind, event.Kind,
			KindStatusOpen, KindStatusApplied, KindStatusClosed, KindStatusDraft)
	}

	s := &Status{Event: event, Kind: event.Kind}
	var pTagCount int
	for _, tag := range event.Tags {
		if len(tag) < 1 {
			continue
		}
		switch tag[0] {
		case "e":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, tag[1], err)
			}
			marker := ""
			if len(tag) > 3 {
				marker = tag[3]
			}
			if marker == "reply" {
				s.AcceptedRevisionID = tag[1]
			} else {
				s.RootID = tag[1]
			}
		case "p":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, tag[1], err)
			}
			pTagCount++
			switch pTagCount {
			case 1:
				s.RepositoryOwner = tag[1]
			case 2:
				s.RootAuthor = tag[1]
			case 3:
				s.RevisionAuthor = tag[1]
			}
		case "a":
			if len(tag) < 2 {
				continue
			}
			if _, _, _, err := utils.ParseATag(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidRepoAddress, tag[1], err)
			}
			s.RepoAddress = tag[1]
		case "r":
			if len(tag) > 1 {
				s.CommitRefs = append(s.CommitRefs, tag[1])
			}
		case "q":
			if len(tag) < 2 {
				continue
			}
			qp := QuotedPatch{EventID: tag[1]}
			if len(tag) > 2 {
				qp.RelayHint = tag[2]
			}
			if len(tag) > 3 {
				qp.Pubkey = tag[3]
			}
			s.AppliedPatches = append(s.AppliedPatches, qp)
		case "merge-commit":
			if len(tag) > 1 {
				s.MergeCommit = tag[1]
			}
		case "applied-as-commits":
			s.AppliedAsCommits = append(s.AppliedAsCommits, tag[1:]...)
		}
	}

	if s.RootID == "" {
		return nil, ErrMissingRootTag
	}
	return s, nil
}

// ValidateStatus checks the signature and structure of a status event.
func ValidateStatus(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseStatus(event)
	return err
}

// StatusParams describes a status event to build. Pubkey, Kind, and RootID
// are required; everything else is optional.
type StatusParams struct {
	Pubkey             string
	Kind               int // one of KindStatusOpen/Applied/Closed/Draft
	RootID             string
	AcceptedRevisionID string
	RepositoryOwner    string
	RootAuthor         string
	RevisionAuthor     string
	RepoAddress        string
	RepoAddressRelay   string
	CommitRefs         []string
	AppliedPatches     []QuotedPatch
	MergeCommit        string
	AppliedAsCommits   []string
	Content            string
}

// NewStatus builds an unsigned status event. Caller must sign it.
func NewStatus(p StatusParams) (*nip01.Event, error) {
	if !IsStatusKind(p.Kind) {
		return nil, fmt.Errorf("%w: got %d, want one of %d/%d/%d/%d", ErrWrongKind, p.Kind,
			KindStatusOpen, KindStatusApplied, KindStatusClosed, KindStatusDraft)
	}
	if err := utils.Validate32Key(p.RootID); err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, p.RootID, err)
	}
	if p.RepoAddress != "" {
		if _, _, _, err := utils.ParseATag(p.RepoAddress); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidRepoAddress, p.RepoAddress, err)
		}
	}
	for _, pubkey := range []string{p.RepositoryOwner, p.RootAuthor, p.RevisionAuthor} {
		if pubkey == "" {
			continue
		}
		if err := utils.Validate32Key(pubkey); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, pubkey, err)
		}
	}

	tags := [][]string{{"e", p.RootID, "", "root"}}
	if p.AcceptedRevisionID != "" {
		if err := utils.Validate32Key(p.AcceptedRevisionID); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, p.AcceptedRevisionID, err)
		}
		tags = append(tags, []string{"e", p.AcceptedRevisionID, "", "reply"})
	}
	if p.RepositoryOwner != "" {
		tags = append(tags, []string{"p", p.RepositoryOwner})
	}
	if p.RootAuthor != "" {
		tags = append(tags, []string{"p", p.RootAuthor})
	}
	if p.RevisionAuthor != "" {
		tags = append(tags, []string{"p", p.RevisionAuthor})
	}
	if p.RepoAddress != "" {
		aTag := []string{"a", p.RepoAddress}
		if p.RepoAddressRelay != "" {
			aTag = append(aTag, p.RepoAddressRelay)
		}
		tags = append(tags, aTag)
	}
	for _, r := range p.CommitRefs {
		tags = append(tags, []string{"r", r})
	}
	for _, q := range p.AppliedPatches {
		qTag := []string{"q", q.EventID}
		if q.RelayHint != "" || q.Pubkey != "" {
			qTag = append(qTag, q.RelayHint)
		}
		if q.Pubkey != "" {
			qTag = append(qTag, q.Pubkey)
		}
		tags = append(tags, qTag)
	}
	if p.MergeCommit != "" {
		tags = append(tags, []string{"merge-commit", p.MergeCommit}, []string{"r", p.MergeCommit})
	}
	if len(p.AppliedAsCommits) > 0 {
		tags = append(tags, append([]string{"applied-as-commits"}, p.AppliedAsCommits...))
		for _, c := range p.AppliedAsCommits {
			tags = append(tags, []string{"r", c})
		}
	}

	return nip01.NewUnsignedEvent(p.Kind, p.Pubkey, p.Content, tags...), nil
}

// ResolveStatus picks the currently-valid status for a thread from a set
// of Status events referencing the same root, per the spec's rule: "the
// most recent Status event (by created_at date) from either the issue/
// patch author or a maintainer is considered valid." Status events not
// authored by rootAuthorPubkey or one of maintainerPubkeys are ignored.
// Returns nil if no authorized Status event is found.
func ResolveStatus(events []*Status, rootAuthorPubkey string, maintainerPubkeys []string) *Status {
	isAuthorized := func(pubkey string) bool {
		if pubkey == rootAuthorPubkey {
			return true
		}
		for _, m := range maintainerPubkeys {
			if pubkey == m {
				return true
			}
		}
		return false
	}

	var latest *Status
	for _, s := range events {
		if !isAuthorized(s.PubKey) {
			continue
		}
		if latest == nil || s.CreatedAt > latest.CreatedAt {
			latest = s
		}
	}
	return latest
}

// ResolveRevisionStatus derives the effective status kind for a patch
// revision (a patch series distinct from the root patch it revises), given
// rootStatus, the resolved Status of the root patch (see ResolveStatus).
// Per the spec: a revision inherits the root patch's status, unless the
// root's status is KindStatusApplied and this revision isn't the one
// tagged as accepted in that status event -- in which case the revision is
// implicitly KindStatusClosed. revisionRootEventID is the id of the
// revision's own first ("root-revision"-tagged) patch event. rootStatus
// may be nil, meaning the root patch has no status yet (implicitly Open).
func ResolveRevisionStatus(revisionRootEventID string, rootStatus *Status) int {
	if rootStatus == nil {
		return KindStatusOpen
	}
	if rootStatus.Kind == KindStatusApplied && rootStatus.AcceptedRevisionID != revisionRootEventID {
		return KindStatusClosed
	}
	return rootStatus.Kind
}
