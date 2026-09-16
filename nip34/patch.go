package nip34

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// ErrInvalidCommitterTag is returned when a Patch's "committer" tag
// doesn't have all four required elements or has an unparsable
// timestamp/timezone offset.
var ErrInvalidCommitterTag = errors.New("nip34: invalid committer tag")

// Committer is the ["committer", name, email, timestamp, tz-offset] tag on
// a Patch, mirroring `git format-patch`'s committer identity.
type Committer struct {
	Name            string
	Email           string
	Timestamp       int64
	TZOffsetMinutes int
}

// Patch is a parsed kind:1617 patch event. Content holds the raw
// `git format-patch` output.
type Patch struct {
	*nip01.Event
	// RepoAddress is the "a" tag pointing at the target repository's
	// announcement ("30617:<owner-pubkey>:<repo-id>"). The spec marks it
	// SHOULD, not MUST, so it may be empty.
	RepoAddress string
	// CommitRefs holds every "r" tag value on the patch. NIP-34 overloads
	// this tag: one instance conventionally mirrors the target repo's
	// EarliestUniqueCommit (so clients can subscribe to all patches for a
	// local repo), and, when Commit is set, another mirrors Commit itself
	// (so clients can find existing patches for a specific commit).
	// Nothing on the wire distinguishes which is which; cross-reference
	// against Commit and the repository announcement's own
	// EarliestUniqueCommit to tell them apart.
	CommitRefs []string
	// RepositoryOwner is the first "p" tag (conventionally the repo
	// owner, per the spec's tag ordering).
	RepositoryOwner string
	// Recipients holds any further "p" tags, e.g. other users brought in
	// for attention.
	Recipients     []string
	IsRoot         bool // "t" "root" tag: first patch in a series
	IsRootRevision bool // "t" "root-revision" tag: first patch of a revision
	// ReplyTo is the NIP-10 "e" tag (marked "reply", or unmarked per the
	// legacy positional convention) pointing at the previous patch in the
	// series/revision, or at the root patch for a revision's first patch.
	ReplyTo         string
	Commit          string // "commit" tag: this patch's resulting commit id
	ParentCommit    string // "parent-commit" tag
	HasCommitPGPSig bool   // whether a "commit-pgp-sig" tag is present at all
	CommitPGPSig    string // its value; empty means an unsigned commit
	Committer       *Committer
}

// ParsePatch parses and structurally validates a kind:1617 event.
func ParsePatch(event *nip01.Event) (*Patch, error) {
	if event.Kind != KindPatch {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindPatch)
	}

	p := &Patch{Event: event}
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
			p.RepoAddress = tag[1]
		case "r":
			if len(tag) > 1 {
				p.CommitRefs = append(p.CommitRefs, tag[1])
			}
		case "p":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkeyTag, tag[1], err)
			}
			if p.RepositoryOwner == "" {
				p.RepositoryOwner = tag[1]
			} else {
				p.Recipients = append(p.Recipients, tag[1])
			}
		case "t":
			if len(tag) < 2 {
				continue
			}
			switch tag[1] {
			case "root":
				p.IsRoot = true
			case "root-revision":
				p.IsRootRevision = true
			}
		case "e":
			if len(tag) < 2 {
				continue
			}
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, tag[1], err)
			}
			if p.ReplyTo == "" {
				p.ReplyTo = tag[1]
			}
		case "commit":
			if len(tag) > 1 {
				p.Commit = tag[1]
			}
		case "parent-commit":
			if len(tag) > 1 {
				p.ParentCommit = tag[1]
			}
		case "commit-pgp-sig":
			p.HasCommitPGPSig = true
			if len(tag) > 1 {
				p.CommitPGPSig = tag[1]
			}
		case "committer":
			if len(tag) < 5 {
				return nil, fmt.Errorf("%w: expected [\"committer\", name, email, timestamp, tz-offset], got %v", ErrInvalidCommitterTag, tag)
			}
			ts, err := strconv.ParseInt(tag[3], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: bad timestamp %q: %w", ErrInvalidCommitterTag, tag[3], err)
			}
			tz, err := strconv.Atoi(tag[4])
			if err != nil {
				return nil, fmt.Errorf("%w: bad tz offset %q: %w", ErrInvalidCommitterTag, tag[4], err)
			}
			p.Committer = &Committer{Name: tag[1], Email: tag[2], Timestamp: ts, TZOffsetMinutes: tz}
		}
	}

	return p, nil
}

// ValidatePatch checks the signature and structure of a patch event.
func ValidatePatch(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParsePatch(event)
	return err
}

// PatchParams describes a patch event to build. Pubkey and Content are
// required; everything else is optional (the spec marks nothing besides
// the repo address as conventional, and even that is a SHOULD).
type PatchParams struct {
	Pubkey          string
	Content         string // `git format-patch` output
	RepoAddress     string
	CommitRefs      []string
	RepositoryOwner string
	Recipients      []string
	IsRoot          bool
	IsRootRevision  bool
	ReplyTo         string
	ReplyRelayHint  string
	Commit          string
	ParentCommit    string
	// CommitPGPSig, when non-nil, adds a "commit-pgp-sig" tag; pass a
	// pointer to "" for an unsigned commit (present-but-empty), or nil to
	// omit the tag entirely.
	CommitPGPSig *string
	Committer    *Committer
}

// NewPatch builds an unsigned kind:1617 event. Caller must sign it.
func NewPatch(p PatchParams) (*nip01.Event, error) {
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
	if p.ReplyTo != "" {
		if err := utils.Validate32Key(p.ReplyTo); err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEventTag, p.ReplyTo, err)
		}
	}

	var tags [][]string
	if p.RepoAddress != "" {
		tags = append(tags, []string{"a", p.RepoAddress})
	}
	for _, r := range p.CommitRefs {
		tags = append(tags, []string{"r", r})
	}
	if p.RepositoryOwner != "" {
		tags = append(tags, []string{"p", p.RepositoryOwner})
	}
	for _, r := range p.Recipients {
		tags = append(tags, []string{"p", r})
	}
	if p.IsRoot {
		tags = append(tags, []string{"t", "root"})
	}
	if p.IsRootRevision {
		tags = append(tags, []string{"t", "root-revision"})
	}
	if p.ReplyTo != "" {
		tags = append(tags, []string{"e", p.ReplyTo, p.ReplyRelayHint, "reply"})
	}
	if p.Commit != "" {
		tags = append(tags, []string{"commit", p.Commit})
	}
	if p.ParentCommit != "" {
		tags = append(tags, []string{"parent-commit", p.ParentCommit})
	}
	if p.CommitPGPSig != nil {
		tags = append(tags, []string{"commit-pgp-sig", *p.CommitPGPSig})
	}
	if p.Committer != nil {
		tags = append(tags, []string{
			"committer", p.Committer.Name, p.Committer.Email,
			strconv.FormatInt(p.Committer.Timestamp, 10),
			strconv.Itoa(p.Committer.TZOffsetMinutes),
		})
	}

	return nip01.NewUnsignedEvent(KindPatch, p.Pubkey, p.Content, tags...), nil
}
