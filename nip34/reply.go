package nip34

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip22"
)

// ErrNotAGitReplyRoot is returned by ParseReply when a kind:1111 comment's
// root scope kind isn't one of Issue, Patch, or PullRequest.
var ErrNotAGitReplyRoot = errors.New("nip34: root item is not an issue/patch/pull-request")

// ReplyParams describes a reply to build: a kind:1111 NIP-22 comment (see
// the nip22 package) on a NIP-34 issue, patch, or pull request. Pubkey and
// RootEvent are required; RootEvent must be the thread's root event (an
// Issue/Patch/PullRequest event). ParentEvent is the specific item being
// replied to -- leave it nil (or set it equal to RootEvent) for a
// top-level reply.
type ReplyParams struct {
	Pubkey    string
	Content   string
	RootEvent *nip01.Event
	// ParentEvent defaults to RootEvent when nil, producing a top-level
	// reply.
	ParentEvent *nip01.Event
	RelayHint   string
}

// NewReply builds an unsigned reply event. See ReplyParams.
func NewReply(p ReplyParams) (*nip01.Event, error) {
	if p.RootEvent == nil {
		return nil, ErrInvalidEventTag
	}
	parent := p.ParentEvent
	if parent == nil {
		parent = p.RootEvent
	}

	return nip22.NewComment(nip22.CommentParams{
		Pubkey:  p.Pubkey,
		Content: p.Content,
		Root: nip22.ScopeParams{
			Pointer: nip22.PointerParams{
				Type:         nip22.PointerEvent,
				Value:        p.RootEvent.ID,
				RelayHint:    p.RelayHint,
				AuthorPubkey: p.RootEvent.PubKey,
			},
			Kind:         strconv.Itoa(p.RootEvent.Kind),
			AuthorPubkey: p.RootEvent.PubKey,
		},
		Parent: nip22.ScopeParams{
			Pointer: nip22.PointerParams{
				Type:         nip22.PointerEvent,
				Value:        parent.ID,
				RelayHint:    p.RelayHint,
				AuthorPubkey: parent.PubKey,
			},
			Kind:         strconv.Itoa(parent.Kind),
			AuthorPubkey: parent.PubKey,
		},
	})
}

// ParseReply parses a kind:1111 event as a NIP-22 comment (see
// nip22.ParseComment) and checks that its root scope kind is one of
// Issue/Patch/PullRequest, returning ErrNotAGitReplyRoot otherwise.
func ParseReply(event *nip01.Event) (*nip22.Comment, error) {
	c, err := nip22.ParseComment(event)
	if err != nil {
		return nil, err
	}

	switch c.Root.Kind {
	case strconv.Itoa(KindIssue), strconv.Itoa(KindPatch), strconv.Itoa(KindPullRequest):
		return c, nil
	default:
		return nil, fmt.Errorf("%w: got %q", ErrNotAGitReplyRoot, c.Root.Kind)
	}
}

// ValidateReply checks the signature and structure of a reply event.
func ValidateReply(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseReply(event)
	return err
}
