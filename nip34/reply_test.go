package nip34

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip22"
)

func TestNewReplyAndParse_TopLevel(t *testing.T) {
	issueEv, err := NewIssue(IssueParams{Pubkey: otherUserPubkey, Content: "bug report", RepoAddress: testRepoAddress(t)})
	if err != nil {
		t.Fatalf("NewIssue() error = %v", err)
	}
	issueEv = signed(t, issueEv)

	replyEv, err := NewReply(ReplyParams{
		Pubkey:    ownerPubkey,
		Content:   "thanks for reporting, looking into it",
		RootEvent: issueEv,
	})
	if err != nil {
		t.Fatalf("NewReply() error = %v", err)
	}
	replyEv = signed(t, replyEv)

	c, err := ParseReply(replyEv)
	if err != nil {
		t.Fatalf("ParseReply() error = %v", err)
	}
	if c.Root.Pointer.Value != issueEv.ID || c.Root.Kind != "1621" {
		t.Errorf("Root = %+v", c.Root)
	}
	if c.Parent.Pointer.Value != issueEv.ID {
		t.Errorf("Parent.Pointer.Value = %q, want top-level reply to point at root", c.Parent.Pointer.Value)
	}

	if err := ValidateReply(replyEv); err != nil {
		t.Errorf("ValidateReply() error = %v", err)
	}
}

func TestNewReplyAndParse_NestedOnPreviousReply(t *testing.T) {
	patchEv, err := NewPatch(PatchParams{Pubkey: ownerPubkey, Content: "diff", RepoAddress: testRepoAddress(t)})
	if err != nil {
		t.Fatalf("NewPatch() error = %v", err)
	}
	patchEv = signed(t, patchEv)

	firstReply, err := NewReply(ReplyParams{Pubkey: otherUserPubkey, Content: "comment", RootEvent: patchEv})
	if err != nil {
		t.Fatalf("NewReply() error = %v", err)
	}
	firstReply = signed(t, firstReply)

	nestedReply, err := NewReply(ReplyParams{
		Pubkey:      ownerPubkey,
		Content:     "reply to comment",
		RootEvent:   patchEv,
		ParentEvent: firstReply,
	})
	if err != nil {
		t.Fatalf("NewReply() (nested) error = %v", err)
	}
	nestedReply = signed(t, nestedReply)

	c, err := ParseReply(nestedReply)
	if err != nil {
		t.Fatalf("ParseReply() error = %v", err)
	}
	if c.Root.Pointer.Value != patchEv.ID {
		t.Errorf("Root.Pointer.Value = %q, want patch id", c.Root.Pointer.Value)
	}
	if c.Parent.Pointer.Value != firstReply.ID || c.Parent.Kind != "1111" {
		t.Errorf("Parent = %+v, want pointer at first reply with kind 1111", c.Parent)
	}
}

func TestNewReply_MissingRootEvent(t *testing.T) {
	if _, err := NewReply(ReplyParams{Pubkey: ownerPubkey}); !errors.Is(err, ErrInvalidEventTag) {
		t.Errorf("error = %v, want ErrInvalidEventTag", err)
	}
}

func TestParseReply_WrongRootKind(t *testing.T) {
	ev, err := nip22.NewComment(nip22.CommentParams{
		Pubkey:  ownerPubkey,
		Content: "not a git thread",
		Root: nip22.ScopeParams{
			Pointer: nip22.PointerParams{Type: nip22.PointerEvent, Value: someEventID},
			Kind:    "1",
		},
		Parent: nip22.ScopeParams{
			Pointer: nip22.PointerParams{Type: nip22.PointerEvent, Value: someEventID},
			Kind:    "1",
		},
	})
	if err != nil {
		t.Fatalf("nip22.NewComment() error = %v", err)
	}
	ev = signed(t, ev)

	if _, err := ParseReply(ev); !errors.Is(err, ErrNotAGitReplyRoot) {
		t.Errorf("error = %v, want ErrNotAGitReplyRoot", err)
	}
}
