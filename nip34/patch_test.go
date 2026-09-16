package nip34

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewPatchAndParse(t *testing.T) {
	sig := "-----BEGIN PGP SIGNATURE-----..."
	ev, err := NewPatch(PatchParams{
		Pubkey:          ownerPubkey,
		Content:         "diff --git a/foo b/foo\n...",
		RepoAddress:     testRepoAddress(t),
		CommitRefs:      []string{someEventID},
		RepositoryOwner: ownerPubkey,
		Recipients:      []string{otherUserPubkey},
		IsRoot:          true,
		Commit:          "abc123",
		ParentCommit:    "def456",
		CommitPGPSig:    &sig,
		Committer:       &Committer{Name: "Alice", Email: "alice@example.com", Timestamp: 1700000000, TZOffsetMinutes: 60},
	})
	if err != nil {
		t.Fatalf("NewPatch() error = %v", err)
	}
	ev = signed(t, ev)

	p, err := ParsePatch(ev)
	if err != nil {
		t.Fatalf("ParsePatch() error = %v", err)
	}
	if p.RepoAddress != testRepoAddress(t) {
		t.Errorf("RepoAddress = %q", p.RepoAddress)
	}
	if len(p.CommitRefs) != 1 || p.CommitRefs[0] != someEventID {
		t.Errorf("CommitRefs = %v", p.CommitRefs)
	}
	if p.RepositoryOwner != ownerPubkey {
		t.Errorf("RepositoryOwner = %q", p.RepositoryOwner)
	}
	if len(p.Recipients) != 1 || p.Recipients[0] != otherUserPubkey {
		t.Errorf("Recipients = %v", p.Recipients)
	}
	if !p.IsRoot || p.IsRootRevision {
		t.Errorf("IsRoot=%v IsRootRevision=%v", p.IsRoot, p.IsRootRevision)
	}
	if p.Commit != "abc123" || p.ParentCommit != "def456" {
		t.Errorf("Commit=%q ParentCommit=%q", p.Commit, p.ParentCommit)
	}
	if !p.HasCommitPGPSig || p.CommitPGPSig != sig {
		t.Errorf("CommitPGPSig = %q (has=%v)", p.CommitPGPSig, p.HasCommitPGPSig)
	}
	if p.Committer == nil || p.Committer.Name != "Alice" || p.Committer.TZOffsetMinutes != 60 {
		t.Errorf("Committer = %+v", p.Committer)
	}

	if err := ValidatePatch(ev); err != nil {
		t.Errorf("ValidatePatch() error = %v", err)
	}
}

func TestNewPatch_NoRepoAddressAllowed(t *testing.T) {
	ev, err := NewPatch(PatchParams{Pubkey: ownerPubkey, Content: "patch body"})
	if err != nil {
		t.Fatalf("NewPatch() error = %v", err)
	}
	ev = signed(t, ev)

	p, err := ParsePatch(ev)
	if err != nil {
		t.Fatalf("ParsePatch() error = %v", err)
	}
	if p.RepoAddress != "" {
		t.Errorf("RepoAddress = %q, want empty", p.RepoAddress)
	}
}

func TestPatchReplyTo(t *testing.T) {
	ev, err := NewPatch(PatchParams{
		Pubkey:  ownerPubkey,
		Content: "revision 2",
		ReplyTo: someEventID,
	})
	if err != nil {
		t.Fatalf("NewPatch() error = %v", err)
	}
	ev = signed(t, ev)

	p, err := ParsePatch(ev)
	if err != nil {
		t.Fatalf("ParsePatch() error = %v", err)
	}
	if p.ReplyTo != someEventID {
		t.Errorf("ReplyTo = %q, want %q", p.ReplyTo, someEventID)
	}
}

func TestParsePatchErrors(t *testing.T) {
	tests := []struct {
		name    string
		kind    int
		tags    [][]string
		wantErr error
	}{
		{name: "wrong kind", kind: 1, tags: nil, wantErr: ErrWrongKind},
		{
			name:    "bad repo address",
			kind:    KindPatch,
			tags:    [][]string{{"a", "not-an-address"}},
			wantErr: ErrInvalidRepoAddress,
		},
		{
			name:    "short committer tag",
			kind:    KindPatch,
			tags:    [][]string{{"committer", "Alice"}},
			wantErr: ErrInvalidCommitterTag,
		},
		{
			name:    "bad committer timestamp",
			kind:    KindPatch,
			tags:    [][]string{{"committer", "Alice", "alice@example.com", "not-a-number", "0"}},
			wantErr: ErrInvalidCommitterTag,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			_, err := ParsePatch(ev)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want wrapping %v", err, tt.wantErr)
			}
		})
	}
}
