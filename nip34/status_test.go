package nip34

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewStatusAndParse_Applied(t *testing.T) {
	ev, err := NewStatus(StatusParams{
		Pubkey:             ownerPubkey,
		Kind:               KindStatusApplied,
		RootID:             someEventID,
		AcceptedRevisionID: someEventID2,
		RepositoryOwner:    ownerPubkey,
		RootAuthor:         otherUserPubkey,
		RepoAddress:        testRepoAddress(t),
		AppliedPatches:     []QuotedPatch{{EventID: someEventID, RelayHint: "wss://relay.example", Pubkey: otherUserPubkey}},
		MergeCommit:        "merged123",
		Content:            "applied, thanks!",
	})
	if err != nil {
		t.Fatalf("NewStatus() error = %v", err)
	}
	ev = signed(t, ev)

	s, err := ParseStatus(ev)
	if err != nil {
		t.Fatalf("ParseStatus() error = %v", err)
	}
	if s.Kind != KindStatusApplied {
		t.Errorf("Kind = %d", s.Kind)
	}
	if s.RootID != someEventID || s.AcceptedRevisionID != someEventID2 {
		t.Errorf("RootID/AcceptedRevisionID = %q/%q", s.RootID, s.AcceptedRevisionID)
	}
	if s.RepositoryOwner != ownerPubkey || s.RootAuthor != otherUserPubkey {
		t.Errorf("owner/author = %q/%q", s.RepositoryOwner, s.RootAuthor)
	}
	if s.RepoAddress != testRepoAddress(t) {
		t.Errorf("RepoAddress = %q", s.RepoAddress)
	}
	if len(s.AppliedPatches) != 1 || s.AppliedPatches[0].EventID != someEventID {
		t.Errorf("AppliedPatches = %+v", s.AppliedPatches)
	}
	if s.MergeCommit != "merged123" {
		t.Errorf("MergeCommit = %q", s.MergeCommit)
	}
	// merge-commit also mirrors into an "r" tag per spec.
	found := false
	for _, r := range s.CommitRefs {
		if r == "merged123" {
			found = true
		}
	}
	if !found {
		t.Errorf("CommitRefs = %v, want to include merge commit", s.CommitRefs)
	}

	if err := ValidateStatus(ev); err != nil {
		t.Errorf("ValidateStatus() error = %v", err)
	}
}

func TestNewStatus_MissingRootID(t *testing.T) {
	if _, err := NewStatus(StatusParams{Pubkey: ownerPubkey, Kind: KindStatusOpen}); err == nil {
		t.Error("expected error for missing RootID")
	}
}

func TestParseStatusErrors(t *testing.T) {
	tests := []struct {
		name    string
		kind    int
		tags    [][]string
		wantErr error
	}{
		{name: "wrong kind", kind: 1617, tags: nil, wantErr: ErrWrongKind},
		{name: "missing root e tag", kind: KindStatusOpen, tags: nil, wantErr: ErrMissingRootTag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			_, err := ParseStatus(ev)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want wrapping %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolveStatus(t *testing.T) {
	rootAuthor := otherUserPubkey
	strangerPubkey := someEventID // reuse a 64-hex string as a bogus pubkey; only equality matters here

	older := &Status{Event: &nip01.Event{PubKey: rootAuthor, CreatedAt: 100}, Kind: KindStatusOpen}
	newer := &Status{Event: &nip01.Event{PubKey: maintainer, CreatedAt: 200}, Kind: KindStatusApplied}
	fromStranger := &Status{Event: &nip01.Event{PubKey: strangerPubkey, CreatedAt: 300}, Kind: KindStatusClosed}

	got := ResolveStatus([]*Status{older, newer, fromStranger}, rootAuthor, []string{maintainer})
	if got != newer {
		t.Errorf("ResolveStatus() = %+v, want the newer authorized status", got)
	}

	if got := ResolveStatus(nil, rootAuthor, nil); got != nil {
		t.Errorf("ResolveStatus(nil events) = %+v, want nil", got)
	}

	onlyStranger := ResolveStatus([]*Status{fromStranger}, rootAuthor, []string{maintainer})
	if onlyStranger != nil {
		t.Errorf("ResolveStatus() = %+v, want nil (no authorized status)", onlyStranger)
	}
}

func TestResolveRevisionStatus(t *testing.T) {
	if got := ResolveRevisionStatus(someEventID, nil); got != KindStatusOpen {
		t.Errorf("nil rootStatus: got %d, want KindStatusOpen", got)
	}

	openRoot := &Status{Kind: KindStatusOpen}
	if got := ResolveRevisionStatus(someEventID, openRoot); got != KindStatusOpen {
		t.Errorf("open root: got %d, want KindStatusOpen", got)
	}

	appliedThisRevision := &Status{Kind: KindStatusApplied, AcceptedRevisionID: someEventID}
	if got := ResolveRevisionStatus(someEventID, appliedThisRevision); got != KindStatusApplied {
		t.Errorf("accepted revision: got %d, want KindStatusApplied", got)
	}

	appliedOtherRevision := &Status{Kind: KindStatusApplied, AcceptedRevisionID: someEventID2}
	if got := ResolveRevisionStatus(someEventID, appliedOtherRevision); got != KindStatusClosed {
		t.Errorf("non-accepted revision: got %d, want KindStatusClosed", got)
	}
}
