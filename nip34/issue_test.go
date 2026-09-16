package nip34

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewIssueAndParse(t *testing.T) {
	ev, err := NewIssue(IssueParams{
		Pubkey:          otherUserPubkey,
		Content:         "The build is broken on main.",
		RepoAddress:     testRepoAddress(t),
		RepositoryOwner: ownerPubkey,
		Subject:         "Build broken",
		Labels:          []string{"bug", "ci"},
	})
	if err != nil {
		t.Fatalf("NewIssue() error = %v", err)
	}
	ev = signed(t, ev)

	iss, err := ParseIssue(ev)
	if err != nil {
		t.Fatalf("ParseIssue() error = %v", err)
	}
	if iss.RepoAddress != testRepoAddress(t) || iss.RepositoryOwner != ownerPubkey {
		t.Errorf("RepoAddress/owner = %q/%q", iss.RepoAddress, iss.RepositoryOwner)
	}
	if iss.Subject != "Build broken" || len(iss.Labels) != 2 {
		t.Errorf("Subject/Labels = %q/%v", iss.Subject, iss.Labels)
	}

	if err := ValidateIssue(ev); err != nil {
		t.Errorf("ValidateIssue() error = %v", err)
	}
}

func TestParseIssueErrors(t *testing.T) {
	tests := []struct {
		name    string
		kind    int
		tags    [][]string
		wantErr error
	}{
		{name: "wrong kind", kind: 1, tags: nil, wantErr: ErrWrongKind},
		{name: "bad repo address", kind: KindIssue, tags: [][]string{{"a", "bogus"}}, wantErr: ErrInvalidRepoAddress},
		{name: "bad owner pubkey", kind: KindIssue, tags: [][]string{{"p", "not-a-pubkey"}}, wantErr: ErrInvalidPubkeyTag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			_, err := ParseIssue(ev)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want wrapping %v", err, tt.wantErr)
			}
		})
	}
}
