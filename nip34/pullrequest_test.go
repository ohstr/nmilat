package nip34

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewPullRequestAndParse(t *testing.T) {
	ev, err := NewPullRequest(PullRequestParams{
		Pubkey:               ownerPubkey,
		Content:              "adds a cool feature",
		RepoAddress:          testRepoAddress(t),
		EarliestUniqueCommit: someEventID,
		RepositoryOwner:      ownerPubkey,
		Recipients:           []string{otherUserPubkey},
		Subject:              "Add cool feature",
		Labels:               []string{"enhancement"},
		Commit:               "abc123",
		CloneURLs:            []string{"https://github.com/example/fork.git"},
		BranchName:           "cool-feature",
		RevisesPatch:         someEventID2,
		MergeBase:            "def456",
	})
	if err != nil {
		t.Fatalf("NewPullRequest() error = %v", err)
	}
	ev = signed(t, ev)

	pr, err := ParsePullRequest(ev)
	if err != nil {
		t.Fatalf("ParsePullRequest() error = %v", err)
	}
	if pr.RepoAddress != testRepoAddress(t) || pr.EarliestUniqueCommit != someEventID {
		t.Errorf("RepoAddress/EUC = %q/%q", pr.RepoAddress, pr.EarliestUniqueCommit)
	}
	if pr.RepositoryOwner != ownerPubkey || len(pr.Recipients) != 1 || pr.Recipients[0] != otherUserPubkey {
		t.Errorf("owner/recipients = %q/%v", pr.RepositoryOwner, pr.Recipients)
	}
	if pr.Subject != "Add cool feature" || len(pr.Labels) != 1 || pr.Labels[0] != "enhancement" {
		t.Errorf("subject/labels = %q/%v", pr.Subject, pr.Labels)
	}
	if pr.Commit != "abc123" || pr.BranchName != "cool-feature" || pr.MergeBase != "def456" {
		t.Errorf("commit/branch/mergebase = %q/%q/%q", pr.Commit, pr.BranchName, pr.MergeBase)
	}
	if len(pr.CloneURLs) != 1 || pr.CloneURLs[0] != "https://github.com/example/fork.git" {
		t.Errorf("CloneURLs = %v", pr.CloneURLs)
	}
	if pr.RevisesPatch != someEventID2 {
		t.Errorf("RevisesPatch = %q", pr.RevisesPatch)
	}

	if err := ValidatePullRequest(ev); err != nil {
		t.Errorf("ValidatePullRequest() error = %v", err)
	}
}

func TestParsePullRequestErrors(t *testing.T) {
	ev := &nip01.Event{Kind: KindPullRequest, Tags: [][]string{{"a", "bogus"}}}
	if _, err := ParsePullRequest(ev); !errors.Is(err, ErrInvalidRepoAddress) {
		t.Errorf("error = %v, want ErrInvalidRepoAddress", err)
	}
}

func TestNewPullRequestUpdateAndParse(t *testing.T) {
	ev, err := NewPullRequestUpdate(PullRequestUpdateParams{
		Pubkey:               ownerPubkey,
		RepoAddress:          testRepoAddress(t),
		EarliestUniqueCommit: someEventID,
		RepositoryOwner:      ownerPubkey,
		PullRequestEventID:   someEventID2,
		PullRequestAuthor:    otherUserPubkey,
		Commit:               "newcommit",
		CloneURLs:            []string{"https://github.com/example/fork.git"},
		MergeBase:            "base123",
	})
	if err != nil {
		t.Fatalf("NewPullRequestUpdate() error = %v", err)
	}
	ev = signed(t, ev)

	u, err := ParsePullRequestUpdate(ev)
	if err != nil {
		t.Fatalf("ParsePullRequestUpdate() error = %v", err)
	}
	if u.PullRequestEventID != someEventID2 || u.PullRequestAuthor != otherUserPubkey {
		t.Errorf("PR id/author = %q/%q", u.PullRequestEventID, u.PullRequestAuthor)
	}
	if u.Commit != "newcommit" || u.MergeBase != "base123" {
		t.Errorf("commit/mergebase = %q/%q", u.Commit, u.MergeBase)
	}

	if err := ValidatePullRequestUpdate(ev); err != nil {
		t.Errorf("ValidatePullRequestUpdate() error = %v", err)
	}
}

func TestNewPullRequestUpdate_MissingPullRequestID(t *testing.T) {
	if _, err := NewPullRequestUpdate(PullRequestUpdateParams{Pubkey: ownerPubkey}); !errors.Is(err, ErrInvalidEventTag) {
		t.Errorf("error = %v, want ErrInvalidEventTag", err)
	}
}

func TestParsePullRequestUpdate_MissingE(t *testing.T) {
	ev := &nip01.Event{Kind: KindPullRequestUpdate, Tags: nil}
	if _, err := ParsePullRequestUpdate(ev); !errors.Is(err, ErrInvalidEventTag) {
		t.Errorf("error = %v, want ErrInvalidEventTag", err)
	}
}
