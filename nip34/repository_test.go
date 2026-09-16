package nip34

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewRepositoryAnnouncementAndParse(t *testing.T) {
	ev, err := NewRepositoryAnnouncement(RepositoryAnnouncementParams{
		Pubkey:               ownerPubkey,
		Identifier:           "ngit",
		Name:                 "ngit",
		Description:          "git over nostr",
		Web:                  []string{"https://gitworkshop.dev/ngit"},
		Clone:                []string{"https://github.com/example/ngit.git"},
		Relays:               []string{"wss://relay.ngit.dev"},
		EarliestUniqueCommit: someEventID,
		Maintainers:          []string{maintainer},
		Upstream:             &UpstreamFork{Pointer: "30617:" + maintainer + ":ngit", RelayHint: "wss://relay.ngit.dev", AuthorPubkey: maintainer},
		Hashtags:             []string{"git", "nostr"},
	})
	if err != nil {
		t.Fatalf("NewRepositoryAnnouncement() error = %v", err)
	}
	ev = signed(t, ev)

	ra, err := ParseRepositoryAnnouncement(ev)
	if err != nil {
		t.Fatalf("ParseRepositoryAnnouncement() error = %v", err)
	}
	if ra.Identifier != "ngit" || ra.Name != "ngit" || ra.Description != "git over nostr" {
		t.Errorf("basic fields = %+v", ra)
	}
	if len(ra.Web) != 1 || ra.Web[0] != "https://gitworkshop.dev/ngit" {
		t.Errorf("Web = %v", ra.Web)
	}
	if len(ra.Clone) != 1 || ra.Clone[0] != "https://github.com/example/ngit.git" {
		t.Errorf("Clone = %v", ra.Clone)
	}
	if len(ra.Relays) != 1 || ra.Relays[0] != "wss://relay.ngit.dev" {
		t.Errorf("Relays = %v", ra.Relays)
	}
	if ra.EarliestUniqueCommit != someEventID {
		t.Errorf("EarliestUniqueCommit = %q", ra.EarliestUniqueCommit)
	}
	if len(ra.Maintainers) != 1 || ra.Maintainers[0] != maintainer {
		t.Errorf("Maintainers = %v", ra.Maintainers)
	}
	if ra.Upstream == nil || ra.Upstream.AuthorPubkey != maintainer {
		t.Errorf("Upstream = %+v", ra.Upstream)
	}
	if len(ra.Hashtags) != 2 {
		t.Errorf("Hashtags = %v", ra.Hashtags)
	}

	if err := ValidateRepositoryAnnouncement(ev); err != nil {
		t.Errorf("ValidateRepositoryAnnouncement() error = %v", err)
	}
}

func TestNewRepositoryAnnouncement_MissingIdentifier(t *testing.T) {
	if _, err := NewRepositoryAnnouncement(RepositoryAnnouncementParams{Pubkey: ownerPubkey}); !errors.Is(err, ErrMissingIdentifier) {
		t.Errorf("error = %v, want ErrMissingIdentifier", err)
	}
}

func TestParseRepositoryAnnouncementErrors(t *testing.T) {
	tests := []struct {
		name    string
		kind    int
		tags    [][]string
		wantErr error
	}{
		{name: "wrong kind", kind: 1, tags: nil, wantErr: ErrWrongKind},
		{name: "missing d", kind: KindRepositoryAnnouncement, tags: nil, wantErr: ErrMissingIdentifier},
		{
			name:    "bad relay scheme",
			kind:    KindRepositoryAnnouncement,
			tags:    [][]string{{"d", "x"}, {"relays", "https://relay.example"}},
			wantErr: ErrInvalidRelayScheme,
		},
		{
			name:    "bad maintainer pubkey",
			kind:    KindRepositoryAnnouncement,
			tags:    [][]string{{"d", "x"}, {"maintainers", "not-a-pubkey"}},
			wantErr: ErrInvalidPubkeyTag,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			_, err := ParseRepositoryAnnouncement(ev)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want wrapping %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewRepositoryStateAndParse(t *testing.T) {
	ev, err := NewRepositoryState(RepositoryStateParams{
		Pubkey:     ownerPubkey,
		Identifier: "ngit",
		Refs: []Ref{
			{Name: "refs/heads/main", CommitID: someEventID},
			{Name: "refs/tags/v1.0.0", CommitID: someEventID2},
		},
		Head: "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("NewRepositoryState() error = %v", err)
	}
	ev = signed(t, ev)

	rs, err := ParseRepositoryState(ev)
	if err != nil {
		t.Fatalf("ParseRepositoryState() error = %v", err)
	}
	if rs.Identifier != "ngit" {
		t.Errorf("Identifier = %q", rs.Identifier)
	}
	if len(rs.Refs) != 2 || rs.Refs[0].Name != "refs/heads/main" || rs.Refs[0].CommitID != someEventID {
		t.Errorf("Refs = %+v", rs.Refs)
	}
	if rs.Head != "refs/heads/main" {
		t.Errorf("Head = %q", rs.Head)
	}

	if err := ValidateRepositoryState(ev); err != nil {
		t.Errorf("ValidateRepositoryState() error = %v", err)
	}
}

func TestNewRepositoryState_MissingIdentifier(t *testing.T) {
	if _, err := NewRepositoryState(RepositoryStateParams{Pubkey: ownerPubkey}); !errors.Is(err, ErrMissingIdentifier) {
		t.Errorf("error = %v, want ErrMissingIdentifier", err)
	}
}
