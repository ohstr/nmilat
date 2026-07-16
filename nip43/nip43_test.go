package nip43

import (
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

const testPubkeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testPubkeyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func intPtr(n int) *int { return &n }

func TestParseRole(t *testing.T) {
	tests := []struct {
		name      string
		tags      [][]string
		wantErrIs error
		wantID    string
		wantColor *int
		wantOrder *int
	}{
		{
			name:   "minimal valid",
			tags:   [][]string{{"-"}, {"d", "28b7e50f"}},
			wantID: "28b7e50f",
		},
		{
			name: "full example from spec",
			tags: [][]string{
				{"-"},
				{"d", "28b7e50f"},
				{"label", "king"},
				{"description", "ruler of the relay"},
				{"color", "37"},
				{"order", "1"},
			},
			wantID:    "28b7e50f",
			wantColor: intPtr(37),
			wantOrder: intPtr(1),
		},
		{
			name:      "missing protected tag",
			tags:      [][]string{{"d", "28b7e50f"}},
			wantErrIs: ErrMissingProtectedTag,
		},
		{
			name:      "missing d tag",
			tags:      [][]string{{"-"}},
			wantErrIs: ErrMissingDTag,
		},
		{
			name:      "color out of range",
			tags:      [][]string{{"-"}, {"d", "x"}, {"color", "361"}},
			wantErrIs: ErrInvalidColor,
		},
		{
			name:      "color negative",
			tags:      [][]string{{"-"}, {"d", "x"}, {"color", "-1"}},
			wantErrIs: ErrInvalidColor,
		},
		{
			name:      "order not an integer",
			tags:      [][]string{{"-"}, {"d", "x"}, {"order", "first"}},
			wantErrIs: ErrInvalidOrder,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: KindRoleDefinition, Tags: tt.tags}
			role, err := ParseRole(ev)
			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is(_, %v)", err, tt.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if role.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", role.ID, tt.wantID)
			}
			if (role.Color == nil) != (tt.wantColor == nil) || (role.Color != nil && *role.Color != *tt.wantColor) {
				t.Errorf("Color = %v, want %v", role.Color, tt.wantColor)
			}
			if (role.Order == nil) != (tt.wantOrder == nil) || (role.Order != nil && *role.Order != *tt.wantOrder) {
				t.Errorf("Order = %v, want %v", role.Order, tt.wantOrder)
			}
		})
	}
}

func TestParseRole_WrongKind(t *testing.T) {
	ev := &nip01.Event{Kind: 1, Tags: [][]string{{"-"}, {"d", "x"}}}
	if _, err := ParseRole(ev); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("err = %v, want errors.Is(_, ErrWrongKind)", err)
	}
}

func TestNewRoleDefinition_RoundTrips(t *testing.T) {
	ev := NewRoleDefinition(RoleParams{
		SelfPubkey:  testPubkeyA,
		ID:          "28b7e50f",
		Label:       "king",
		Description: "ruler of the relay",
		Color:       intPtr(37),
		Order:       intPtr(1),
	})
	if ev.Kind != KindRoleDefinition {
		t.Fatalf("Kind = %d, want %d", ev.Kind, KindRoleDefinition)
	}
	role, err := ParseRole(ev)
	if err != nil {
		t.Fatalf("ParseRole() on NewRoleDefinition's own output: %v", err)
	}
	if role.ID != "28b7e50f" || role.Label != "king" || role.Description != "ruler of the relay" {
		t.Fatalf("round-trip mismatch: %+v", role)
	}
	if role.Color == nil || *role.Color != 37 || role.Order == nil || *role.Order != 1 {
		t.Fatalf("round-trip mismatch: %+v", role)
	}
}

func TestParseMembershipList(t *testing.T) {
	tests := []struct {
		name        string
		tags        [][]string
		wantErrIs   error
		wantMembers []Member
	}{
		{
			name:        "empty list is valid",
			tags:        [][]string{{"-"}},
			wantMembers: nil,
		},
		{
			name: "spec example",
			tags: [][]string{
				{"-"},
				{"member", testPubkeyA},
				{"member", testPubkeyB, "28b7e50f"},
			},
			wantMembers: []Member{
				{Pubkey: testPubkeyA},
				{Pubkey: testPubkeyB, Roles: []string{"28b7e50f"}},
			},
		},
		{
			name:      "missing protected tag",
			tags:      [][]string{{"member", testPubkeyA}},
			wantErrIs: ErrMissingProtectedTag,
		},
		{
			name:      "invalid member pubkey",
			tags:      [][]string{{"-"}, {"member", "not-a-pubkey"}},
			wantErrIs: ErrInvalidMemberPubkey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: KindMembershipList, Tags: tt.tags}
			list, err := ParseMembershipList(ev)
			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is(_, %v)", err, tt.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(list.Members) != len(tt.wantMembers) {
				t.Fatalf("Members = %+v, want %+v", list.Members, tt.wantMembers)
			}
			for i, m := range list.Members {
				want := tt.wantMembers[i]
				if m.Pubkey != want.Pubkey || len(m.Roles) != len(want.Roles) {
					t.Fatalf("Members[%d] = %+v, want %+v", i, m, want)
				}
				for j, r := range m.Roles {
					if r != want.Roles[j] {
						t.Fatalf("Members[%d].Roles[%d] = %q, want %q", i, j, r, want.Roles[j])
					}
				}
			}
		})
	}
}

func TestNewMembershipList_RoundTrips(t *testing.T) {
	ev := NewMembershipList(MembershipListParams{
		SelfPubkey: testPubkeyA,
		Members: []Member{
			{Pubkey: testPubkeyA},
			{Pubkey: testPubkeyB, Roles: []string{"28b7e50f"}},
		},
	})
	list, err := ParseMembershipList(ev)
	if err != nil {
		t.Fatalf("ParseMembershipList() on NewMembershipList's own output: %v", err)
	}
	if len(list.Members) != 2 {
		t.Fatalf("Members = %+v, want 2 entries", list.Members)
	}
}

func TestAddRemoveUser(t *testing.T) {
	tests := []struct {
		name      string
		build     func() *nip01.Event
		parse     func(*nip01.Event) (*UserEvent, error)
		wantKind  int
		wrongKind int
	}{
		{
			name:      "add user",
			build:     func() *nip01.Event { return NewAddUser(testPubkeyA, testPubkeyB) },
			parse:     ParseAddUser,
			wantKind:  KindAddUser,
			wrongKind: KindRemoveUser,
		},
		{
			name:      "remove user",
			build:     func() *nip01.Event { return NewRemoveUser(testPubkeyA, testPubkeyB) },
			parse:     ParseRemoveUser,
			wantKind:  KindRemoveUser,
			wrongKind: KindAddUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := tt.build()
			if ev.Kind != tt.wantKind {
				t.Fatalf("Kind = %d, want %d", ev.Kind, tt.wantKind)
			}
			ue, err := tt.parse(ev)
			if err != nil {
				t.Fatalf("parse() on own output: %v", err)
			}
			if ue.Pubkey != testPubkeyB {
				t.Errorf("Pubkey = %q, want %q", ue.Pubkey, testPubkeyB)
			}

			ev.Kind = tt.wrongKind
			if _, err := tt.parse(ev); !errors.Is(err, ErrWrongKind) {
				t.Fatalf("wrong-kind err = %v, want errors.Is(_, ErrWrongKind)", err)
			}
		})
	}

	t.Run("missing p tag", func(t *testing.T) {
		ev := &nip01.Event{Kind: KindAddUser, Tags: [][]string{{"-"}}}
		if _, err := ParseAddUser(ev); !errors.Is(err, ErrMissingPTag) {
			t.Fatalf("err = %v, want errors.Is(_, ErrMissingPTag)", err)
		}
	})

	t.Run("invalid p pubkey", func(t *testing.T) {
		ev := &nip01.Event{Kind: KindAddUser, Tags: [][]string{{"-"}, {"p", "bad"}}}
		if _, err := ParseAddUser(ev); !errors.Is(err, ErrInvalidPubkey) {
			t.Fatalf("err = %v, want errors.Is(_, ErrInvalidPubkey)", err)
		}
	})

	t.Run("missing protected tag", func(t *testing.T) {
		ev := &nip01.Event{Kind: KindAddUser, Tags: [][]string{{"p", testPubkeyB}}}
		if _, err := ParseAddUser(ev); !errors.Is(err, ErrMissingProtectedTag) {
			t.Fatalf("err = %v, want errors.Is(_, ErrMissingProtectedTag)", err)
		}
	})
}

func TestJoinRequest(t *testing.T) {
	ev := NewJoinRequest(testPubkeyA, "some-claim-code")
	if ev.Kind != KindJoinRequest {
		t.Fatalf("Kind = %d, want %d", ev.Kind, KindJoinRequest)
	}
	jr, err := ParseJoinRequest(ev)
	if err != nil {
		t.Fatalf("ParseJoinRequest() on own output: %v", err)
	}
	if jr.Claim != "some-claim-code" {
		t.Errorf("Claim = %q, want %q", jr.Claim, "some-claim-code")
	}

	t.Run("missing claim", func(t *testing.T) {
		ev := &nip01.Event{Kind: KindJoinRequest, Tags: [][]string{{"-"}}}
		if _, err := ParseJoinRequest(ev); !errors.Is(err, ErrMissingClaimTag) {
			t.Fatalf("err = %v, want errors.Is(_, ErrMissingClaimTag)", err)
		}
	})

	t.Run("missing protected tag", func(t *testing.T) {
		ev := &nip01.Event{Kind: KindJoinRequest, Tags: [][]string{{"claim", "x"}}}
		if _, err := ParseJoinRequest(ev); !errors.Is(err, ErrMissingProtectedTag) {
			t.Fatalf("err = %v, want errors.Is(_, ErrMissingProtectedTag)", err)
		}
	})
}

func TestInviteResponse(t *testing.T) {
	ev := NewInviteResponse(testPubkeyA, "fresh-claim")
	if ev.Kind != KindInviteRequest {
		t.Fatalf("Kind = %d, want %d", ev.Kind, KindInviteRequest)
	}
	ir, err := ParseInviteResponse(ev)
	if err != nil {
		t.Fatalf("ParseInviteResponse() on own output: %v", err)
	}
	if ir.Claim != "fresh-claim" {
		t.Errorf("Claim = %q, want %q", ir.Claim, "fresh-claim")
	}
}

func TestLeaveRequest(t *testing.T) {
	ev := NewLeaveRequest(testPubkeyA)
	if ev.Kind != KindLeaveRequest {
		t.Fatalf("Kind = %d, want %d", ev.Kind, KindLeaveRequest)
	}
	if _, err := ParseLeaveRequest(ev); err != nil {
		t.Fatalf("ParseLeaveRequest() on own output: %v", err)
	}

	t.Run("missing protected tag", func(t *testing.T) {
		ev := &nip01.Event{Kind: KindLeaveRequest, Tags: nil}
		if _, err := ParseLeaveRequest(ev); !errors.Is(err, ErrMissingProtectedTag) {
			t.Fatalf("err = %v, want errors.Is(_, ErrMissingProtectedTag)", err)
		}
	})
}

func TestValidateFreshness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	window := 5 * time.Minute

	tests := []struct {
		name      string
		createdAt uint64
		wantErr   bool
	}{
		{name: "exactly now", createdAt: uint64(now.Unix()), wantErr: false},
		{name: "within window, past", createdAt: uint64(now.Unix()) - 60, wantErr: false},
		{name: "within window, future", createdAt: uint64(now.Unix()) + 60, wantErr: false},
		{name: "at window boundary, past", createdAt: uint64(now.Unix()) - uint64(window.Seconds()), wantErr: false},
		{name: "past window", createdAt: uint64(now.Unix()) - uint64(window.Seconds()) - 1, wantErr: true},
		{name: "beyond window, future", createdAt: uint64(now.Unix()) + uint64(window.Seconds()) + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFreshness(tt.createdAt, now, window)
			if tt.wantErr && !errors.Is(err, ErrStaleTimestamp) {
				t.Fatalf("err = %v, want errors.Is(_, ErrStaleTimestamp)", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
		})
	}
}

func TestNewClaim_UniqueAndNonEmpty(t *testing.T) {
	c1 := NewClaim()
	c2 := NewClaim()
	if c1 == "" || c2 == "" {
		t.Fatal("NewClaim() returned an empty string")
	}
	if c1 == c2 {
		t.Fatal("NewClaim() returned duplicate strings")
	}
}

func TestIsRelayAuthoredKind(t *testing.T) {
	relayAuthored := []int{KindRoleDefinition, KindMembershipList, KindAddUser, KindRemoveUser, KindInviteRequest}
	for _, k := range relayAuthored {
		if !IsRelayAuthoredKind(k) {
			t.Errorf("IsRelayAuthoredKind(%d) = false, want true", k)
		}
	}

	notRelayAuthored := []int{1, KindJoinRequest, KindLeaveRequest, 0, 9999}
	for _, k := range notRelayAuthored {
		if IsRelayAuthoredKind(k) {
			t.Errorf("IsRelayAuthoredKind(%d) = true, want false", k)
		}
	}
}
