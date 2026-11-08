package relay

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/wire"
)

func inviteFilters(filters ...*nip01.SubscriptionFilter) *nip01.SubscriptionFilterGroup {
	return nip01.NewSubscriptionFilterGroup(filters...)
}

func TestMembershipRequestHandler_CanHandleOnlyInviteOnlyREQs(t *testing.T) {
	h := &MembershipRequestHandler{}
	invite := []int{nip43.KindInviteRequest}
	cases := []struct {
		name    string
		filters *nip01.SubscriptionFilterGroup
		want    bool
	}{
		{"only 28935", inviteFilters(&nip01.SubscriptionFilter{Kinds: invite}), true},
		{"two filters, both 28935", inviteFilters(
			&nip01.SubscriptionFilter{Kinds: invite},
			&nip01.SubscriptionFilter{Kinds: invite},
		), true},
		{"28935 and kind 1 in one filter", inviteFilters(&nip01.SubscriptionFilter{Kinds: []int{nip43.KindInviteRequest, 1}}), false},
		{"28935 filter beside a kind 1 filter", inviteFilters(
			&nip01.SubscriptionFilter{Kinds: invite},
			&nip01.SubscriptionFilter{Kinds: []int{1}},
		), false},
		{"28935 filter beside a filter with no kinds", inviteFilters(
			&nip01.SubscriptionFilter{Kinds: invite},
			&nip01.SubscriptionFilter{Authors: []string{authTestPubKey}},
		), false},
		{"no filters", inviteFilters(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rp := &wire.RequestPacket{SubscriptionID: "sub", Filters: tc.filters}
			if got := h.CanHandle(rp); got != tc.want {
				t.Fatalf("CanHandle() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A REQ that names 28935 beside other kinds is an ordinary subscription:
// it must reach the standard handler, not be answered with an invite.
func TestMembershipRequestHandler_MixedREQNotHijacked(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)

	req := &wire.RequestPacket{SubscriptionID: "mixed", Filters: inviteFilters(
		&nip01.SubscriptionFilter{Kinds: []int{nip43.KindInviteRequest}},
		&nip01.SubscriptionFilter{Kinds: []int{1}},
	)}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	timeout := time.After(5 * time.Second)
	for done := false; !done; {
		select {
		case reply := <-sess.incoming:
			switch r := reply.(type) {
			case *wire.EventSubscriptionResponse:
				var ev nip01.Event
				if err := json.Unmarshal(r.EventBytes, &ev); err == nil && ev.Kind == nip43.KindInviteRequest {
					t.Fatal("a mixed REQ was answered with an invite response")
				}
			case *wire.ClosedSubscriptionResponse:
				t.Fatalf("a mixed REQ was closed: %q", r.Message)
			case *wire.EOSESubscriptionResponse:
				done = true
			}
		case <-timeout:
			t.Fatal("no EOSE for the mixed REQ")
		}
	}
	assertNoInviteClaims(t, sess)
}

func assertNoInviteClaims(t *testing.T, sess *Session) {
	t.Helper()
	claims, err := sess.store.ListInviteClaims()
	if err != nil {
		t.Fatalf("ListInviteClaims: %v", err)
	}
	if len(claims) != 0 {
		t.Fatalf("stored %d invite claims, want none", len(claims))
	}
}

type refusalRecorder struct {
	NopObserver
	mu      sync.Mutex
	reasons []RejectReason
}

func (o *refusalRecorder) ReadRefused(r RejectReason) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reasons = append(o.reasons, r)
}

func (o *refusalRecorder) got() []RejectReason {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]RejectReason(nil), o.reasons...)
}

// closedReply drains sess's replies to the first CLOSED and returns its
// reason, failing on any EVENT before it.
func closedReply(t *testing.T, sess *Session) string {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case reply := <-sess.incoming:
			switch r := reply.(type) {
			case *wire.ClosedSubscriptionResponse:
				return r.Message
			case *wire.EventSubscriptionResponse:
				t.Fatal("got an EVENT, want the request refused")
			}
		case <-timeout:
			t.Fatal("no CLOSED reply")
		}
	}
}

func TestMembershipRequestHandler_AuthorizerRefusesAuthenticated(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	obs := &refusalRecorder{}
	sess.config.Observer = obs
	sess.config.InviteRequestAuthorizer = func(context.Context, *Session) error {
		return errors.New("only operators may request invites")
	}

	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: inviteRequestFilter()}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	if got, want := closedReply(t, sess), "restricted: only operators may request invites"; got != want {
		t.Fatalf("CLOSED = %q, want %q", got, want)
	}
	assertNoInviteClaims(t, sess)
	if got := obs.got(); len(got) != 1 || got[0] != ReasonRestricted {
		t.Fatalf("observer ReadRefused = %v, want one %v", got, ReasonRestricted)
	}
}

func TestMembershipRequestHandler_AuthorizerRefusesUnauthenticated(t *testing.T) {
	store := newStore(t)
	cfg := defaultSessionConfig()
	cfg.PrivKey = authTestPrivKey
	obs := &refusalRecorder{}
	cfg.Observer = obs
	cfg.InviteRequestAuthorizer = func(_ context.Context, s *Session) error {
		if len(s.Identities()) == 0 {
			return errors.New("not authenticated")
		}
		return nil
	}
	sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{Self: authTestPubKey}, nil, nil, cfg)
	sc.membership = NewMembershipService(store)
	sess := &Session{SessionContext: sc}

	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: inviteRequestFilter()}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	if got := closedReply(t, sess); !strings.HasPrefix(got, "auth-required: ") {
		t.Fatalf("CLOSED = %q, want an auth-required: reason", got)
	}
	assertNoInviteClaims(t, sess)
	if got := obs.got(); len(got) != 1 || got[0] != ReasonAuthRequired {
		t.Fatalf("observer ReadRefused = %v, want one %v", got, ReasonAuthRequired)
	}
}

func TestMembershipRequestHandler_AuthorizerSeesEveryIdentity(t *testing.T) {
	const agent = "1111111111111111111111111111111111111111111111111111111111111111"
	sess := newMembershipEnabledTestSession(t)
	sess.addIdentity(AuthedIdentity{Pubkey: agent, Membership: MembershipVirtual, Owner: authTestPubKey})

	var seen []AuthedIdentity
	sess.config.InviteRequestAuthorizer = func(_ context.Context, s *Session) error {
		seen = s.Identities()
		for _, id := range seen {
			if id.Pubkey == agent && id.Membership == MembershipVirtual {
				return nil
			}
		}
		return errors.New("no agent identity")
	}

	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: inviteRequestFilter()}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	if _, ok := (<-sess.incoming).(*wire.EventSubscriptionResponse); !ok {
		t.Fatal("expected the invite response once the authorizer allows it")
	}
	if len(seen) != 2 || seen[0].Pubkey != authTestPubKey || seen[1].Pubkey != agent || seen[1].Owner != authTestPubKey {
		t.Fatalf("authorizer saw %+v, want the NIP-42 identity and the NIP-AA agent", seen)
	}
}

// Without an authorizer the handler keeps issuing codes as before, for
// embedders that have not set one yet.
func TestMembershipRequestHandler_NilAuthorizerIssues(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	if sess.config.InviteRequestAuthorizer != nil {
		t.Fatal("default config has an InviteRequestAuthorizer")
	}
	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: inviteRequestFilter()}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	if _, ok := (<-sess.incoming).(*wire.EventSubscriptionResponse); !ok {
		t.Fatal("expected an invite response with no authorizer set")
	}
	claims, err := sess.store.ListInviteClaims()
	if err != nil || len(claims) != 1 {
		t.Fatalf("ListInviteClaims = %d claims, %v; want 1", len(claims), err)
	}
}

func TestWithInviteRequestAuthorizer(t *testing.T) {
	cfg := defaultSessionConfig()
	called := false
	WithInviteRequestAuthorizer(func(context.Context, *Session) error { called = true; return nil })(cfg)
	if cfg.InviteRequestAuthorizer == nil {
		t.Fatal("option did not set InviteRequestAuthorizer")
	}
	_ = cfg.InviteRequestAuthorizer(context.Background(), nil)
	if !called {
		t.Fatal("stored authorizer is not the one passed")
	}
}
