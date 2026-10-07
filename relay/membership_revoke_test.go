package relay

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip43"
)

// A removal reaches sessions that authenticated before it: membership is
// cached per session at AUTH, so without revocation a removed member kept
// reading and writing on the connection it already had.
func TestMembershipRemoval_RevokesLiveSessions(t *testing.T) {
	member := strings.Repeat("a1", 32)
	agent := strings.Repeat("b2", 32)
	other := strings.Repeat("c3", 32)

	setup := func(t *testing.T) (*SessionHandler, *Session, *Session) {
		t.Helper()
		store := newStore(t)
		meta := &nip11.Metadata{Limitation: nip11.Limitation{MembershipRequired: true}}
		sh := NewSessionHandler(store, meta, nil)
		direct := &Session{SessionContext: NewSessionContext(store, &ClientInfo{}, meta, nil, nil, nil)}
		direct.addIdentity(AuthedIdentity{Pubkey: member, Membership: MembershipActive})
		virtual := &Session{SessionContext: NewSessionContext(store, &ClientInfo{}, meta, nil, nil, nil)}
		virtual.addIdentity(AuthedIdentity{Pubkey: agent, Membership: MembershipVirtual, Owner: member})
		sh.sessions.Store(int64(1), direct)
		sh.sessions.Store(int64(2), virtual)
		for _, pk := range []string{member, other} {
			if err := sh.membership.Join(pk, nil); err != nil {
				t.Fatal(err)
			}
		}
		return sh, direct, virtual
	}

	t.Run("Leave", func(t *testing.T) {
		sh, direct, virtual := setup(t)
		if err := sh.membership.Leave(member); err != nil {
			t.Fatal(err)
		}
		if direct.HasMembership() {
			t.Error("removed member's live session still has membership")
		}
		// NIP-AA: virtual membership is checked per connection, not
		// expired mid-session.
		if !virtual.HasMembership() {
			t.Error("virtual identity revoked mid-session")
		}
	})

	t.Run("ReplaceFromEvent drops a member", func(t *testing.T) {
		sh, direct, _ := setup(t)
		list := nip43.NewMembershipList(nip43.MembershipListParams{
			SelfPubkey: authTestPubKey,
			Members:    []nip43.Member{{Pubkey: other}},
		})
		if err := sh.membership.ReplaceFromEvent(list); err != nil {
			t.Fatal(err)
		}
		if direct.HasMembership() {
			t.Error("member dropped by a replacement list keeps membership on its live session")
		}
	})

	t.Run("unrelated removal leaves the session alone", func(t *testing.T) {
		sh, direct, _ := setup(t)
		if err := sh.membership.Leave(other); err != nil {
			t.Fatal(err)
		}
		if !direct.HasMembership() {
			t.Error("removing another pubkey revoked this session")
		}
	})
}
