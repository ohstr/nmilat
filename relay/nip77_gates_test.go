package relay

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/nip77"
	"github.com/ohstr/nmilat/wire"
)

// negReader returns a session on sess's store and groups, with limitation,
// authenticated as pk unless pk is "".
func negReader(t *testing.T, sess *Session, limitation nip11.Limitation, pk string) *Session {
	t.Helper()
	r := &Session{
		SessionContext:     NewSessionContext(sess.store, &ClientInfo{}, &nip11.Metadata{Self: authTestPubKey, Limitation: limitation}, nil, nil, sess.config),
		negentropySessions: map[string]*nip77.Negentropy{},
	}
	r.groups = sess.groups
	if pk != "" {
		r.addIdentity(AuthedIdentity{Pubkey: pk, Membership: MembershipNone})
	}
	return r
}

// negOpen sends a NEG-OPEN for filter and returns the number of items in
// the reader's set, or the NEG-ERR it got.
func negOpen(t *testing.T, r *Session, filter *nip01.SubscriptionFilter) (items int, negErr string) {
	t.Helper()
	empty, err := (&nip77.Message{ProtocolVersion: nip77.ProtocolVersion1}).ToHex()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.processNegOpen(context.Background(), &wire.NegOpenPacket{SubscriptionID: "n", Filter: filter, Message: empty}); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-r.incoming:
		if e, ok := resp.(*wire.NegErrPacket); ok {
			return 0, e.Code
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer to NEG-OPEN")
	}
	r.negMu.Lock()
	defer r.negMu.Unlock()
	return len(r.negentropySessions["n"].Items), ""
}

// NEG-OPEN passes the same connection-level read gate as REQ.
func TestNegOpen_ReadGate(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	InsertTestEvents(t, sess.store, []*nip01.Event{roSigned(t, 1, strangerPrivKey)})
	f := &nip01.SubscriptionFilter{Kinds: []int{1}}

	for _, lim := range []nip11.Limitation{{AuthRequired: true}, {MembershipRequired: true}} {
		if _, code := negOpen(t, negReader(t, sess, lim, ""), f); !strings.HasPrefix(code, "auth-required:") {
			t.Fatalf("%+v, unauthenticated: NEG-ERR %q, want auth-required:", lim, code)
		}
	}
	if _, code := negOpen(t, negReader(t, sess, nip11.Limitation{MembershipRequired: true}, memberA), f); !strings.HasPrefix(code, "restricted:") {
		t.Fatalf("membership_required, authenticated non-member: NEG-ERR %q, want restricted:", code)
	}
	if n, code := negOpen(t, negReader(t, sess, nip11.Limitation{AuthRequired: true}, memberA), f); code != "" || n != 1 {
		t.Fatalf("auth_required, authenticated: %d items, NEG-ERR %q", n, code)
	}
}

// A non-member's negentropy set leaves out a private group's events, and
// naming the group is refused as REQ refuses it.
func TestNegOpen_PrivateGroups(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	if !sess.groups.IsPrivate(groupA) {
		t.Fatal("precondition: a new group is private")
	}
	InsertTestEvents(t, sess.store, []*nip01.Event{roSigned(t, 9, authTestPrivKey, []string{"h", groupA})})

	content := &nip01.SubscriptionFilter{Kinds: []int{9}}
	metadata := &nip01.SubscriptionFilter{Kinds: []int{nip29.KindGroupMetadata, nip29.KindGroupMembers}}
	for _, c := range []struct {
		name string
		pk   string
		want int
	}{{"anonymous", "", 0}, {"non-member", memberA, 0}, {"member", authTestPubKey, 1}} {
		r := negReader(t, sess, nip11.Limitation{}, c.pk)
		if n, code := negOpen(t, r, content); code != "" || n != c.want {
			t.Errorf("%s, group content: %d items, NEG-ERR %q; want %d", c.name, n, code, c.want)
		}
		if n, code := negOpen(t, r, metadata); code != "" || n != 2*c.want {
			t.Errorf("%s, group metadata: %d items, NEG-ERR %q; want %d", c.name, n, code, 2*c.want)
		}
	}

	byGroup := &nip01.SubscriptionFilter{Tags: map[string][]string{"h": {groupA}}}
	if _, code := negOpen(t, negReader(t, sess, nip11.Limitation{}, ""), byGroup); !strings.HasPrefix(code, "auth-required:") {
		t.Fatalf("anonymous #h: NEG-ERR %q, want auth-required:", code)
	}
	if _, code := negOpen(t, negReader(t, sess, nip11.Limitation{}, memberA), byGroup); !strings.HasPrefix(code, "restricted:") {
		t.Fatalf("non-member #h: NEG-ERR %q, want restricted:", code)
	}
}

// A recipient-only kind's ids are in the recipient's set only.
func TestNegOpen_RecipientOnlyKinds(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sess.config.RecipientOnlyKinds = []int{1059}
	recipient := pubOf(t, recipientPrivKey)
	InsertTestEvents(t, sess.store, []*nip01.Event{roSigned(t, 1059, wrapperPrivKey, []string{"p", recipient})})

	f := &nip01.SubscriptionFilter{Kinds: []int{1059}}
	if _, code := negOpen(t, negReader(t, sess, nip11.Limitation{}, ""), f); !strings.HasPrefix(code, "auth-required:") {
		t.Fatalf("anonymous: NEG-ERR %q, want auth-required:", code)
	}
	if n, code := negOpen(t, negReader(t, sess, nip11.Limitation{}, pubOf(t, strangerPrivKey)), f); code != "" || n != 0 {
		t.Fatalf("stranger: %d items, NEG-ERR %q", n, code)
	}
	if n, code := negOpen(t, negReader(t, sess, nip11.Limitation{}, recipient), f); code != "" || n != 1 {
		t.Fatalf("recipient: %d items, NEG-ERR %q", n, code)
	}
	// Asking by author names no kind, so it is not refused, but the wrap
	// still stays out of a stranger's set.
	byAuthor := &nip01.SubscriptionFilter{Authors: []string{pubOf(t, wrapperPrivKey)}}
	if n, code := negOpen(t, negReader(t, sess, nip11.Limitation{}, ""), byAuthor); code != "" || n != 0 {
		t.Fatalf("anonymous by author: %d items, NEG-ERR %q", n, code)
	}
}
