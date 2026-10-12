package relay

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/wire"
)

// rankedSearch answers every search REQ itself with a fixed, ranked list.
type rankedSearch struct {
	results []*nip01.Event
}

func (h *rankedSearch) CanHandle(rp *wire.RequestPacket) bool { return rp.Filters.HasSearch() }

func (h *rankedSearch) Handle(_ context.Context, s *Session, rp *wire.RequestPacket) (bool, error) {
	s.SendEvents(rp.SubscriptionID, h.results)
	s.SendEOSE(rp.SubscriptionID)
	return true, nil
}

// observer sees every REQ and leaves it to the next handler.
type observer struct {
	seen []string
}

func (h *observer) CanHandle(*wire.RequestPacket) bool { return true }

func (h *observer) Handle(_ context.Context, _ *Session, rp *wire.RequestPacket) (bool, error) {
	h.seen = append(h.seen, rp.SubscriptionID)
	return false, nil
}

func signedNote(t *testing.T, content string, createdAt uint64, tags ...[]string) *nip01.Event {
	t.Helper()
	ev := nip01.NewEvent(1, content)
	ev.CreatedAt = createdAt
	ev.Tags = tags
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatal(err)
	}
	return ev
}

func searchREQ(subID string) *wire.RequestPacket {
	return &wire.RequestPacket{
		SubscriptionID: subID,
		Filters:        nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Search: "bitcoin"}),
	}
}

// nextReply returns the session's next outgoing message.
func nextReply(t *testing.T, sess *Session) wire.SubscriptionResponse {
	t.Helper()
	select {
	case r := <-sess.incoming:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("no reply")
		return nil
	}
}

// expectEvents reads EVENTs under subID up to its EOSE and returns their ids.
func expectEvents(t *testing.T, sess *Session, subID string) []string {
	t.Helper()
	var ids []string
	for {
		switch r := nextReply(t, sess).(type) {
		case *wire.EventSubscriptionResponse:
			if r.SubscriptionID != subID {
				t.Fatalf("EVENT for %q, want %q", r.SubscriptionID, subID)
			}
			ids = append(ids, r.Event.ID)
		case *wire.EOSESubscriptionResponse:
			return ids
		default:
			t.Fatalf("unexpected reply %T %+v", r, r)
		}
	}
}

// A handler from WithRequestHandler answers a search REQ ahead of the
// built-in NIP-50 handler, which would refuse it with no search service,
// and its order reaches the client unchanged, oldest first here.
func TestRequestHandler_AnswersInItsOwnOrder(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	older := signedNote(t, "older", 1000)
	newer := signedNote(t, "newer", 2000)
	WithRequestHandler(&rankedSearch{results: []*nip01.Event{older, newer}})(sess.config)

	if err := sess.processRequest(context.Background(), searchREQ("s")); err != nil {
		t.Fatal(err)
	}
	got := expectEvents(t, sess, "s")
	if len(got) != 2 || got[0] != older.ID || got[1] != newer.ID {
		t.Fatalf("got %v, want [older newer]", got)
	}
}

// A handler that returns false leaves the REQ to the built-in chain.
func TestRequestHandler_PassesThrough(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	obs := &observer{}
	sess.config.RequestHandlers = []RequestHandler{obs}

	rp := &wire.RequestPacket{
		SubscriptionID: "plain",
		Filters:        nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}}),
	}
	if err := sess.processRequest(context.Background(), rp); err != nil {
		t.Fatal(err)
	}
	if got := expectEvents(t, sess, "plain"); len(got) != 0 {
		t.Fatalf("got %v from an empty store", got)
	}
	if len(obs.seen) != 1 || obs.seen[0] != "plain" {
		t.Fatalf("observer saw %v", obs.seen)
	}
	if _, open := sess.subscriptions.Get("plain"); !open {
		t.Fatal("the built-in handler opened no subscription")
	}
}

// SendEvents replaces an open subscription under the same id, and withholds
// an event from a private NIP-29 group the session can't read.
func TestSendEvents_ReplacesSubAndHidesPrivateGroups(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	if resp := sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA)); !resp.Accepted {
		t.Fatalf("create group: %s", resp.Message)
	}
	if !sess.groups.IsPrivate(groupA) {
		t.Fatal("a new group should be private")
	}

	live := &wire.RequestPacket{
		SubscriptionID: "s",
		Filters:        nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}}),
	}
	if err := sess.processRequest(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	expectEvents(t, sess, "s")

	public := signedNote(t, "public", 1000)
	private := signedNote(t, "private", 1000, []string{"h", groupA})
	sess.SendEvents("s", []*nip01.Event{private, public})
	sess.SendEOSE("s")

	if got := expectEvents(t, sess, "s"); len(got) != 1 || got[0] != public.ID {
		t.Fatalf("got %v, want only the public note", got)
	}
	if _, open := sess.subscriptions.Get("s"); open {
		t.Fatal("the live subscription is still open")
	}
}
