package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAssertionsSession(t *testing.T) *Session {
	t.Helper()
	sess := newGroupsEnabledTestSession(t)
	sess.config.EnableProfileStats = true
	return sess
}

// assertionsReq sends a REQ for kind 30382 and returns the events up to
// EOSE, or the CLOSED message.
func assertionsReq(t *testing.T, sess *Session, filter *nip01.SubscriptionFilter) ([]*nip01.Event, string) {
	t.Helper()
	filter.Kinds = []int{KindUserAssertion}
	rp := &wire.RequestPacket{SubscriptionID: "a", Filters: nip01.NewSubscriptionFilterGroup(filter)}
	require.NoError(t, sess.processRequest(context.Background(), rp))
	var events []*nip01.Event
	for {
		switch r := nextReply(t, sess).(type) {
		case *wire.EventSubscriptionResponse:
			ev := r.Event
			if ev == nil {
				ev = &nip01.Event{}
				require.NoError(t, json.Unmarshal(r.EventBytes, ev))
			}
			events = append(events, ev)
		case *wire.EOSESubscriptionResponse:
			return events, ""
		case *wire.ClosedSubscriptionResponse:
			return events, r.Message
		default:
			t.Fatalf("unexpected reply %T", r)
		}
	}
}

func dTags(pubkeys ...string) map[string][]string { return map[string][]string{"d": pubkeys} }

func tagValue(ev *nip01.Event, name string) string {
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == name {
			return tag[1]
		}
	}
	return ""
}

func TestAssertions_ServesSignedStats(t *testing.T) {
	sess := newAssertionsSession(t)
	alice, bob, provider := newTestKey(t, 10), newTestKey(t, 11), newTestKey(t, 12)
	zap := zapReceipt(t, zapSpec{Sender: bob, Provider: provider, Recipient: alice.pub, Amount: 21_000, CreatedAt: 1_700_000_000})
	follow := &nip01.Event{PubKey: bob.pub, CreatedAt: 100, Kind: 3, Tags: [][]string{{"p", alice.pub}}}
	require.NoError(t, follow.Sign(bob.priv))
	InsertTestEvents(t, sess.store, []*nip01.Event{zap, follow})
	require.NoError(t, sess.store.UpdateProfileMetrics(alice.pub, func(m *ProfileMetrics) {
		m.BaseScore = 50
		m.Nip05 = CheckState{Value: "alice@example.com", Status: CheckOK}
	}))

	events, closed := assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(alice.pub, bob.pub)})
	require.Empty(t, closed)
	require.Len(t, events, 2)
	a := events[0]
	require.NoError(t, a.Verify())
	assert.Equal(t, KindUserAssertion, a.Kind)
	assert.Equal(t, authTestPubKey, a.PubKey)
	assert.Equal(t, alice.pub, tagValue(a, "d"))
	assert.Equal(t, "1", tagValue(a, "followers"))
	assert.Equal(t, "1", tagValue(a, "zap_cnt_recd"))
	assert.Equal(t, "21", tagValue(a, "zap_amt_recd"), "sats, not milli-sats")
	assert.Equal(t, "1700000000", tagValue(a, "zap_first_recd"))
	assert.Equal(t, "alice@example.com", tagValue(a, "nip05_verified"))
	assert.Equal(t, "", tagValue(a, "lud16_verified"))
	assert.Equal(t, "33", tagValue(a, "rank"), "score 100 of 300")

	b := events[1]
	assert.Equal(t, "1", tagValue(b, "following"))
	assert.Equal(t, "21", tagValue(b, "zap_amt_sent"))
}

func TestAssertions_StableIDUntilStatsChange(t *testing.T) {
	sess := newAssertionsSession(t)
	alice, bob := newTestKey(t, 40), newTestKey(t, 41)
	follow := func(at uint64, tags ...[]string) {
		ev := &nip01.Event{PubKey: bob.pub, CreatedAt: at, Kind: 3, Tags: tags}
		require.NoError(t, ev.Sign(bob.priv))
		InsertTestEvents(t, sess.store, []*nip01.Event{ev})
	}
	follow(100, []string{"p", alice.pub})

	first, _ := assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(alice.pub)})
	again, _ := assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(alice.pub)})
	require.Len(t, first, 1)
	require.Len(t, again, 1)
	assert.Equal(t, first[0].ID, again[0].ID)

	follow(200, []string{"p", alice.pub}, []string{"p", bob.pub})
	follow(300) // bob unfollows everyone
	changed, _ := assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(alice.pub)})
	require.Len(t, changed, 1)
	assert.NotEqual(t, first[0].ID, changed[0].ID)
	assert.Greater(t, changed[0].CreatedAt, first[0].CreatedAt)
	assert.Equal(t, "0", tagValue(changed[0], "followers"))
}

func TestAssertions_Limits(t *testing.T) {
	sess := newAssertionsSession(t)

	_, closed := assertionsReq(t, sess, &nip01.SubscriptionFilter{})
	assert.Contains(t, closed, "restricted:")

	sess.config.MaxStatsTargets = 2
	var many []string
	for i := 0; i < 3; i++ {
		many = append(many, fmt.Sprintf("%064x", i+1))
	}
	_, closed = assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(many...)})
	assert.Contains(t, closed, "invalid:")

	events, closed := assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(newTestKey(t, 77).pub)})
	assert.Empty(t, closed)
	assert.Empty(t, events, "an unknown profile has no assertion")
}

func TestAssertions_OtherProvidersAndDisabledFallThrough(t *testing.T) {
	sess := newAssertionsSession(t)
	other := newTestKey(t, 60)
	target := newTestKey(t, 61).pub
	stored := &nip01.Event{PubKey: other.pub, CreatedAt: 100, Kind: KindUserAssertion, Tags: [][]string{{"d", target}, {"rank", "90"}}}
	require.NoError(t, stored.Sign(other.priv))
	InsertTestEvents(t, sess.store, []*nip01.Event{stored})

	events, _ := assertionsReq(t, sess, &nip01.SubscriptionFilter{Authors: []string{other.pub}, Tags: dTags(target)})
	require.Len(t, events, 1, "another provider's stored assertion is served as stored")
	assert.Equal(t, stored.ID, events[0].ID)

	sess.config.EnableProfileStats = false
	events, _ = assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(target)})
	require.Len(t, events, 1)
	assert.Equal(t, stored.ID, events[0].ID)
}

// A REQ that also asks for other kinds (as `ncli profile` does) gets the
// assertions and the stored events, then one EOSE.
func TestAssertions_MixedREQ(t *testing.T) {
	sess := newAssertionsSession(t)
	alice := newTestKey(t, 70)
	profile := &nip01.Event{PubKey: alice.pub, CreatedAt: 100, Kind: 0, Content: `{"name":"alice"}`}
	require.NoError(t, profile.Sign(alice.priv))
	InsertTestEvents(t, sess.store, []*nip01.Event{profile})
	require.NoError(t, sess.store.UpdateProfileMetrics(alice.pub, func(m *ProfileMetrics) { m.BaseScore = 10 }))

	rp := &wire.RequestPacket{SubscriptionID: "m", Filters: nip01.NewSubscriptionFilterGroup(
		&nip01.SubscriptionFilter{Kinds: []int{0}, Authors: []string{alice.pub}},
		&nip01.SubscriptionFilter{Kinds: []int{KindUserAssertion}, Tags: dTags(alice.pub)},
	)}
	require.NoError(t, sess.processRequest(context.Background(), rp))

	kinds := map[int]int{}
	for done := false; !done; {
		switch r := nextReply(t, sess).(type) {
		case *wire.EventSubscriptionResponse:
			ev := r.Event
			if ev == nil {
				ev = &nip01.Event{}
				require.NoError(t, json.Unmarshal(r.EventBytes, ev))
			}
			kinds[ev.Kind]++
		case *wire.EOSESubscriptionResponse:
			done = true
		default:
			t.Fatalf("unexpected reply %T", r)
		}
	}
	assert.Equal(t, map[int]int{0: 1, KindUserAssertion: 1}, kinds)
}
