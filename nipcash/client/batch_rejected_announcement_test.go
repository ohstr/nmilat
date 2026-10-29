package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// rejectableAnnouncement is a validly signed kind 11190 at created_at at that a client must reject: its
// pad_bucket_bytes is below the 2048 floor.
func rejectableAnnouncement(t *testing.T, hubPriv, hubXOnly, inbox string, at time.Time) *nip01.Event {
	t.Helper()
	ev := datedAnnouncement(t, hubPriv, hubXOnly, inbox, at)
	for _, tag := range ev.Tags {
		if len(tag) == 3 && tag[0] == "limit" && tag[1] == "pad_bucket_bytes" {
			tag[2] = "1024"
		}
	}
	if err := ev.Sign(hubPriv); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ParseAnnouncement(ev, hubXOnly); err == nil {
		t.Fatal("the announcement must be one a client rejects")
	}
	return ev
}

// NIP-CASH §The Hub Announcement: when the newest announcement is rejected the Hub is unusable until a valid newer
// one is seen, and the client never falls back to an older one, neither the one it held nor one served again later.
func TestRefresh_RejectedNewestAnnouncementDropsTheOlderOne(t *testing.T) {
	hubPriv, hubXOnly := sessionKeypair(t)
	_, oldInbox := sessionKeypair(t)
	_, badInbox := sessionKeypair(t)
	_, newInbox := sessionKeypair(t)
	now := time.Now()
	cur := datedAnnouncement(t, hubPriv, hubXOnly, oldInbox, now.Add(-time.Hour))
	bad := rejectableAnnouncement(t, hubPriv, hubXOnly, badInbox, now.Add(-time.Minute))
	var mu sync.Mutex
	serving := []*nip01.Event{cur}
	serve := func(evs ...*nip01.Event) { mu.Lock(); serving = evs; mu.Unlock() }
	relay := newAnnouncementRelay(t, func() []*nip01.Event { mu.Lock(); defer mu.Unlock(); return serving })
	ctx := context.Background()
	s, err := (&Client{}).NewBatchSession(ctx, hubXOnly, []string{relay})
	if err != nil || s.Inbox() != oldInbox {
		t.Fatalf("setup: %v %q", err, s.Inbox())
	}

	serve(bad, cur)
	if err := s.Refresh(ctx); !errors.Is(err, ErrHubUnusable) {
		t.Fatalf("Refresh() = %v, want ErrHubUnusable", err)
	}
	if s.Inbox() != "" || s.Limits() != (transport.Limits{}) || s.MaxRequestAge() != 0 {
		t.Fatalf("the older announcement is still in use: inbox %q, limits %+v", s.Inbox(), s.Limits())
	}
	serve(cur)
	if err := s.Refresh(ctx); !errors.Is(err, ErrHubUnusable) || s.Inbox() != "" {
		t.Fatalf("an older announcement served alone was adopted: %v, inbox %q", err, s.Inbox())
	}
	serve(bad)
	if err := s.Refresh(ctx); !errors.Is(err, ErrHubUnusable) || s.Inbox() != "" {
		t.Fatalf("the rejected announcement again: %v, inbox %q", err, s.Inbox())
	}

	// A valid newer announcement makes the Hub usable again, one second after the rejected one included.
	serve(datedAnnouncement(t, hubPriv, hubXOnly, newInbox, now.Add(-time.Minute+time.Second)), bad, cur)
	if err := s.Refresh(ctx); err != nil || s.Inbox() != newInbox {
		t.Fatalf("a valid newer announcement: %v, inbox %q, want %q", err, s.Inbox(), newInbox)
	}
}

// No call of any kind reaches the Hub while its newest announcement is rejected: reads and a bearer cash_redeem
// carry no request_id, and still must not go to the older inbox. A valid newer announcement lets them through again.
func TestBatchSession_RejectedNewestAnnouncementRefusesEveryCall(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	s, relay := openTestSession(t, hub)
	ctx, cancel := e2eContext(t)
	defer cancel()
	priv, target := sessionKeypair(t)
	status := func() error {
		_, err := s.StatusMany(ctx, []BatchStatus{{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)}})
		return err
	}
	redeem := func() error {
		_, err := s.RedeemMany(ctx, []BatchRedeem{{Bill: mustBill(t, target),
			Params: nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: nipcash.BySecret("aa")}}})
		return err
	}
	if err := status(); err != nil {
		t.Fatalf("before: StatusMany: %v", err)
	}
	sent := len(requestsOn(relay))

	if ok, msg := relay.Publish(rejectableAnnouncement(t, hub.hubPriv, hub.hubXOnly, hub.inboxXOnly, time.Now().Add(2*time.Second))); !ok {
		t.Fatalf("publish: %s", msg)
	}
	if err := s.Refresh(ctx); !errors.Is(err, ErrHubUnusable) {
		t.Fatalf("Refresh() = %v, want ErrHubUnusable", err)
	}
	for name, call := range map[string]func() error{"cash_status": status, "bearer cash_redeem": redeem} {
		if err := call(); !errors.Is(err, ErrHubUnusable) {
			t.Errorf("%s: %v, want ErrHubUnusable", name, err)
		}
	}
	if n := len(requestsOn(relay)); n != sent {
		t.Fatalf("%d requests published while the Hub was unusable", n-sent)
	}

	if ok, msg := relay.Publish(datedAnnouncement(t, hub.hubPriv, hub.hubXOnly, hub.inboxXOnly, time.Now().Add(3*time.Second))); !ok {
		t.Fatalf("publish: %s", msg)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatalf("Refresh() with a valid newer announcement: %v", err)
	}
	if err := status(); err != nil {
		t.Fatalf("after: StatusMany: %v", err)
	}
}
