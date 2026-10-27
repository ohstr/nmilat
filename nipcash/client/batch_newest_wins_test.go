package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// E-ENV-03.
// NIP-CASH §The Hub Announcement: a client MUST prefer the newest announcement and
// never adopt an older one. Served newest-first, so last-arrival-wins would adopt
// the retired inbox; the existing tests serve oldest-first and could not tell.
func TestNewBatchSession_NewestAnnouncementWinsWhenServedFirst(t *testing.T) {
	hubPriv, hubXOnly := sessionKeypair(t)
	_, retiredInbox := sessionKeypair(t)
	_, currentInbox := sessionKeypair(t)
	old := datedAnnouncement(t, hubPriv, hubXOnly, retiredInbox, time.Now().Add(-90*24*time.Hour))
	cur := datedAnnouncement(t, hubPriv, hubXOnly, currentInbox, time.Now())
	relay := newAnnouncementRelay(t, func() []*nip01.Event { return []*nip01.Event{cur, old} })

	s, err := (&Client{}).NewBatchSession(context.Background(), hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("NewBatchSession: %v", err)
	}
	if s.Inbox() != currentInbox {
		t.Errorf("adopted inbox %q, want the newest %q", s.Inbox(), currentInbox)
	}
}

func chunkRuleSetup(t *testing.T) (packedEnvelope, [32]byte, *BatchSession, transport.Limits, string) {
	t.Helper()
	limits := transport.DefaultLimits()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	p := statusPacked(nonce, time.Now().Add(3*time.Second).Unix(), "a", "b", "c")
	var k [32]byte
	copy(k[:], strings.Repeat("g", 32))
	return p, k, hostileSession(limits, strings.Repeat("b", 64)), limits, nonce
}
