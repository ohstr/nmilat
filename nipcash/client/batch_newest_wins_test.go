package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
)

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
	p := packedEnvelope{
		Envelope: transport.Envelope{Version: transport.EnvelopeVersion, Nonce: nonce,
			NotAfter: time.Now().Add(3 * time.Second).Unix()},
		ItemIDs: []string{"a", "b", "c"},
	}
	var k [32]byte
	copy(k[:], strings.Repeat("g", 32))
	return p, k, hostileSession(limits, strings.Repeat("b", 64)), limits, nonce
}

// §Chunked Replies: a client MUST reject a set whose members disagree about total.
func TestCollectReply_ChunksDisagreeingAboutTotalAreRejected(t *testing.T) {
	p, k, s, limits, nonce := chunkRuleSetup(t)
	ch := make(chan *nip01.Event, 2)
	ch <- sealChunk(t, k, limits, transport.ResponseEnvelope{Version: transport.EnvelopeVersion, ReqNonce: nonce,
		Seq: 1, Total: 2, Results: []transport.Result{{ID: "a", Result: []byte(`{}`)}}})
	ch <- sealChunk(t, k, limits, transport.ResponseEnvelope{Version: transport.EnvelopeVersion, ReqNonce: nonce,
		Seq: 2, Total: 3, Results: []transport.Result{{ID: "b", Result: []byte(`{}`)}}})
	got, err := s.collectReply(context.Background(), ch, k, p, 0)
	if err == nil || !strings.Contains(err.Error(), "an earlier one claimed") {
		t.Errorf("total 2 then total 3 was not rejected: outcomes=%d err=%v", len(got), err)
	}
}

// §Chunked Replies: a client MUST reject a repeated seq, not count it toward completion.
func TestCollectReply_RepeatedSeqIsRejected(t *testing.T) {
	p, k, s, limits, nonce := chunkRuleSetup(t)
	ch := make(chan *nip01.Event, 2)
	ch <- sealChunk(t, k, limits, transport.ResponseEnvelope{Version: transport.EnvelopeVersion, ReqNonce: nonce,
		Seq: 1, Total: 2, Results: []transport.Result{{ID: "a", Result: []byte(`{}`)}}})
	ch <- sealChunk(t, k, limits, transport.ResponseEnvelope{Version: transport.EnvelopeVersion, ReqNonce: nonce,
		Seq: 1, Total: 2, Results: []transport.Result{{ID: "b", Result: []byte(`{}`)}}})
	got, err := s.collectReply(context.Background(), ch, k, p, 0)
	if err == nil || !strings.Contains(err.Error(), "repeated chunk") {
		t.Errorf("seq 1 twice was not rejected: outcomes=%d err=%v", len(got), err)
	}
}
