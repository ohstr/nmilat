package client

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

func isRequest(ev *nip01.Event) bool { return ev.Kind == transport.KindPrivateRequest }

// NIP-CASH §Multiple Relay Hints: a relay that accepts the request but never answers, as one the Hub no longer
// reads, is followed by the next relay; the first that answers serves the request. A relay that answers is the only
// one contacted.
func TestBatchSession_SilentRelayFailsOverToTheNext(t *testing.T) {
	ctx, cancel := e2eContext(t)
	defer cancel()
	for _, c := range []struct {
		name           string
		muteFirst      bool
		wantOnSecond   int
		wantOnFirst    int
		answeredWithin time.Duration
	}{
		{"the first relay is silent", true, 1, 1, 5 * time.Second},
		{"the first relay answers", false, 0, 1, 5 * time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			first, second := cashtest.NewRelay(t), cashtest.NewRelay(t)
			if c.muteFirst {
				first.Mute(isRequest)
			}
			hub := cashtest.NewFakeHub(t, cashtest.WithRelays(first, second),
				cashtest.WithDecide(func(ic cashtest.ItemCtx) *transport.Result { return alwaysSucceed(ic.Item) }))
			s, err := OpenBatchSession(ctx, hub.NodeXOnly(), []string{first.URL()}, WithRelayAnswerWait(300*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			priv, target := sessionKeypair(t)
			start := time.Now()
			out, err := s.StatusMany(ctx, []BatchStatus{{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)}})
			if err != nil || len(out) != 1 || out[0].State != OutcomeResult {
				t.Fatalf("StatusMany = %+v, %v", out, err)
			}
			if d := time.Since(start); d > c.answeredWithin {
				t.Errorf("answered after %v", d)
			}
			if n := len(requestsOn(first)); n != c.wantOnFirst {
				t.Errorf("%d requests on the first relay, want %d", n, c.wantOnFirst)
			}
			if n := len(requestsOn(second)); n != c.wantOnSecond {
				t.Errorf("%d requests on the second relay, want %d", n, c.wantOnSecond)
			}
		})
	}
}

// Every relay silent: the request goes to each in turn, and the call ends unanswered at not_after, never before a
// listed relay was tried.
func TestBatchSession_EveryRelaySilentTriesEachOnce(t *testing.T) {
	ctx, cancel := e2eContext(t)
	defer cancel()
	relays := []*cashtest.Relay{cashtest.NewRelay(t), cashtest.NewRelay(t), cashtest.NewRelay(t)}
	for _, r := range relays {
		r.Mute(isRequest)
	}
	hub := cashtest.NewFakeHub(t, cashtest.WithRelays(relays...),
		cashtest.WithDecide(func(ic cashtest.ItemCtx) *transport.Result { return alwaysSucceed(ic.Item) }))
	s, err := OpenBatchSession(ctx, hub.NodeXOnly(), []string{relays[0].URL()}, WithRelayAnswerWait(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	priv, target := sessionKeypair(t)
	short, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	out, _ := s.StatusMany(short, []BatchStatus{{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)}})
	if len(out) != 1 || out[0].State == OutcomeResult {
		t.Fatalf("outcomes = %+v, want the item unanswered", out)
	}
	for i, r := range relays {
		if n := len(requestsOn(r)); n != 1 {
			t.Errorf("relay %d took %d requests, want 1", i, n)
		}
	}
}

// Without WithRelayAnswerWait, the time left until not_after is shared between the relay just sent to and every
// untried one, never below a second; a fixed wait is used as set.
func TestRelayAnswerWait(t *testing.T) {
	in := func(s int64) int64 { return time.Now().Unix() + s }
	near := func(got, want time.Duration) bool { return got <= want && got > want-1500*time.Millisecond }
	if got := relayAnswerWait(0, in(60), 1); !near(got, 30*time.Second) {
		t.Errorf("60 s, one untried: %v", got)
	}
	if got := relayAnswerWait(0, in(60), 2); !near(got, 20*time.Second) {
		t.Errorf("60 s, two untried: %v", got)
	}
	if got := relayAnswerWait(0, in(1), 3); got != minRelayAnswerWait {
		t.Errorf("1 s, three untried: %v, want the floor", got)
	}
	if got := relayAnswerWait(0, in(-5), 1); got != minRelayAnswerWait {
		t.Errorf("past not_after: %v, want the floor", got)
	}
	if got := relayAnswerWait(250*time.Millisecond, in(60), 1); got != 250*time.Millisecond {
		t.Errorf("fixed: %v", got)
	}
}
