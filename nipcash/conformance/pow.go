package conformance

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// powCases are the proof-of-work cases (NIP-CASH §Proof of Work), run against
// a Hub whose inbox relay enforces a minimum.
var powCases = []ctCase{
	{id: "CT-POW-01", needs: []need{needPow}, run: ctPow01},
	{id: "CT-POW-02", needs: []need{needPow}, run: ctPow02},
	{id: "CT-POW-03", needs: []need{needPow}, run: ctPow03},
}

// powOn sets the Hub's relay minimum for one case and clears it afterwards.
func powOn(t *testing.T, s *suite, difficulty int) (PowRelay, string) {
	t.Helper()
	p := s.h.(PowRelay)
	p.SetMinPow(t, difficulty)
	t.Cleanup(func() { p.SetMinPow(t, 0) })
	return p, p.RelayURL()
}

// offer publishes ev to relay and returns the relay's verdict.
func offer(t *testing.T, relay string, ev *nip01.Event) (bool, string) {
	t.Helper()
	u, err := url.Parse(relay)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ok, err := relayclient.PublishEventToRelay(ctx, u, ev)
	if err != nil {
		t.Fatalf("publish to %s: %v", relay, err)
	}
	return ok.Accepted, ok.Message
}

// minedRequest is an envelope refused at E4 (no items), wrapped and mined: a
// Hub that ran it answers one envelope-level BAD_REQUEST.
func (s *suite) minedRequest(t *testing.T, difficulty int) (request, *transport.PowRequest) {
	t.Helper()
	e, _, _, notAfter := s.newEnvelope(t)
	e["items"] = []transport.Item{}
	plaintext, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pr, key, err := transport.WrapRequestPow(ctx, plaintext, s.inbox, notAfter, difficulty)
	if err != nil {
		t.Fatalf("mine: %v", err)
	}
	r := request{ev: pr.Event}
	r.replyTo, _ = e["reply_to"].(string)
	r.nonce, _ = e["nonce"].(string)
	if k, err := transport.DeriveReplyKey(key, r.replyTo); err == nil {
		r.replyKey = k
	}
	return r, pr
}

// CT-POW-01 (CASH-POW-02): the relay's NIP-11 minimum is read; an unmined
// request is refused "pow: …"; a mined one is accepted and the Hub runs it.
func ctPow01(t *testing.T, s *suite) {
	_, relay := powOn(t, s, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if n, err := transport.RelayPowMinimum(ctx, relay); err != nil || n != 8 {
		t.Fatalf("NIP-11 min_pow_difficulty = %d (%v), want 8", n, err)
	}

	e, _, _, _ := s.newEnvelope(t)
	e["items"] = []transport.Item{}
	raw := s.wrap(t, e, "")
	if ok, msg := offer(t, relay, raw.ev); ok || !strings.HasPrefix(msg, "pow:") {
		t.Fatalf("an unmined request: accepted %v, %q; want refused pow:", ok, msg)
	}

	r, _ := s.minedRequest(t, 8)
	l := s.listen(t, r.replyTo)
	if ok, msg := offer(t, relay, r.ev); !ok {
		t.Fatalf("a mined request was refused: %s", msg)
	}
	got := l.wait(1, s.quiet())
	if len(got) != 1 {
		t.Fatalf("%d replies to a mined request, want 1", len(got))
	}
	if code := envelopeErrorCode(t, r.open(t, got[0].ev)); code != "BAD_REQUEST" {
		t.Fatalf("envelope error %q, want BAD_REQUEST (E4 ran)", code)
	}
}

// CT-POW-02 (CASH-POW-03, K-POW-2): after a raised minimum the relay refuses
// "pow: difficulty N required"; the same request re-mined to N is accepted and
// the Hub answers it once.
func ctPow02(t *testing.T, s *suite) {
	_, relay := powOn(t, s, 10)
	r, pr := s.minedRequest(t, 4)
	ok, msg := offer(t, relay, r.ev)
	if ok {
		t.Skip("the request met the raised minimum by chance")
	}
	n, isPow := transport.ParsePowRejection(msg)
	if !isPow || n != 10 {
		t.Fatalf("refusal %q, want pow: difficulty 10 required", msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := pr.Remine(ctx, n); err != nil {
		t.Fatal(err)
	}
	l := s.listen(t, r.replyTo)
	if ok, msg := offer(t, relay, pr.Event); !ok {
		t.Fatalf("the re-mined request was refused: %s", msg)
	}
	if got := l.wait(2, s.quiet()); len(distinct(got)) != 1 {
		t.Fatalf("%d replies, want 1", len(distinct(got)))
	}
}

// CT-POW-03 (CASH-POW-04, K-POW-4): the relay refuses a 23190 without
// expiration, with one past or more than one day ahead, accepts one exactly a
// day ahead, and drops a repeat of an id it accepted.
func ctPow03(t *testing.T, s *suite) {
	_, relay := powOn(t, s, 4)
	priv, pub := keypair(t)
	now := time.Now().Unix()
	mined := func(exp int64) *nip01.Event {
		ev := nip01.NewEvent(transport.KindPrivateRequest, "x")
		ev.PubKey = pub
		ev.Tags = append(ev.Tags, []string{"p", s.inbox})
		if exp != 0 {
			ev.Tags = append(ev.Tags, []string{"expiration", strconv.FormatInt(exp, 10)})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := ev.Mine(ctx, 4); err != nil {
			t.Fatal(err)
		}
		if err := ev.Sign(priv); err != nil {
			t.Fatal(err)
		}
		return ev
	}
	for name, exp := range map[string]int64{
		"no expiration":     0,
		"past":              now - 10,
		"more than one day": now + transport.MaxPowAhead + 60,
	} {
		if ok, msg := offer(t, relay, mined(exp)); ok {
			t.Errorf("%s: accepted, want refused (%s)", name, msg)
		}
	}
	day := mined(now + transport.MaxPowAhead - 5)
	if ok, msg := offer(t, relay, day); !ok {
		t.Fatalf("expiration one day ahead refused: %s", msg)
	}
	if ok, _ := offer(t, relay, day); ok {
		t.Error("a repeated id was accepted before its expiration")
	}
}
