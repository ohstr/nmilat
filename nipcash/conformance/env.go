package conformance

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// envCases are the envelope-serving cases (NIP-CASH §Serving an Envelope,
// §Responses (kind 23191), §Addressing the Response, §The Reply Key).
var envCases = []ctCase{
	{id: "CT-ENV-01", run: ctEnv01},
	{id: "CT-ENV-02", run: ctEnv02},
	{id: "CT-ENV-03", run: ctEnv03},
	{id: "CT-ENV-10", run: ctEnv10},
	{id: "CT-ENV-11", run: ctEnv11},
	{id: "CT-ENV-15", run: ctEnv15},
}

// CT-ENV-01 (S-CASH-225): E1 drops. A malformed reply_to, or content that does
// not decrypt under the inbox key, gets no reply.
func ctEnv01(t *testing.T, s *suite) {
	e, nonce, _, notAfter := s.newEnvelope(t)
	e["items"] = []transport.Item{s.omittedItem(t, "1", nonce, notAfter)}
	badReplyTo := strings.ToUpper(mustNonce(t))
	e["reply_to"] = badReplyTo
	l := s.listen(t, badReplyTo)
	s.publish(t, 0, s.wrap(t, e, "").ev)

	e2, nonce2, replyTo2, notAfter2 := s.newEnvelope(t)
	e2["items"] = []transport.Item{s.omittedItem(t, "1", nonce2, notAfter2)}
	l2 := s.listen(t, replyTo2)
	_, otherInbox := keypair(t)
	s.publish(t, 0, s.wrap(t, e2, otherInbox).ev)

	if got := l.wait(1, s.quiet()); len(got) > 0 {
		t.Errorf("a reply was sent for an envelope whose reply_to is not 64 lowercase hex")
	}
	if got := l2.wait(1, s.quiet()); len(got) > 0 {
		t.Errorf("a reply was sent for an envelope the inbox key cannot decrypt")
	}
}

// CT-ENV-02 (S-CASH-135, S-CASH-225): E4 refusals are an envelope-level
// BAD_REQUEST, and an envelope refused there leaves its nonce unserved.
func ctEnv02(t *testing.T, s *suite) {
	for name, mutate := range map[string]func(e envelope){
		"uppercase nonce": func(e envelope) { e["nonce"] = strings.ToUpper(e["nonce"].(string)) },
		"no not_after":    func(e envelope) { delete(e, "not_after") },
		"empty items":     func(e envelope) { e["items"] = []transport.Item{} },
		"duplicate ids": func(e envelope) {
			items := e["items"].([]transport.Item)
			e["items"] = append(items, items[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, nonce, replyTo, notAfter := s.newEnvelope(t)
			e["items"] = []transport.Item{s.omittedItem(t, "1", nonce, notAfter)}
			mutate(e)
			l := s.listen(t, replyTo)
			r := s.wrap(t, e, "")
			s.publish(t, 0, r.ev)
			got := l.wait(1, s.quiet())
			if len(got) != 1 {
				t.Fatalf("%d replies, want one envelope-level BAD_REQUEST", len(got))
			}
			if code := envelopeErrorCode(t, r.open(t, got[0].ev)); code != "BAD_REQUEST" {
				t.Fatalf("envelope error %q, want BAD_REQUEST", code)
			}
		})
	}

	// The nonce of a refused envelope is still usable.
	e, nonce, replyTo, notAfter := s.newEnvelope(t)
	e["items"] = []transport.Item{}
	l := s.listen(t, replyTo)
	s.publish(t, 0, s.wrap(t, e, "").ev)
	if got := l.wait(1, s.quiet()); len(got) != 1 {
		t.Fatalf("no BAD_REQUEST for an empty items array")
	}
	good, _, replyTo2, _ := s.newEnvelope(t)
	good["nonce"], good["not_after"] = nonce, notAfter
	good["items"] = []transport.Item{s.omittedItem(t, "1", nonce, notAfter)}
	l2 := s.listen(t, replyTo2)
	s.publish(t, 0, s.wrap(t, good, "").ev)
	if got := l2.wait(1, s.quiet()); len(got) != 1 {
		t.Fatalf("the nonce of an envelope refused at E4 was treated as served")
	}
}

// CT-ENV-03 (S-CASH-147): an envelope whose every item is omitted is answered
// `"results": []`, seq 1 of total 1.
func ctEnv03(t *testing.T, s *suite) {
	e, nonce, replyTo, notAfter := s.newEnvelope(t)
	e["items"] = []transport.Item{s.omittedItem(t, "1", nonce, notAfter), s.omittedItem(t, "2", nonce, notAfter)}
	l := s.listen(t, replyTo)
	r := s.wrap(t, e, "")
	s.publish(t, 0, r.ev)
	got := l.wait(1, s.quiet())
	if len(got) != 1 {
		t.Fatalf("%d replies, want one: a Hub replies to every envelope it parses", len(got))
	}
	body := r.open(t, got[0].ev)
	var results []json.RawMessage
	if raw, ok := body["results"]; !ok || json.Unmarshal(raw, &results) != nil || results == nil || len(results) != 0 {
		t.Errorf(`results = %s, want []`, body["results"])
	}
	if string(body["seq"]) != "1" || string(body["total"]) != "1" {
		t.Errorf("seq/total = %s/%s, want 1/1", body["seq"], body["total"])
	}
}

// CT-ENV-10 (S-CASH-150): the reply comes back on the relay the request arrived
// on. Needs a Hub with two relays.
func ctEnv10(t *testing.T, s *suite) {
	if len(s.relays) < 2 {
		t.Skip("the Hub announces one relay")
	}
	e, nonce, replyTo, notAfter := s.newEnvelope(t)
	e["items"] = []transport.Item{s.omittedItem(t, "1", nonce, notAfter)}
	l := s.listen(t, replyTo)
	s.publish(t, 1, s.wrap(t, e, "").ev)
	l.wait(1, s.quiet())
	arrived := false
	for _, h := range l.wait(len(s.relays), s.quiet()/2) {
		if h.relay == 1 {
			arrived = true
		}
	}
	if !arrived {
		t.Errorf("no reply on the relay the request was published to")
	}
}

// CT-ENV-11 (S-CASH-16, S-CASH-137): a replayed envelope, or its nonce under a
// new ciphertext, gets no reply; so does one first refused at E5 (S-CASH-225).
func ctEnv11(t *testing.T, s *suite) {
	e, nonce, replyTo, notAfter := s.newEnvelope(t)
	e["items"] = []transport.Item{s.omittedItem(t, "1", nonce, notAfter)}
	l := s.listen(t, replyTo)
	first := s.wrap(t, e, "")
	s.publish(t, 0, first.ev)
	if got := l.wait(1, s.quiet()); len(got) != 1 {
		t.Fatalf("no reply to the original envelope")
	}
	s.publish(t, 0, first.ev)            // the same event again
	s.publish(t, 0, s.wrap(t, e, "").ev) // the same envelope, new ciphertext
	if got := l.wait(2, s.quiet()); len(got) != 1 {
		t.Errorf("%d replies, want only the original's: a served nonce is never served again", len(got))
	}

	// An envelope refused at E5 passed E4, so its nonce counts as served too:
	// the same envelope again gets no reply.
	over, nonce, replyTo, notAfter := s.newEnvelope(t)
	var items []transport.Item
	for i := 0; i <= s.limits.MaxItems; i++ {
		items = append(items, s.omittedItem(t, strconv.Itoa(i+1), nonce, notAfter))
	}
	over["items"] = items
	l3 := s.listen(t, replyTo)
	refused := s.wrap(t, over, "")
	s.publish(t, 0, refused.ev)
	got := l3.wait(1, s.quiet())
	if len(got) != 1 {
		t.Fatalf("%d replies to an envelope over max_items, want one QUOTA_EXCEEDED", len(got))
	}
	if code := envelopeErrorCode(t, refused.open(t, got[0].ev)); code != "QUOTA_EXCEEDED" {
		t.Fatalf("envelope error %q, want QUOTA_EXCEEDED", code)
	}
	s.publish(t, 0, s.wrap(t, over, "").ev)
	if got := l3.wait(2, s.quiet()); len(got) != 1 {
		t.Errorf("%d replies, want one: the nonce of an envelope refused at E5 was served again", len(got))
	}
}

// CT-ENV-15 (S-CASH-159, S-CASH-226): each reply chunk is signed by a fresh key,
// neither the node identity nor the inbox, and carries only the p tag.
func ctEnv15(t *testing.T, s *suite) {
	var authors []string
	for range 2 {
		e, nonce, replyTo, notAfter := s.newEnvelope(t)
		e["items"] = []transport.Item{s.omittedItem(t, "1", nonce, notAfter)}
		l := s.listen(t, replyTo)
		s.publish(t, 0, s.wrap(t, e, "").ev)
		got := l.wait(1, s.quiet())
		if len(got) != 1 {
			t.Fatalf("no reply")
		}
		ev := got[0].ev
		if ev.PubKey == s.nodeXOnly || ev.PubKey == s.inbox {
			t.Errorf("reply signed by a long-term key %s", ev.PubKey)
		}
		if len(ev.Tags) != 1 || len(ev.Tags[0]) != 2 || ev.Tags[0][0] != "p" || ev.Tags[0][1] != replyTo {
			t.Errorf("reply tags = %v, want only [p, reply_to]", ev.Tags)
		}
		authors = append(authors, ev.PubKey)
	}
	if authors[0] == authors[1] {
		t.Errorf("two replies share the author %s: chunk keys must be fresh", authors[0])
	}
}

func envelopeErrorCode(t *testing.T, body map[string]json.RawMessage) string {
	t.Helper()
	var e struct {
		Code string `json:"code"`
	}
	if raw, ok := body["error"]; !ok || json.Unmarshal(raw, &e) != nil {
		return ""
	}
	return e.Code
}
