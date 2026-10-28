package cashtest

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip13"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// SetMinPow makes the relay enforce proof of work on kind 23190 the way NIP-CASH
// §Proof of Work asks of a relay a Hub reads its inbox on: it advertises n as
// limitation.min_pow_difficulty in its NIP-11 document, refuses a request below
// it with OK false "pow: difficulty n required", refuses one whose expiration is
// absent, past or more than a day ahead, and drops a repeat of an id it accepted
// until that id's expiration. 0 turns all of it off.
func (r *Relay) SetMinPow(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.minPow = n
	if r.powSeen == nil {
		r.powSeen = map[string]int64{}
	}
}

// SetPowClock makes the proof-of-work checks read now from f (nil: the wall
// clock), so expiration bounds can be tested to the second.
func (r *Relay) SetPowClock(f func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.powNow = f
}

// MinPow is the enforced minimum, 0 when none.
func (r *Relay) MinPow() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.minPow
}

// powRefusalLocked is the refusal message for ev, "" when it passes. Called
// with r.mu held.
func (r *Relay) powRefusalLocked(ev *nip01.Event) string {
	if r.minPow <= 0 || ev.Kind != transport.KindPrivateRequest {
		return ""
	}
	now := time.Now().Unix()
	if r.powNow != nil {
		now = r.powNow().Unix()
	}
	for id, exp := range r.powSeen {
		if exp < now {
			delete(r.powSeen, id)
		}
	}
	if _, dup := r.powSeen[ev.ID]; dup {
		return "duplicate: already have this event"
	}
	if d, err := nip13.Difficulty(ev.ID); err != nil || d < r.minPow {
		return fmt.Sprintf("pow: difficulty %d required", r.minPow)
	}
	exp, ok := expirationOf(ev)
	switch {
	case !ok:
		return "invalid: expiration tag required"
	case exp < now:
		return "invalid: event has expired"
	case exp > now+transport.MaxPowAhead:
		return "invalid: expiration more than one day ahead"
	}
	r.powSeen[ev.ID] = exp
	return ""
}

func expirationOf(ev *nip01.Event) (int64, bool) {
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "expiration" {
			n, err := strconv.ParseInt(tag[1], 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// serveNIP11 answers a plain GET asking for application/nostr+json with the
// relay's NIP-11 document; it reports whether it did.
func (r *Relay) serveNIP11(w http.ResponseWriter, req *http.Request) bool {
	if req.Method != http.MethodGet || strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(req.Header.Get("Accept"), "application/nostr+json") {
		return false
	}
	w.Header().Set("Content-Type", "application/nostr+json")
	_, _ = fmt.Fprintf(w, `{"name":"cashtest","supported_nips":[1,11,13,40],"limitation":{"min_pow_difficulty":%d}}`, r.MinPow())
	return true
}

// SetMinPow sets the proof-of-work minimum on every relay the Hub reads its
// inbox on (conformance PowRelay).
func (h *FakeHub) SetMinPow(_ testing.TB, difficulty int) {
	for _, r := range h.Relays {
		r.SetMinPow(difficulty)
	}
}

// RelayURL is the first relay the Hub reads its inbox on (conformance PowRelay).
func (h *FakeHub) RelayURL() string {
	if len(h.Relays) == 0 {
		return ""
	}
	return h.Relays[0].URL()
}
