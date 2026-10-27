package relay

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// T17-10 (CASH-KIND-01): the NIP-CASH transport kinds 23190-23193 are
// ephemeral: published to the relay, each reaches a live subscription and
// none is returned by a later REQ.
func TestCashTransportKindsNeverStored(t *testing.T) {
	handler, url := newRecipientOnlyRelay(t)
	kinds := []int{23190, 23191, 23192, 23193}
	sub := dialRO(t, handler, url)
	if ids, closed := sub.req("live", map[string]any{"kinds": kinds}); len(ids) != 0 || closed != "" {
		t.Fatalf("before: %v %q", ids, closed)
	}
	pub := dialRO(t, handler, url)
	for _, k := range kinds {
		ev := roSigned(t, k, wrapperPrivKey, []string{"p", pubOf(t, recipientPrivKey)})
		pub.publish(ev)
		_, raw := sub.until("EVENT")
		var got nip01.Event
		_ = json.Unmarshal(raw[2], &got)
		if got.ID != ev.ID {
			t.Fatalf("kind %d: live subscription got %s, want %s", k, got.ID, ev.ID)
		}
	}
	later := dialRO(t, handler, url)
	if ids, closed := later.req("later", map[string]any{"kinds": kinds}); len(ids) != 0 || closed != "" {
		t.Fatalf("stored transport events returned: %v %q", ids, closed)
	}
}
