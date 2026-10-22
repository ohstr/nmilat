package relay

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip77"
	"github.com/ohstr/nmilat/testlogger"
)

// A NIP-77 sync with thousands of differing items on each side stays under
// a 64 KiB max_message_length in both directions and finds the exact diff.
func TestNegentropyLargeDiffUnderMessageLimit(t *testing.T) {
	const (
		maxMessage = 65535
		shared     = 1500
		serverOnly = 2500
		clientOnly = 4000
	)

	events := make([]*nip01.Event, 0, shared+serverOnly)
	base := uint64(time.Now().Unix()) - 10_000
	for i := range shared + serverOnly {
		ev := CreateEventWithTimestamp(t, 1, base+uint64(i%300))
		ev.Content = fmt.Sprintf("negentropy %d", i)
		if err := ev.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	// QueryNip77Items is bounded by max_limit, so keep every event in reach.
	store, err := NewEventStore(t.TempDir()+"/neg.db", &nip11.Limitation{MaxLimit: 10_000}, WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	InsertTestEvents(t, store, events)

	cfg := *defaultSessionConfig()
	cfg.Logger = testlogger.New(t)
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: maxMessage}}
	srv := httptest.NewServer(NewSessionHandler(store, metadata, nil, WithSessionConfig(cfg)))
	t.Cleanup(srv.Close)

	// Client: the shared events plus ids the relay has never seen.
	var items []nip77.Item
	wantNeed := map[string]bool{}
	wantHave := map[string]bool{}
	for i, ev := range events {
		if i >= shared {
			wantNeed[ev.ID] = true
			continue
		}
		var it nip77.Item
		it.Timestamp = ev.CreatedAt
		b, _ := hex.DecodeString(ev.ID)
		copy(it.ID[:], b)
		items = append(items, it)
	}
	for i := range clientOnly {
		var it nip77.Item
		it.Timestamp = base + uint64(i%300)
		_, _ = rand.Read(it.ID[:])
		items = append(items, it)
		wantHave[hex.EncodeToString(it.ID[:])] = true
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Compare(items[j]) < 0 })

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	send := func(v []any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > maxMessage {
			t.Fatalf("client message is %d bytes, over %d", len(b), maxMessage)
		}
		if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
			t.Fatal(err)
		}
	}

	neg := nip77.New(items)
	h, err := neg.Initiate().ToHex()
	if err != nil {
		t.Fatal(err)
	}
	send([]any{"NEG-OPEN", "n1", map[string]any{"kinds": []int{1}}, h})

	gotHave, gotNeed := map[string]bool{}, map[string]bool{}
	for round := 1; ; round++ {
		if round > 2000 {
			t.Fatal("no convergence")
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("round %d: relay closed the connection: %v", round, err)
		}
		if len(raw) > maxMessage {
			t.Fatalf("round %d: relay message is %d bytes, over %d", round, len(raw), maxMessage)
		}
		var frame []json.RawMessage
		if err := json.Unmarshal(raw, &frame); err != nil || len(frame) < 2 {
			t.Fatalf("round %d: unexpected frame %s", round, raw)
		}
		var typ, payload string
		_ = json.Unmarshal(frame[0], &typ)
		if typ == "AUTH" {
			round--
			continue
		}
		_ = json.Unmarshal(frame[2], &payload)
		if typ != "NEG-MSG" {
			t.Fatalf("round %d: got %s", round, raw)
		}
		msg, err := nip77.FromHex(payload)
		if err != nil {
			t.Fatal(err)
		}
		reply, have, need, err := neg.Reconcile(msg)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range have {
			gotHave[id] = true
		}
		for _, id := range need {
			gotNeed[id] = true
		}
		if nip77.IsComplete(reply) {
			t.Logf("converged in %d rounds", round)
			break
		}
		rh, err := reply.ToHex()
		if err != nil {
			t.Fatal(err)
		}
		send([]any{"NEG-MSG", "n1", rh})
	}
	send([]any{"NEG-CLOSE", "n1"})

	if len(gotNeed) != len(wantNeed) || len(gotHave) != len(wantHave) {
		t.Fatalf("need %d (want %d), have %d (want %d)", len(gotNeed), len(wantNeed), len(gotHave), len(wantHave))
	}
	for id := range wantNeed {
		if !gotNeed[id] {
			t.Fatalf("need is missing %s", id)
		}
	}
	for id := range wantHave {
		if !gotHave[id] {
			t.Fatalf("have is missing %s", id)
		}
	}
}
