package relay

import (
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/ohstr/nmilat/wire"
)

func TestParseRejectReason(t *testing.T) {
	cases := map[string]RejectReason{
		"":                                     ReasonNone,
		"invalid: bad signature":               ReasonInvalid,
		"auth-error: invalid signature":        ReasonInvalid,
		"pow: difficulty 3 is less than 20":    ReasonPow,
		"auth-required: valid NIP-42 required": ReasonAuthRequired,
		"restricted: not a member":             ReasonRestricted,
		"blocked: pubkey is banned":            ReasonBlocked,
		"rate-limited: too many tasks":         ReasonRateLimited,
		"mute: no one listens":                 ReasonMute,
		"error: could not store event":         ReasonError,
		"error: relay busy, try again later":   ReasonBusy,
		"something else":                       ReasonOther,
		"weird: prefix":                        ReasonOther,
	}
	for msg, want := range cases {
		if got := ParseRejectReason(msg); got != want {
			t.Errorf("ParseRejectReason(%q) = %v, want %v", msg, got, want)
		}
	}
}

func TestClassifyKind(t *testing.T) {
	cases := map[int]KindClass{
		0: KindMetadata, 1: KindNote, 1111: KindNote, 3: KindContacts, 4: KindDM,
		5: KindDeletion, 6: KindRepost, 7: KindReaction, 1059: KindGiftWrap,
		42: KindChannel, 9735: KindZap, 9521: KindZap, 9522: KindZap, 9523: KindZap, 9007: KindGroup,
		39000: KindGroup, 10002: KindList, 10063: KindList, 13534: KindReplaceable,
		22242: KindEphemeral, 30000: KindList, 30023: KindLongForm,
		30312: KindAddressable, 1984: KindOther,
	}
	for kind, want := range cases {
		if got := ClassifyKind(kind); got != want {
			t.Errorf("ClassifyKind(%d) = %v, want %v", kind, got, want)
		}
	}
}

func TestLabelNamesCoverEveryValue(t *testing.T) {
	for _, v := range MessageTypes() {
		if v.String() == "unknown" {
			t.Errorf("MessageType %d has no name", v)
		}
	}
	for _, v := range EventResults() {
		if v.String() == "unknown" {
			t.Errorf("EventResult %d has no name", v)
		}
	}
	for _, v := range RejectReasons() {
		if v.String() == "unknown" {
			t.Errorf("RejectReason %d has no name", v)
		}
	}
	for _, v := range KindClasses() {
		if v.String() == "unknown" {
			t.Errorf("KindClass %d has no name", v)
		}
	}
}

// The hot path calls these per message: none may allocate.
func TestObserverPathDoesNotAllocate(t *testing.T) {
	var obs Observer = NopObserver{}
	allocs := testing.AllocsPerRun(1000, func() {
		obs.Message(MsgEvent)
		obs.EventHandled(EventRejected, ParseRejectReason("blocked: banned"), ClassifyKind(30023), time.Millisecond)
		obs.Sent(time.Microsecond, false)
		obs.SubscriptionsChanged(1)
		_ = RejectReason(3).String()
	})
	if allocs != 0 {
		t.Fatalf("observer path allocated %.1f times per run", allocs)
	}
}

type recordingObserver struct {
	NopObserver
	opened, closed       atomic.Int64
	messages             [numMessageTypes]atomic.Int64
	results              [numEventResults]atomic.Int64
	reasons              [numRejectReasons]atomic.Int64
	reqServed, reqEvents atomic.Int64
	counts               atomic.Int64
	subs                 atomic.Int64
	sent                 atomic.Int64
	batches              atomic.Int64
	mu                   sync.Mutex
	classes              []KindClass
}

func (o *recordingObserver) SessionOpened()            { o.opened.Add(1) }
func (o *recordingObserver) SessionClosed()            { o.closed.Add(1) }
func (o *recordingObserver) Message(m MessageType)     { o.messages[m].Add(1) }
func (o *recordingObserver) CountServed(time.Duration) { o.counts.Add(1) }
func (o *recordingObserver) SubscriptionsChanged(d int) {
	o.subs.Add(int64(d))
}
func (o *recordingObserver) Sent(time.Duration, bool)                { o.sent.Add(1) }
func (o *recordingObserver) BatchCommitted(int, time.Duration, bool) { o.batches.Add(1) }
func (o *recordingObserver) ReqServed(_ time.Duration, n int) {
	o.reqServed.Add(1)
	o.reqEvents.Add(int64(n))
}
func (o *recordingObserver) EventHandled(r EventResult, reason RejectReason, k KindClass, _ time.Duration) {
	o.results[r].Add(1)
	o.reasons[reason].Add(1)
	o.mu.Lock()
	o.classes = append(o.classes, k)
	o.mu.Unlock()
}

func awaitResponse(t *testing.T, conn *websocket.Conn, match func(wire.SubscriptionResponse) bool) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var msg wire.ClientPayload
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("read: %v", err)
		}
		if match(msg.SubscriptionResponse) {
			return
		}
	}
}

func isOK(id string) func(wire.SubscriptionResponse) bool {
	return func(r wire.SubscriptionResponse) bool {
		ok, is := r.(*wire.OkSubscriptionResponse)
		return is && ok.EventID == id
	}
}

func TestObserverSeesSessionTraffic(t *testing.T) {
	obs := &recordingObserver{}
	store, err := NewEventStore(t.TempDir()+"/obs.db", &nip11.Limitation{},
		WithEventStoreLogger(testlogger.New(t)), WithEventStoreObserver(obs))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	handler := NewSessionHandler(store, metadata, nil, WithLogger(testlogger.New(t)), WithObserver(obs))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
		_, ok := r.(*wire.AuthChallengeResponse)
		return ok
	})

	ev := CreateEvent(t, 1)
	send := func(v ...interface{}) {
		t.Helper()
		if err := conn.WriteJSON(v); err != nil {
			t.Fatal(err)
		}
	}

	send("EVENT", ev)
	awaitResponse(t, conn, isOK(ev.ID))
	send("EVENT", ev)
	awaitResponse(t, conn, isOK(ev.ID))

	bad := CreateEvent(t, 7)
	bad.Sig = strings.Repeat("0", 128)
	send("EVENT", bad)
	awaitResponse(t, conn, isOK(bad.ID))

	send("REQ", "s1", map[string]interface{}{"kinds": []int{1}})
	awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
		_, ok := r.(*wire.EOSESubscriptionResponse)
		return ok
	})
	if got := obs.subs.Load(); got != 1 {
		t.Fatalf("open subscriptions = %d, want 1", got)
	}
	send("CLOSE", "s1")
	awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
		_, ok := r.(*wire.ClosedSubscriptionResponse)
		return ok
	})
	send("COUNT", "c1", map[string]interface{}{"kinds": []int{1}})
	awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
		_, ok := r.(*wire.CountSubscriptionResponse)
		return ok
	})

	_ = conn.Close()
	waitForSessionCount(t, handler, 0)

	checks := []struct {
		name      string
		got, want int64
	}{
		{"sessions opened", obs.opened.Load(), 1},
		{"sessions closed", obs.closed.Load(), 1},
		{"EVENT messages", obs.messages[MsgEvent].Load(), 3},
		{"REQ messages", obs.messages[MsgReq].Load(), 1},
		{"CLOSE messages", obs.messages[MsgClose].Load(), 1},
		{"COUNT messages", obs.messages[MsgCount].Load(), 1},
		{"accepted", obs.results[EventAccepted].Load(), 1},
		{"duplicate", obs.results[EventDuplicate].Load(), 1},
		{"rejected", obs.results[EventRejected].Load(), 1},
		{"rejected as invalid", obs.reasons[ReasonInvalid].Load(), 1},
		{"REQs served", obs.reqServed.Load(), 1},
		{"events before EOSE", obs.reqEvents.Load(), 1},
		{"COUNTs served", obs.counts.Load(), 1},
		{"open subscriptions", obs.subs.Load(), 0},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if obs.sent.Load() == 0 {
		t.Error("no sends observed")
	}
	if obs.batches.Load() == 0 {
		t.Error("no store batches observed")
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.classes) != 3 || obs.classes[0] != KindNote || obs.classes[2] != KindReaction {
		t.Errorf("kind classes = %v, want [note note reaction]", obs.classes)
	}
}
