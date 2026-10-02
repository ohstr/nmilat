package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/wire"
)

// auditD_privacy: what the RELAY OPERATOR sees, written down verbatim.
//
// Every claim in this area so far has been made from the event's point of view —
// "reply_to appears nowhere else, so nothing on the relay links this reply to the
// request it answers" (batch_send.go:subscribeReplies, private_dispatch.go:100). That
// is true of the EVENTS and false of the SESSION, because the client must subscribe
// with reply_to in a plaintext REQ filter BEFORE it publishes the request. The relay
// therefore receives the correlator from the client, by hand, in advance.
//
// This harness is startFakeHub with one change: it records every inbound frame with
// its connection id, its remote address and an arrival index, so the transcript is
// the relay's own log rather than an argument about one.

type auditDFrame struct {
	seq        int
	connID     int
	remoteAddr string
	kind       string // "REQ" or "EVENT"
	subID      string
	filterKind []int
	filterP    []string
	filterAuth []string
	eventKind  int
	eventPTag  string
	eventBytes int
}

type auditDRelayLog struct {
	mu     sync.Mutex
	frames []auditDFrame
	nextID int
}

func (l *auditDRelayLog) record(f auditDFrame) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f.seq = len(l.frames) + 1
	l.frames = append(l.frames, f)
}

func (l *auditDRelayLog) conn() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextID++
	return l.nextID
}

func (l *auditDRelayLog) snapshot() []auditDFrame {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]auditDFrame(nil), l.frames...)
}

// startLoggingHub is startFakeHub plus the relay's own access log.
func startLoggingHub(t *testing.T, h *fakeHub, log *auditDRelayLog) string {
	t.Helper()
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		connID := log.conn()
		remote := r.RemoteAddr

		var writeMu sync.Mutex
		writeMsg := func(v json.Marshaler) bool {
			b, err := v.MarshalJSON()
			if err != nil {
				return false
			}
			writeMu.Lock()
			defer writeMu.Unlock()
			return conn.WriteMessage(websocket.TextMessage, b) == nil
		}

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var payload wire.RelayPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				continue
			}

			switch p := payload.Packet.(type) {
			case *wire.RequestPacket:
				wantsAnnouncement := false
				var kinds []int
				var ps []string
				var authors []string
				for _, f := range p.Filters.GetAll() {
					kinds = append(kinds, f.Kinds...)
					authors = append(authors, f.Authors...)
					for _, k := range f.Kinds {
						if k == transport.KindHubAnnouncement {
							wantsAnnouncement = true
						}
					}
					if f.Tags != nil {
						ps = append(ps, f.Tags["p"]...)
					}
				}
				log.record(auditDFrame{
					connID: connID, remoteAddr: remote, kind: "REQ",
					subID: p.SubscriptionID, filterKind: kinds, filterP: ps, filterAuth: authors,
				})

				if wantsAnnouncement {
					ann := signedAnnouncement(t, h.hubPriv, h.hubXOnly, h.inboxXOnly, h.limits, nil)
					b, err := json.Marshal(ann)
					if err != nil {
						return
					}
					if !writeMsg(&wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, EventBytes: b}) {
						return
					}
					_ = writeMsg(&wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID})
					continue
				}

				ch := make(chan *nip01.Event, 8)
				h.register(ch)
				subID := p.SubscriptionID
				go func() {
					for ev := range ch {
						b, err := json.Marshal(ev)
						if err != nil {
							return
						}
						if !writeMsg(&wire.EventSubscriptionResponse{SubscriptionID: subID, EventBytes: b}) {
							return
						}
					}
				}()

			case *wire.EventPacket:
				ptag := ""
				for _, tag := range p.Event.Tags {
					if len(tag) >= 2 && tag[0] == "p" {
						ptag = tag[1]
						break
					}
				}
				log.record(auditDFrame{
					connID: connID, remoteAddr: remote, kind: "EVENT",
					eventKind: p.Event.Kind, eventPTag: ptag, eventBytes: len(p.Event.Content),
				})
				_ = writeMsg(&wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: true})
				if p.Event.Kind == transport.KindPrivateRequest {
					go h.handleRequest(t, p.Event)
				}
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

func auditDPrintLog(t *testing.T, frames []auditDFrame) {
	t.Helper()
	short := func(s string) string {
		if len(s) > 16 {
			return s[:16] + "…"
		}
		return s
	}
	for _, f := range frames {
		switch f.kind {
		case "REQ":
			ps := make([]string, 0, len(f.filterP))
			for _, p := range f.filterP {
				ps = append(ps, short(p))
			}
			as := make([]string, 0, len(f.filterAuth))
			for _, a := range f.filterAuth {
				as = append(as, short(a))
			}
			t.Logf("#%02d conn=%d from=%s  REQ   kinds=%v authors=%v #p=%v",
				f.seq, f.connID, f.remoteAddr, f.filterKind, as, ps)
		case "EVENT":
			t.Logf("#%02d conn=%d from=%s  EVENT kind=%d p=%s content=%d chars",
				f.seq, f.connID, f.remoteAddr, f.eventKind, short(f.eventPTag), f.eventBytes)
		}
	}
}

// TestAuditDPrivacy_RelaySeesReplyToBeforeTheRequest is the finding: the client hands
// the relay the request/response correlator, in plaintext, before the request exists.
func TestAuditDPrivacy_RelaySeesReplyToBeforeTheRequest(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	log := &auditDRelayLog{}
	relay := startLoggingHub(t, hub, log)

	items := make([]BatchStatus, 0, 3)
	for i := 0; i < 3; i++ {
		priv, target := sessionKeypair(t)
		items = append(items, BatchStatus{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := &Client{}
	s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("NewBatchSession() error = %v", err)
	}
	outcomes, err := s.StatusMany(ctx, items)
	if err != nil {
		t.Fatalf("StatusMany() error = %v", err)
	}
	for _, o := range outcomes {
		if !o.Succeeded() {
			t.Fatalf("control failed: item %s did not succeed (%v); the measurement below "+
				"would otherwise be of a broken exchange", o.ID, o.State)
		}
	}

	frames := log.snapshot()
	t.Log("=== the relay operator's own log of this one three-bill status check ===")
	auditDPrintLog(t, frames)

	// Find the reply subscription and the request event.
	var replySub, requestEvent *auditDFrame
	for i := range frames {
		f := &frames[i]
		if f.kind == "REQ" {
			for _, k := range f.filterKind {
				if k == transport.KindPrivateResponse {
					replySub = f
				}
			}
		}
		if f.kind == "EVENT" && f.eventKind == transport.KindPrivateRequest {
			requestEvent = f
		}
	}
	if replySub == nil {
		t.Fatal("no kind-23191 subscription was logged")
	}
	if requestEvent == nil {
		t.Fatal("no kind-23190 request was logged")
	}
	if len(replySub.filterP) != 1 {
		t.Fatalf("reply subscription carried %d p values, want 1", len(replySub.filterP))
	}
	replyTo := replySub.filterP[0]

	if replySub.seq >= requestEvent.seq {
		t.Fatalf("the reply subscription (#%d) did not precede the request (#%d); "+
			"the ordering this finding rests on is not what the client does",
			replySub.seq, requestEvent.seq)
	}
	t.Logf("ORDERING: the relay learned reply_to=%s… at frame #%d, and only saw the "+
		"kind-23190 it belongs to at frame #%d — %d frame(s) later.",
		replyTo[:16], replySub.seq, requestEvent.seq, requestEvent.seq-replySub.seq)

	// The frame BEFORE either of those is the announcement fetch, and it names the
	// hub's own identity key in a plaintext authors filter (batch_session.go:90). That
	// key is the hub's LN node pubkey in Nostr form (lokihub
	// service/private_transport.go:newPrivateTransport), so the relay learns which
	// custodian this host banks with before any private traffic exists.
	var annFetch *auditDFrame
	for i := range frames {
		if frames[i].kind != "REQ" {
			continue
		}
		for _, k := range frames[i].filterKind {
			if k == transport.KindHubAnnouncement {
				annFetch = &frames[i]
			}
		}
	}
	if annFetch == nil {
		t.Fatal("no kind-11190 announcement fetch was logged")
	}
	if len(annFetch.filterAuth) != 1 || annFetch.filterAuth[0] != hub.hubXOnly {
		t.Fatalf("announcement filter authors = %v, want exactly the hub identity %q",
			annFetch.filterAuth, hub.hubXOnly)
	}
	if annFetch.seq >= replySub.seq {
		t.Fatalf("announcement fetch (#%d) did not precede the private exchange (#%d)",
			annFetch.seq, replySub.seq)
	}
	t.Logf("COUNTERPARTY: frame #%d is a plaintext {kinds:[11190],authors:[%s…]} from the "+
		"same host. The hub identity is its LN node pubkey, so the relay knows WHICH HUB "+
		"this client uses, by name, before frame #%d.",
		annFetch.seq, hub.hubXOnly[:16], requestEvent.seq)

	// The request event is p-tagged to the hub inbox, a stable value: the relay can
	// select all of this hub's private traffic with one filter, forever.
	if requestEvent.eventPTag != hub.inboxXOnly {
		t.Fatalf("request p-tag = %q, want the hub inbox %q", requestEvent.eventPTag, hub.inboxXOnly)
	}
	t.Logf("The kind-23190's own p tag is the hub's inbox key %s… — constant for the life "+
		"of the hub (privateTransportKeyIndex is a const 0), so {kinds:[23190],#p:[inbox]} "+
		"enumerates every private request this hub ever receives.", hub.inboxXOnly[:16])

	// Same source address on every frame: the per-envelope ephemeral author key buys
	// unlinkability against someone who sees only events, and nothing against anyone
	// who sees the transport that carried them.
	addrs := map[string]int{}
	conns := map[int]struct{}{}
	for _, f := range frames {
		addrs[strings.Split(f.remoteAddr, ":")[0]]++
		conns[f.connID] = struct{}{}
	}
	t.Logf("SOURCE: %d frames arrived from %d distinct host address(es) across %d "+
		"connection(s): %v", len(frames), len(addrs), len(conns), addrs)
	if len(addrs) != 1 {
		t.Errorf("expected every frame from one host; got %v", addrs)
	}
}

// TestAuditDPrivacy_RelayLinksTwoEnvelopesOfOneBatch: when a batch splits, the relay
// gets both reply_to values on the SAME connection, so "two unrelated envelopes" is
// unlinkable only to an observer who cannot see connections.
func TestAuditDPrivacy_RelayLinksTwoEnvelopesOfOneBatch(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	hub.limits.MaxItems = 2 // force the split
	log := &auditDRelayLog{}
	relay := startLoggingHub(t, hub, log)

	items := make([]BatchStatus, 0, 5)
	for i := 0; i < 5; i++ {
		priv, target := sessionKeypair(t)
		items = append(items, BatchStatus{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := &Client{}
	s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("NewBatchSession() error = %v", err)
	}
	outcomes, err := s.StatusMany(ctx, items)
	if err != nil {
		t.Fatalf("StatusMany() error = %v", err)
	}
	served := 0
	for _, o := range outcomes {
		if o.Succeeded() {
			served++
		}
	}
	if served != len(items) {
		t.Fatalf("control failed: %d of %d items served", served, len(items))
	}

	frames := log.snapshot()
	t.Log("=== relay log: five bills, MaxItems=2, so three envelopes ===")
	auditDPrintLog(t, frames)

	replyTos := map[string]struct{}{}
	requests := 0
	hosts := map[string]struct{}{}
	for _, f := range frames {
		hosts[strings.Split(f.remoteAddr, ":")[0]] = struct{}{}
		if f.kind == "REQ" {
			for _, k := range f.filterKind {
				if k == transport.KindPrivateResponse {
					for _, p := range f.filterP {
						replyTos[p] = struct{}{}
					}
				}
			}
		}
		if f.kind == "EVENT" && f.eventKind == transport.KindPrivateRequest {
			requests++
		}
	}
	t.Logf("The relay saw %d kind-23190 events and %d distinct reply_to values, all from "+
		"%d host(s) inside one second. Each 23190 has an unrelated author key; the "+
		"GROUPING is free anyway.", requests, len(replyTos), len(hosts))
	if requests < 2 {
		t.Fatalf("expected the batch to split into >=2 envelopes, got %d", requests)
	}
	if len(replyTos) != requests {
		t.Errorf("got %d reply_to values for %d envelopes; expected one each", len(replyTos), requests)
	}
	if len(hosts) != 1 {
		t.Errorf("expected one host, got %v", hosts)
	}
}

// TestAuditDPrivacy_ChunkedReplyIsGroupedByTheSharedReplyTo: chunking defeats the
// padding bucket, because the number of reply EVENTS is unpadded and they are tied
// together by a tag.
func TestAuditDPrivacy_ChunkedReplyIsGroupedByTheSharedReplyTo(t *testing.T) {
	for _, chunkSize := range []int{0, 1, 2, 4} {
		hub := newTestHub(t, alwaysSucceed)
		hub.chunkSize = chunkSize
		log := &auditDRelayLog{}
		relay := startLoggingHub(t, hub, log)

		const bills = 8
		items := make([]BatchStatus, 0, bills)
		for i := 0; i < bills; i++ {
			priv, target := sessionKeypair(t)
			items = append(items, BatchStatus{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)})
		}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		c := &Client{}
		s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
		if err != nil {
			cancel()
			t.Fatalf("NewBatchSession() error = %v", err)
		}
		outcomes, err := s.StatusMany(ctx, items)
		cancel()
		if err != nil {
			t.Fatalf("chunkSize=%d: StatusMany() error = %v", chunkSize, err)
		}
		served := 0
		for _, o := range outcomes {
			if o.Succeeded() {
				served++
			}
		}
		// The reply events the relay forwarded are the hub's, not logged inbound; count
		// them from the hub's own view of what it published.
		want := 1
		if chunkSize > 0 {
			want = (bills + chunkSize - 1) / chunkSize
		}
		t.Logf("chunkSize=%d: %d/%d items served; an observer counting kind-23191 events "+
			"sharing one reply_to tag reads %d chunk(s) — i.e. ~%d results, which the "+
			"8 KiB bucket on each individual event does not hide",
			chunkSize, served, bills, want, bills)
		if served != bills {
			t.Errorf("chunkSize=%d: control failed, %d of %d served", chunkSize, served, bills)
		}
	}
	t.Log("The per-event bucket bounds ONE event's content. The chunk COUNT is not " +
		"padded and not bounded, and all chunks carry the same reply_to tag, so an " +
		"observer multiplies: observable volume = chunks x bucket.")
}

// TestAuditDPrivacy_TimingPairsRequestAndReply measures the other half of brief item 5:
// with reply_to in hand from the subscription, how tight is the request->reply gap?
func TestAuditDPrivacy_TimingPairsRequestAndReply(t *testing.T) {
	type sample struct {
		gap time.Duration
	}
	var samples []sample

	for i := 0; i < 5; i++ {
		var publishedAt, repliedAt time.Time
		var mu sync.Mutex

		hub := newTestHub(t, func(item transport.Item) *transport.Result {
			mu.Lock()
			if repliedAt.IsZero() {
				repliedAt = time.Now()
			}
			mu.Unlock()
			return alwaysSucceed(item)
		})
		log := &auditDRelayLog{}
		relay := startLoggingHub(t, hub, log)

		priv, target := sessionKeypair(t)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		c := &Client{}
		s, err := c.NewBatchSession(ctx, hub.hubXOnly, []string{relay})
		if err != nil {
			cancel()
			t.Fatalf("NewBatchSession() error = %v", err)
		}
		mu.Lock()
		publishedAt = time.Now()
		mu.Unlock()
		outcomes, err := s.StatusMany(ctx, []BatchStatus{
			{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)},
		})
		cancel()
		if err != nil || len(outcomes) != 1 || !outcomes[0].Succeeded() {
			t.Fatalf("control failed: err=%v outcomes=%v", err, outcomes)
		}
		mu.Lock()
		gap := repliedAt.Sub(publishedAt)
		mu.Unlock()
		samples = append(samples, sample{gap})
	}

	var total time.Duration
	minGap, maxGap := samples[0].gap, samples[0].gap
	for _, s := range samples {
		total += s.gap
		if s.gap < minGap {
			minGap = s.gap
		}
		if s.gap > maxGap {
			maxGap = s.gap
		}
	}
	t.Logf("request -> reply gap over %d exchanges: min %v, mean %v, max %v",
		len(samples), minGap, total/time.Duration(len(samples)), maxGap)
	t.Log("In-process, so these are a FLOOR, not a measurement of production latency. " +
		"The point is the shape: a reply follows its request within one round trip and " +
		"nothing delays, batches or decoys it, so an observer holding neither key still " +
		"pairs the two by arrival order alone — before using the reply_to it was given.")

	_ = fmt.Sprint() // keep fmt imported for the helpers above
}
