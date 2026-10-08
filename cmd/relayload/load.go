package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
)

const writerKey = "5b1d2a6cbd5c1e1f6f1d0b4f0f4d6a3e2c1b0a9f8e7d6c5b4a39281706f5e4d3"

// recorder keeps every latency sample; the run is small enough for that.
type recorder struct {
	mu       sync.Mutex
	lat      map[string][]time.Duration
	timeouts map[string]int
	closed   map[string]int
	reasons  map[string]int
}

func newRecorder() *recorder {
	return &recorder{lat: map[string][]time.Duration{}, timeouts: map[string]int{}, closed: map[string]int{}, reasons: map[string]int{}}
}

func (r *recorder) add(cat string, d time.Duration) {
	r.mu.Lock()
	r.lat[cat] = append(r.lat[cat], d)
	r.mu.Unlock()
}

func (r *recorder) timeout(cat string) {
	r.mu.Lock()
	r.timeouts[cat]++
	r.mu.Unlock()
}

func (r *recorder) close(cat, reason string) {
	r.mu.Lock()
	r.closed[cat]++
	if i := strings.IndexByte(reason, ':'); i > 0 {
		reason = reason[:i]
	}
	r.reasons[cat+" "+reason]++
	r.mu.Unlock()
}

type catSummary struct {
	N        int     `json:"n"`
	P50ms    float64 `json:"p50_ms"`
	P90ms    float64 `json:"p90_ms"`
	P99ms    float64 `json:"p99_ms"`
	MaxMs    float64 `json:"max_ms"`
	Timeouts int     `json:"timeouts"`
	Closed   int     `json:"closed"`
}

func pct(s []time.Duration, p float64) float64 {
	if len(s) == 0 {
		return 0
	}
	i := int(p * float64(len(s)-1))
	return float64(s[i].Microseconds()) / 1000
}

// snapshot summarises and, with reset, starts a new interval.
func (r *recorder) snapshot(reset bool) map[string]catSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]catSummary{}
	cats := map[string]bool{}
	for c := range r.lat {
		cats[c] = true
	}
	for c := range r.timeouts {
		cats[c] = true
	}
	for c := range r.closed {
		cats[c] = true
	}
	for c := range cats {
		s := slices.Clone(r.lat[c])
		slices.Sort(s)
		cs := catSummary{N: len(s), Timeouts: r.timeouts[c], Closed: r.closed[c]}
		if len(s) > 0 {
			cs.P50ms, cs.P90ms, cs.P99ms = pct(s, .5), pct(s, .9), pct(s, .99)
			cs.MaxMs = float64(s[len(s)-1].Microseconds()) / 1000
		}
		out[c] = cs
	}
	if reset {
		r.lat, r.timeouts, r.closed = map[string][]time.Duration{}, map[string]int{}, map[string]int{}
	}
	return out
}

// conn is one websocket client: a reader goroutine routes EOSE, CLOSED and OK
// to whoever is waiting on that subscription or event id.
type conn struct {
	ws      *websocket.Conn
	wmu     sync.Mutex
	mu      sync.Mutex
	waiters map[string]chan string
	events  *atomic.Int64
	// onLive, if set, gets how long ago each writer note delivered live on
	// "feed" (after its EOSE) was published: write-to-delivery latency.
	onLive func(time.Duration)
}

func dial(url string, events *atomic.Int64, onLive func(time.Duration)) (*conn, error) {
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	ws, _, err := d.Dial(url, nil)
	if err != nil {
		return nil, err
	}
	c := &conn{ws: ws, waiters: map[string]chan string{}, events: events, onLive: onLive}
	go c.read()
	return c, nil
}

func (c *conn) send(v any) error {
	b, _ := json.Marshal(v)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.ws.WriteMessage(websocket.TextMessage, b)
}

func (c *conn) wait(key string) chan string {
	ch := make(chan string, 1)
	c.mu.Lock()
	c.waiters[key] = ch
	c.mu.Unlock()
	return ch
}

func (c *conn) notify(key, msg string) {
	c.mu.Lock()
	ch, ok := c.waiters[key]
	delete(c.waiters, key)
	c.mu.Unlock()
	if ok {
		ch <- msg
	}
}

func (c *conn) read() {
	// Subscriptions past EOSE: only their events are live deliveries.
	live := map[string]bool{}
	for {
		_, b, err := c.ws.ReadMessage()
		if err != nil {
			c.mu.Lock()
			for k, ch := range c.waiters {
				ch <- "CLOSED:connection " + err.Error()
				delete(c.waiters, k)
			}
			c.mu.Unlock()
			return
		}
		var msg []json.RawMessage
		if json.Unmarshal(b, &msg) != nil || len(msg) < 2 {
			continue
		}
		var typ, key string
		_ = json.Unmarshal(msg[0], &typ)
		_ = json.Unmarshal(msg[1], &key)
		switch typ {
		case "EVENT":
			c.events.Add(1)
			if key == "feed" && live[key] && c.onLive != nil && len(msg) > 2 {
				var ev struct {
					Content string `json:"content"`
				}
				if json.Unmarshal(msg[2], &ev) == nil {
					if f := strings.Fields(ev.Content); len(f) == 3 && f[0] == "relayload" {
						if ns, err := strconv.ParseInt(f[2], 10, 64); err == nil {
							c.onLive(time.Since(time.Unix(0, ns)))
						}
					}
				}
			}
		case "EOSE":
			live[key] = true
			c.notify("sub:"+key, "EOSE")
		case "CLOSED":
			var reason string
			if len(msg) > 2 {
				_ = json.Unmarshal(msg[2], &reason)
			}
			c.notify("sub:"+key, "CLOSED:"+reason)
		case "OK":
			var ok bool
			var reason string
			if len(msg) > 3 {
				_ = json.Unmarshal(msg[2], &ok)
				_ = json.Unmarshal(msg[3], &reason)
			}
			if ok {
				c.notify("ok:"+key, "OK")
			} else {
				c.notify("ok:"+key, "CLOSED:"+reason)
			}
		}
	}
}

type loadSummary struct {
	Window     string                `json:"window"`
	Cats       map[string]catSummary `json:"latency"`
	Reasons    map[string]int        `json:"closed_reasons,omitempty"`
	WaitMax    int                   `json:"scan_waiting_max"`
	WaitMean   float64               `json:"scan_waiting_mean"`
	HoldMean   float64               `json:"scan_holding_mean"`
	GorMax     int                   `json:"goroutines_max"`
	MajFltPS   float64               `json:"majflt_per_s"`
	ReadMBps   float64               `json:"read_mb_per_s"`
	CPUPct     float64               `json:"cpu_pct"`
	MemMiB     float64               `json:"cgroup_mem_mib_last"`
	IOPressure string                `json:"cgroup_io_pressure_last"`
	OpenConns  int64                 `json:"open_conns"`
	LiveEvents int64                 `json:"events_received"`
	DialErrors int64                 `json:"dial_errors"`
}

type statWindow struct {
	n                int
	waitSum, holdSum int
	waitMax, gorMax  int
	first, last      stats
	firstAt, lastAt  time.Time
}

func (w *statWindow) add(s stats, at time.Time) {
	if w.n == 0 {
		w.first, w.firstAt = s, at
	}
	w.last, w.lastAt = s, at
	w.n++
	w.waitSum += s.ScanWaiting
	w.holdSum += s.ScanHolding
	w.waitMax = max(w.waitMax, s.ScanWaiting)
	w.gorMax = max(w.gorMax, s.Goroutines)
}

func (w *statWindow) fill(out *loadSummary) {
	if w.n == 0 {
		return
	}
	out.WaitMax, out.GorMax = w.waitMax, w.gorMax
	out.WaitMean = float64(w.waitSum) / float64(w.n)
	out.HoldMean = float64(w.holdSum) / float64(w.n)
	if secs := w.lastAt.Sub(w.firstAt).Seconds(); secs > 0 {
		out.MajFltPS = float64(w.last.MajFlt-w.first.MajFlt) / secs
		out.ReadMBps = float64(w.last.ReadBytes-w.first.ReadBytes) / secs / 1e6
		out.CPUPct = 100 * (w.last.CPUSeconds - w.first.CPUSeconds) / secs
	}
	out.MemMiB = float64(w.last.MemCurrent) / (1 << 20)
	out.IOPressure = w.last.IOPressure
}

func runLoad(args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	url := fs.String("url", "ws://127.0.0.1:7447", "relay websocket url")
	statsURL := fs.String("stats", "http://127.0.0.1:7448/stats", "serve's /stats url")
	samplePath := fs.String("sample", "notes.db.sample.json", "sample file written by gen")
	duration := fs.Duration("duration", 6*time.Minute, "total run time")
	warmup := fs.Duration("warmup", 2*time.Minute, "excluded from the final summary")
	connPer30s := fs.Float64("conns", 70, "new connections per 30s")
	lifeMin := fs.Duration("life-min", 60*time.Second, "shortest connection lifetime")
	lifeMax := fs.Duration("life-max", 180*time.Second, "longest connection lifetime")
	writeRate := fs.Float64("writes", 5, "events published per second")
	eoseTimeout := fs.Duration("eose-timeout", 60*time.Second, "REQ counted as timed out after this")
	interval := fs.Duration("interval", 15*time.Second, "progress report interval")
	out := fs.String("out", "", "write the final summary JSON here too")
	_ = fs.Parse(args)

	var smp sample
	b, err := os.ReadFile(*samplePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &smp); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	began := time.Now()
	warmEnd := began.Add(*warmup)

	interRec, totalRec := newRecorder(), newRecorder()
	both := func(f func(*recorder)) {
		f(interRec)
		if time.Now().After(warmEnd) {
			f(totalRec)
		}
	}
	var openConns, events, dialErrs atomic.Int64

	// Stats sampler.
	var swMu sync.Mutex
	var interSW, totalSW statWindow
	go func() {
		cl := http.Client{Timeout: 2 * time.Second}
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				resp, err := cl.Get(*statsURL)
				if err != nil {
					continue
				}
				var s stats
				_ = json.NewDecoder(resp.Body).Decode(&s)
				_ = resp.Body.Close()
				swMu.Lock()
				interSW.add(s, now)
				if now.After(warmEnd) {
					totalSW.add(s, now)
				}
				swMu.Unlock()
			}
		}
	}()

	// Writer: one long-lived connection publishing a small steady stream.
	go func() {
		c, err := dial(*url, &events, nil)
		if err != nil {
			dialErrs.Add(1)
			return
		}
		defer func() { _ = c.ws.Close() }()
		r := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 1))
		t := time.NewTicker(time.Duration(float64(time.Second) / *writeRate))
		defer t.Stop()
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			kind, cat := 1, "ok_kind1"
			var tags [][]string
			switch r.IntN(10) {
			case 0:
				kind, cat = 1059, "ok_kind1059"
				tags = [][]string{{"p", smp.Authors[r.IntN(len(smp.Authors))]}}
			case 1:
				kind, cat = 20001, "ok_ephemeral"
			}
			ev, err := nip01.NewSignedEvent(kind, fmt.Sprintf("relayload %d %d", i, time.Now().UnixNano()), writerKey, tags...)
			if err != nil {
				continue
			}
			go func() {
				ch := c.wait("ok:" + ev.ID)
				start := time.Now()
				if err := c.send([]any{"EVENT", ev}); err != nil {
					both(func(r *recorder) { r.close(cat, "send") })
					return
				}
				// Ephemeral events are acknowledged too.
				select {
				case m := <-ch:
					d := time.Since(start)
					if m == "OK" {
						both(func(r *recorder) { r.add(cat, d) })
					} else {
						both(func(r *recorder) { r.close(cat, strings.TrimPrefix(m, "CLOSED:")) })
					}
				case <-time.After(30 * time.Second):
					both(func(r *recorder) { r.timeout(cat) })
				}
			}()
		}
	}()

	client := func(seed uint64) {
		r := rand.New(rand.NewPCG(seed, 2))
		c, err := dial(*url, &events, func(d time.Duration) {
			both(func(rr *recorder) { rr.add("live_feed", d) })
		})
		if err != nil {
			dialErrs.Add(1)
			return
		}
		openConns.Add(1)
		defer openConns.Add(-1)
		defer func() { _ = c.ws.Close() }()
		life := *lifeMin + time.Duration(r.Int64N(int64(*lifeMax-*lifeMin)+1))
		deadline := time.After(life)

		rec := func(cat string, filter map[string]any, id string) bool {
			var ok bool
			ch := c.wait("sub:" + id)
			start := time.Now()
			if err := c.send([]any{"REQ", id, filter}); err != nil {
				both(func(rr *recorder) { rr.close(cat, "send") })
				return false
			}
			select {
			case m := <-ch:
				if m == "EOSE" {
					d := time.Since(start)
					both(func(rr *recorder) { rr.add(cat, d) })
					ok = true
				} else {
					both(func(rr *recorder) { rr.close(cat, strings.TrimPrefix(m, "CLOSED:")) })
				}
			case <-time.After(*eoseTimeout):
				both(func(rr *recorder) { rr.timeout(cat) })
			case <-ctx.Done():
			}
			return ok
		}

		// Feed and notifications stay open for the connection's life; the
		// two lookups close once answered, as a client would.
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); rec("eose_feed", map[string]any{"kinds": []int{1}, "limit": 100}, "feed") }()
		go func() {
			defer wg.Done()
			rec("eose_notif", map[string]any{"kinds": []int{1, 7}, "#p": []string{smp.Authors[r.IntN(len(smp.Authors))]}, "limit": 50}, "notif")
		}()
		ids := make([]string, 5)
		for i := range ids {
			ids[i] = smp.IDs[r.IntN(len(smp.IDs))]
		}
		go func() {
			defer wg.Done()
			rec("eose_ids", map[string]any{"ids": ids}, "ids")
			_ = c.send([]any{"CLOSE", "ids"})
		}()
		authors := make([]string, 10)
		for i := range authors {
			authors[i] = smp.Authors[r.IntN(len(smp.Authors))]
		}
		go func() {
			defer wg.Done()
			rec("eose_profiles", map[string]any{"kinds": []int{0}, "authors": authors}, "prof")
			_ = c.send([]any{"CLOSE", "prof"})
		}()

		select {
		case <-deadline:
		case <-ctx.Done():
		}
		_ = c.ws.Close()
		wg.Wait()
	}

	// Connection arrivals, Poisson at the requested rate.
	go func() {
		r := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 3))
		rate := *connPer30s / 30
		for i := uint64(0); ; i++ {
			wait := time.Duration(r.ExpFloat64() / rate * float64(time.Second))
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			go client(i + 100)
		}
	}()

	report := func(label string, rec *recorder, sw *statWindow, reset bool) loadSummary {
		s := loadSummary{Window: label, Cats: rec.snapshot(reset)}
		swMu.Lock()
		sw.fill(&s)
		if reset {
			*sw = statWindow{}
		}
		swMu.Unlock()
		s.OpenConns, s.LiveEvents, s.DialErrors = openConns.Load(), events.Load(), dialErrs.Load()
		return s
	}

	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s := report(time.Since(began).Round(time.Second).String(), interRec, &interSW, true)
			line, _ := json.Marshal(s)
			fmt.Println(string(line))
		case <-ctx.Done():
			s := report("summary (after warmup)", totalRec, &totalSW, false)
			totalRec.mu.Lock()
			s.Reasons = totalRec.reasons
			totalRec.mu.Unlock()
			res, _ := json.MarshalIndent(s, "", "  ")
			fmt.Println(string(res))
			if *out != "" {
				_ = os.WriteFile(*out, res, 0o644)
			}
			return nil
		}
	}
}
