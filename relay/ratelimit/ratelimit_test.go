package ratelimit

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a manual clock: tests advance it instead of sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newLimiter(t *testing.T, cfg Config) (*Limiter, *clock) {
	t.Helper()
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	cfg.Now = c.now
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l, c
}

func allowed(l *Limiter, a Action, ip, pk string, n int) int {
	got := 0
	for range n {
		if _, ok := l.Allow(a, ip, pk); ok {
			got++
		}
	}
	return got
}

func TestZeroConfigLimitsNothing(t *testing.T) {
	l, _ := newLimiter(t, Config{})
	for a := range numActions {
		if got := allowed(l, a, "1.2.3.4", "pk", 10_000); got != 10_000 {
			t.Fatalf("action %d: %d of 10000 allowed with no limits", a, got)
		}
	}
	for range 1000 {
		if _, ok := l.OpenConn("1.2.3.4"); !ok {
			t.Fatal("a connection was refused with no MaxConnsPerIP")
		}
	}
	var nilLimiter *Limiter
	if _, ok := nilLimiter.Allow(Event, "1.2.3.4", "pk"); !ok {
		t.Fatal("a nil Limiter refused")
	}
	if _, ok := nilLimiter.OpenConn("1.2.3.4"); !ok {
		t.Fatal("a nil Limiter refused a connection")
	}
	// A Rate with only one of Events and Per set is no limit either.
	l, _ = newLimiter(t, Config{Event: Limit{PerIP: Rate{Events: 1}, PerPubkey: Rate{Per: time.Second}}})
	if got := allowed(l, Event, "1.2.3.4", "pk", 100); got != 100 {
		t.Fatalf("%d of 100 allowed by half-set rates", got)
	}
}

func TestBurstThenRefill(t *testing.T) {
	// 10 per minute, bursts of 5.
	l, c := newLimiter(t, Config{Event: Limit{PerPubkey: Rate{Events: 10, Per: time.Minute, Burst: 5}}})
	if got := allowed(l, Event, "", "pk", 20); got != 5 {
		t.Fatalf("burst: %d allowed, want 5", got)
	}
	wait, ok := l.Allow(Event, "", "pk")
	if ok || wait != 6*time.Second {
		t.Fatalf("empty bucket: ok %v, retry after %v, want 6s", ok, wait)
	}
	c.advance(5999 * time.Millisecond)
	if _, ok := l.Allow(Event, "", "pk"); ok {
		t.Fatal("allowed before a token refilled")
	}
	c.advance(time.Millisecond)
	if _, ok := l.Allow(Event, "", "pk"); !ok {
		t.Fatal("refused once a token refilled")
	}
	// A long idle refills to the burst, never beyond it.
	c.advance(time.Hour)
	if got := allowed(l, Event, "", "pk", 20); got != 5 {
		t.Fatalf("after idle: %d allowed, want 5", got)
	}
}

func TestBurstDefaultsToEvents(t *testing.T) {
	l, _ := newLimiter(t, Config{Read: Limit{PerIP: Rate{Events: 3, Per: time.Second}}})
	if got := allowed(l, Read, "1.2.3.4", "", 10); got != 3 {
		t.Fatalf("%d allowed, want 3", got)
	}
}

func TestPubkeyAndIPAreIndependent(t *testing.T) {
	l, _ := newLimiter(t, Config{Event: Limit{
		PerPubkey: Rate{Events: 2, Per: time.Hour},
		PerIP:     Rate{Events: 3, Per: time.Hour},
	}})
	// One pubkey from several IPs: the pubkey limit binds.
	got := 0
	for i := range 5 {
		if _, ok := l.Allow(Event, fmt.Sprintf("10.0.0.%d", i), "alice"); ok {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("alice from 5 IPs: %d allowed, want 2", got)
	}
	// Several pubkeys from one IP: the IP limit binds.
	got = 0
	for i := range 5 {
		if _, ok := l.Allow(Event, "10.0.1.1", fmt.Sprintf("pk%d", i)); ok {
			got++
		}
	}
	if got != 3 {
		t.Fatalf("5 pubkeys from one IP: %d allowed, want 3", got)
	}
	// Actions are independent too.
	if _, ok := l.Allow(Read, "10.0.1.1", "alice"); !ok {
		t.Fatal("an Event limit refused a Read")
	}
}

func TestPubkeyRefusalRefundsTheIPToken(t *testing.T) {
	l, _ := newLimiter(t, Config{Event: Limit{
		PerPubkey: Rate{Events: 1, Per: time.Hour},
		PerIP:     Rate{Events: 2, Per: time.Hour},
	}})
	l.Allow(Event, "1.1.1.1", "alice")
	for range 10 {
		l.Allow(Event, "1.1.1.1", "alice") // refused by alice's bucket
	}
	if _, ok := l.Allow(Event, "1.1.1.1", "bob"); !ok {
		t.Fatal("alice's refused events spent the IP's tokens")
	}
}

func TestExemptSkipsOnlyPerPubkey(t *testing.T) {
	l, _ := newLimiter(t, Config{
		Event:  Limit{PerPubkey: Rate{Events: 1, Per: time.Hour}, PerIP: Rate{Events: 5, Per: time.Hour}},
		Exempt: func(pk string) bool { return pk == "admin" },
	})
	got := 0
	for i := range 50 {
		if _, ok := l.Allow(Event, fmt.Sprintf("10.0.0.%d", i), "admin"); ok {
			got++
		}
	}
	if got != 50 {
		t.Fatalf("exempt pubkey: %d of 50 allowed", got)
	}
	if got := allowed(l, Event, "9.9.9.9", "admin", 10); got != 5 {
		t.Fatalf("exempt pubkey from one IP: %d allowed, want the IP's 5", got)
	}
	if got := allowed(l, Event, "", "user", 10); got != 1 {
		t.Fatalf("other pubkey: %d allowed, want 1", got)
	}
}

func TestNewRejectsMalformedRates(t *testing.T) {
	cases := []struct {
		name  string
		cfg   Config
		field string
	}{
		{"negative events", Config{Event: Limit{PerPubkey: Rate{Events: -1, Per: time.Second}}}, "Event.PerPubkey"},
		{"negative per", Config{Read: Limit{PerIP: Rate{Events: 1, Per: -time.Second}}}, "Read.PerIP"},
		{"negative burst", Config{HTTP: Limit{PerIP: Rate{Events: 1, Per: time.Second, Burst: -2}}}, "HTTP.PerIP"},
		{"burst without events", Config{Upload: Limit{PerPubkey: Rate{Burst: 5}}}, "Upload.PerPubkey"},
		{"burst without per", Config{Upload: Limit{PerIP: Rate{Events: 3, Burst: 5}}}, "Upload.PerIP"},
		{"interval under 1ns", Config{Download: Limit{PerIP: Rate{Events: 2_000_000_000, Per: time.Second}}}, "Download.PerIP"},
		{"burst overflows", Config{Event: Limit{PerIP: Rate{Events: 1, Per: time.Hour, Burst: math.MaxInt32}}}, "Event.PerIP"},
	}
	for _, c := range cases {
		_, err := New(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s: err %v, want one naming %s", c.name, err, c.field)
		}
	}
	// The largest burst that fits is accepted.
	if _, err := New(Config{Event: Limit{PerIP: Rate{Events: 1, Per: time.Hour, Burst: int(math.MaxInt64/int64(time.Hour)) + 1}}}); err != nil {
		t.Fatalf("largest burst refused: %v", err)
	}
}

func TestToleranceSaturates(t *testing.T) {
	r := Rate{Events: 1, Per: time.Hour, Burst: math.MaxInt32}
	if got := r.tolerance(); got != math.MaxInt64 {
		t.Fatalf("tolerance %d, want saturated", got)
	}
	if got := (Rate{Events: 1, Per: time.Second}).tolerance(); got != 0 {
		t.Fatalf("burst 1 tolerance %s, want 0", got)
	}
}

func TestEvictionIsBounded(t *testing.T) {
	l, c := newLimiter(t, Config{Read: Limit{PerIP: Rate{Events: 1, Per: time.Hour}}, MaxKeys: 100})
	tab := l.ip[Read]
	for i := range 10_000 {
		l.Allow(Read, fmt.Sprintf("ip%d", i), "")
	}
	if n := tab.size(); n != 100 {
		t.Fatalf("%d keys tracked, want MaxKeys 100", n)
	}
	// Refilled buckets are forgotten as new keys arrive.
	c.advance(2 * time.Hour)
	for i := range 50 {
		l.Allow(Read, fmt.Sprintf("new%d", i), "")
	}
	if n := tab.size(); n > 60 {
		t.Fatalf("%d keys tracked after the old ones refilled", n)
	}
}

func TestFullTableForgetsRefilledBucketsFirst(t *testing.T) {
	l, c := newLimiter(t, Config{Read: Limit{PerIP: Rate{Events: 1, Per: time.Minute, Burst: 2}}, MaxKeys: 2})
	tab := l.ip[Read]
	// "limited" spends its whole burst first, so it is the least recently
	// seen; "refilled" spends one token after it and is full again first.
	l.Allow(Read, "limited", "")
	l.Allow(Read, "limited", "")
	c.advance(time.Second)
	l.Allow(Read, "refilled", "")
	c.advance(time.Minute)
	l.Allow(Read, "new", "")
	if _, ok := tab.keys["limited"]; !ok {
		t.Fatal("a still-limited bucket was forgotten while a refilled one was there")
	}
	if _, ok := tab.keys["refilled"]; ok {
		t.Fatal("the refilled bucket was kept")
	}
	if n := tab.size(); n != 2 {
		t.Fatalf("%d keys, want 2", n)
	}

	// With every bucket still limited, the least recently seen goes.
	l2, _ := newLimiter(t, Config{Read: Limit{PerIP: Rate{Events: 1, Per: time.Hour}}, MaxKeys: 2})
	l2.Allow(Read, "a", "")
	l2.Allow(Read, "b", "")
	l2.Allow(Read, "c", "")
	if _, ok := l2.Allow(Read, "a", ""); !ok {
		t.Fatal("the least recently seen key was not the one forgotten")
	}
}

func TestRefilledBucketsAreForgotten(t *testing.T) {
	l, c := newLimiter(t, Config{Read: Limit{PerIP: Rate{Events: 10, Per: time.Second}}})
	tab := l.ip[Read]
	for i := range 1000 {
		l.Allow(Read, fmt.Sprintf("ip%d", i), "")
		c.advance(10 * time.Millisecond)
	}
	// Each bucket refills one token in 100ms; only the last few are not
	// back to full.
	if n := tab.size(); n > 20 {
		t.Fatalf("%d keys tracked, want only the recently used", n)
	}
}

func TestOpenConn(t *testing.T) {
	l, _ := newLimiter(t, Config{MaxConnsPerIP: 2})
	r1, ok1 := l.OpenConn("1.1.1.1")
	_, ok2 := l.OpenConn("1.1.1.1")
	_, ok3 := l.OpenConn("1.1.1.1")
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("opens: %v %v %v, want true true false", ok1, ok2, ok3)
	}
	if _, ok := l.OpenConn("2.2.2.2"); !ok {
		t.Fatal("another IP was refused")
	}
	r1()
	r1() // twice is once
	if _, ok := l.OpenConn("1.1.1.1"); !ok {
		t.Fatal("refused after a release")
	}
	if _, ok := l.OpenConn("1.1.1.1"); ok {
		t.Fatal("a double release freed two slots")
	}
}

func TestClientIP(t *testing.T) {
	l, err := New(Config{TrustedProxies: []string{"10.0.0.0/8", "::1"}})
	if err != nil {
		t.Fatal(err)
	}
	req := func(remote string, h map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		name   string
		remote string
		h      map[string]string
		want   string
	}{
		{"direct", "203.0.113.5:1234", nil, "203.0.113.5"},
		{"untrusted peer's header ignored", "203.0.113.5:1234", map[string]string{"X-Forwarded-For": "1.1.1.1"}, "203.0.113.5"},
		{"trusted proxy", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "1.1.1.1"}, "1.1.1.1"},
		{"rightmost untrusted hop", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "6.6.6.6, 1.1.1.1, 10.9.9.9"}, "1.1.1.1"},
		{"X-Real-IP", "10.1.2.3:80", map[string]string{"X-Real-IP": "2.2.2.2"}, "2.2.2.2"},
		{"trusted proxy with no header", "10.1.2.3:80", nil, "10.1.2.3"},
		{"ipv6 keyed by /64", "[2001:db8:1:2:3:4:5:6]:443", nil, "2001:db8:1:2::/64"},
		{"trusted ipv6 loopback", "[::1]:443", map[string]string{"X-Real-IP": "4.4.4.4"}, "4.4.4.4"},
		{"mapped ipv4", "[::ffff:192.0.2.1]:1", nil, "192.0.2.1"},
		{"X-Real-IP ignored beside X-Forwarded-For", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "1.1.1.1", "X-Real-IP": "2.2.2.2"}, "1.1.1.1"},
		{"X-Real-IP ignored when every hop is trusted", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "10.9.9.9", "X-Real-IP": "2.2.2.2"}, "10.1.2.3"},
		{"hop with a port", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "1.2.3.4:5678"}, "1.2.3.4"},
		{"bracketed ipv6 hop", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "[2001:db8::1]"}, "2001:db8::/64"},
		{"bracketed ipv6 hop with a port", "10.1.2.3:80", map[string]string{"X-Forwarded-For": " [2001:db8::1]:443 "}, "2001:db8::/64"},
		{"malformed hop skipped", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "5.5.5.5, unknown"}, "5.5.5.5"},
		{"malformed hop past a trusted one", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "5.5.5.5, unknown, 10.8.8.8"}, "5.5.5.5"},
		{"nothing usable falls back", "10.1.2.3:80", map[string]string{"X-Forwarded-For": "unknown, garbage"}, "10.1.2.3"},
		{"zoned remote", "[fe80::1%eth0]:80", nil, "fe80::/64"},
	}
	for _, c := range cases {
		if got := l.ClientIP(req(c.remote, c.h)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if _, err := New(Config{TrustedProxies: []string{"not-an-ip"}}); err == nil {
		t.Fatal("a malformed trusted proxy was accepted")
	}
}

func TestTrustedProxyForms(t *testing.T) {
	cases := []struct {
		proxy, remote string
	}{
		{"::ffff:10.0.0.0/104", "10.1.2.3:80"},
		{"::ffff:10.1.2.3", "10.1.2.3:80"},
		{"fe80::1%eth0", "[fe80::1%eth0]:80"},
		{"fe80::1%eth0/128", "[fe80::1]:80"},
		{" 10.0.0.0/8 ", "10.1.2.3:80"},
	}
	for _, c := range cases {
		l, err := New(Config{TrustedProxies: []string{c.proxy}})
		if err != nil {
			t.Fatalf("%s: %v", c.proxy, err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		r.Header.Set("X-Forwarded-For", "1.1.1.1")
		if got := l.ClientIP(r); got != "1.1.1.1" {
			t.Errorf("proxy %s, remote %s: %q, want the forwarded client", c.proxy, c.remote, got)
		}
	}
	if _, err := New(Config{TrustedProxies: []string{"::ffff:0.0.0.0/80"}}); err == nil {
		t.Fatal("an IPv4-mapped prefix wider than IPv4 was accepted")
	}
}

func TestRefuseWritesRetryAfter(t *testing.T) {
	w := httptest.NewRecorder()
	Refuse(w, HTTP, 1500*time.Millisecond)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "2" {
		t.Fatalf("status %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	if RetryAfterSeconds(0) != 1 {
		t.Fatal("Retry-After 0")
	}
}

func TestAllowBlossomCountsEachKeyOnce(t *testing.T) {
	l, _ := newLimiter(t, Config{Upload: Limit{PerIP: Rate{Events: 2, Per: time.Hour}, PerPubkey: Rate{Events: 1, Per: time.Hour}}})
	r := httptest.NewRequest(http.MethodPut, "/upload", nil)
	r.RemoteAddr = "1.2.3.4:5"
	if _, ok := l.AllowBlossom(r, true, ""); !ok {
		t.Fatal("first upload refused by IP")
	}
	if _, ok := l.AllowBlossom(r, true, "alice"); !ok {
		t.Fatal("first upload refused by pubkey")
	}
	if _, ok := l.AllowBlossom(r, true, ""); !ok {
		t.Fatal("second upload refused by IP")
	}
	if _, ok := l.AllowBlossom(r, true, "alice"); ok {
		t.Fatal("second upload allowed for alice")
	}
	if _, ok := l.AllowBlossom(r, false, ""); !ok {
		t.Fatal("a download was counted as an upload")
	}
}

func TestConcurrentUse(t *testing.T) {
	l, _ := newLimiter(t, Config{
		Event:         Limit{PerPubkey: Rate{Events: 100, Per: time.Hour}, PerIP: Rate{Events: 1000, Per: time.Hour}},
		MaxConnsPerIP: 5,
		MaxKeys:       10,
	})
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := 0
	for g := range 16 {
		wg.Go(func() {
			for i := range 200 {
				if _, ok := l.Allow(Event, fmt.Sprintf("ip%d", i%3), "pk"); ok {
					mu.Lock()
					got++
					mu.Unlock()
				}
				if rel, ok := l.OpenConn(fmt.Sprintf("ip%d", g)); ok {
					rel()
				}
			}
		})
	}
	wg.Wait()
	if got != 100 {
		t.Fatalf("%d allowed concurrently, want exactly 100", got)
	}
}
