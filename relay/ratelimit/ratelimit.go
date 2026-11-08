// Package ratelimit is an opt-in token-bucket rate limiter a relay keys by
// pubkey and by client IP: EVENT writes, REQ/COUNT reads, HTTP bridge
// requests, Blossom uploads and downloads, and concurrent connections per
// IP. Every limit is off until it is set: a zero Config limits nothing.
//
// A Limiter is shared: relay.WithRateLimiter hands it to the WebSocket
// sessions and the HTTP bridge, and AllowBlossom plugs it into
// nipB7/server's Options.RateLimit.
package ratelimit

import (
	"container/list"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// DefaultMaxKeys is Config.MaxKeys when it is 0.
const DefaultMaxKeys = 100_000

// Rate is a token bucket: Events requests per Per, with up to Burst at
// once. Events or Per zero means no limit; Burst zero means Events. New
// refuses a negative field, a Burst with no rate, and a rate finer than
// one token per nanosecond or a burst whose window overflows a
// time.Duration.
type Rate struct {
	Events int
	Per    time.Duration
	Burst  int
}

func (r Rate) enabled() bool { return r.Events > 0 && r.Per > 0 }

// interval is the time one token takes to refill.
func (r Rate) interval() time.Duration { return r.Per / time.Duration(r.Events) }

// tolerance is how far ahead of now a key may run: its burst less one.
// It saturates rather than overflow; New refuses a Rate that would.
func (r Rate) tolerance() time.Duration {
	burst := r.burst()
	iv := r.interval()
	if burst <= 1 || iv <= 0 {
		return 0
	}
	if int64(burst-1) > math.MaxInt64/int64(iv) {
		return math.MaxInt64
	}
	return time.Duration(burst-1) * iv
}

func (r Rate) burst() int {
	if r.Burst <= 0 {
		return r.Events
	}
	return r.Burst
}

// validate reports what is wrong with r, naming it field.
func (r Rate) validate(field string) error {
	switch {
	case r.Events < 0 || r.Per < 0 || r.Burst < 0:
		return fmt.Errorf("ratelimit: %s: Events, Per and Burst must not be negative", field)
	case !r.enabled():
		if r.Burst > 0 {
			return fmt.Errorf("ratelimit: %s: Burst needs Events and Per", field)
		}
		return nil
	case r.interval() <= 0:
		return fmt.Errorf("ratelimit: %s: %d events per %s is under 1ns each", field, r.Events, r.Per)
	case int64(r.burst()-1) > math.MaxInt64/int64(r.interval()):
		return fmt.Errorf("ratelimit: %s: Burst %d at %s each overflows a time.Duration", field, r.burst(), r.interval())
	}
	return nil
}

// Limit is one action's limits, each counted on its own: per signer or
// authenticated pubkey, and per client IP.
type Limit struct {
	PerPubkey Rate
	PerIP     Rate
}

// Action is what a request does, each with its own Limit.
type Action uint8

const (
	// Event is an EVENT write (and an event POSTed to /events).
	Event Action = iota
	// Read is a REQ or COUNT.
	Read
	// HTTP is an HTTP bridge request: POST /query, /count or /events.
	HTTP
	// Upload is a Blossom upload.
	Upload
	// Download is any other Blossom request: GET, HEAD, DELETE.
	Download
	numActions
)

var actionNames = [numActions]string{"events", "requests", "requests", "uploads", "requests"}

// limitNames are Config's field names, for errors.
var limitNames = [numActions]string{"Event", "Read", "HTTP", "Upload", "Download"}

// Config sets a Limiter's limits. The zero value limits nothing.
type Config struct {
	Event    Limit
	Read     Limit
	HTTP     Limit
	Upload   Limit
	Download Limit

	// MaxConnsPerIP caps concurrent WebSocket connections from one IP.
	// 0 means no cap.
	MaxConnsPerIP int

	// Exempt, when set, exempts a pubkey from every per-pubkey limit (the
	// per-IP limits still apply), e.g. a relay's members and admins. It
	// must be safe for concurrent use.
	Exempt func(pubkey string) bool

	// TrustedProxies are the CIDRs (or bare IPs) of reverse proxies whose
	// X-Forwarded-For and X-Real-IP headers name the client. Empty trusts
	// no header: the client is the connection's remote address.
	TrustedProxies []string

	// MaxKeys bounds how many pubkeys or IPs each limit tracks at once; the
	// least recently seen is forgotten first. 0 means DefaultMaxKeys.
	MaxKeys int

	// Now is the clock; nil means time.Now. For tests.
	Now func() time.Time
}

// Limiter enforces a Config. A nil *Limiter limits nothing, so callers
// never nil-check. Safe for concurrent use.
type Limiter struct {
	cfg     Config
	now     func() time.Time
	proxies []netip.Prefix

	pubkey [numActions]*table
	ip     [numActions]*table

	connMu sync.Mutex
	conns  map[string]int
}

// New returns a Limiter for cfg, or an error naming the field for a
// malformed Rate or TrustedProxies entry.
func New(cfg Config) (*Limiter, error) {
	limits := [numActions]Limit{cfg.Event, cfg.Read, cfg.HTTP, cfg.Upload, cfg.Download}
	for a, lim := range limits {
		if err := lim.PerPubkey.validate(limitNames[a] + ".PerPubkey"); err != nil {
			return nil, err
		}
		if err := lim.PerIP.validate(limitNames[a] + ".PerIP"); err != nil {
			return nil, err
		}
	}
	l := &Limiter{cfg: cfg, now: cfg.Now, conns: make(map[string]int)}
	if l.now == nil {
		l.now = time.Now
	}
	for _, s := range cfg.TrustedProxies {
		p, err := parsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("ratelimit: trusted proxy %q: %w", s, err)
		}
		l.proxies = append(l.proxies, p)
	}
	maxKeys := cfg.MaxKeys
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	for a, lim := range limits {
		if lim.PerPubkey.enabled() {
			l.pubkey[a] = newTable(lim.PerPubkey, maxKeys)
		}
		if lim.PerIP.enabled() {
			l.ip[a] = newTable(lim.PerIP, maxKeys)
		}
	}
	return l, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Allow takes one token for action from ip's bucket and pubkey's, skipping
// whichever is "" or has no limit; an exempt pubkey skips its own. When
// either bucket is empty it takes nothing and reports how long until a
// retry may pass.
func (l *Limiter) Allow(action Action, ip, pubkey string) (retryAfter time.Duration, ok bool) {
	if l == nil || action >= numActions {
		return 0, true
	}
	now := l.now()
	ipt := l.ip[action]
	if ip == "" {
		ipt = nil
	}
	if ipt != nil {
		if wait, ok := ipt.take(ip, now); !ok {
			return wait, false
		}
	}
	pkt := l.pubkey[action]
	if pubkey == "" || (pkt != nil && l.cfg.Exempt != nil && l.cfg.Exempt(pubkey)) {
		pkt = nil
	}
	if pkt != nil {
		if wait, ok := pkt.take(pubkey, now); !ok {
			if ipt != nil {
				ipt.refund(ip)
			}
			return wait, false
		}
	}
	return 0, true
}

// Message is the NIP-01 refusal for action: "rate-limited: too many ...".
func Message(action Action) string {
	if action >= numActions {
		return "rate-limited: slow down"
	}
	return "rate-limited: too many " + actionNames[action] + ", slow down"
}

// ConnMessage is the body of a connection refused for MaxConnsPerIP.
const ConnMessage = "rate-limited: too many connections from this address"

// RetryAfterSeconds is wait as a Retry-After value: whole seconds, at
// least 1.
func RetryAfterSeconds(wait time.Duration) int {
	s := int(math.Ceil(wait.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}

// Refuse writes a 429 with Retry-After and action's Message.
func Refuse(w http.ResponseWriter, action Action, wait time.Duration) {
	w.Header().Set("Retry-After", fmt.Sprint(RetryAfterSeconds(wait)))
	http.Error(w, Message(action), http.StatusTooManyRequests)
}

// OpenConn counts a connection from ip, reporting false (and counting
// nothing) when ip already has MaxConnsPerIP open. Call release once the
// connection ends.
func (l *Limiter) OpenConn(ip string) (release func(), ok bool) {
	if l == nil || l.cfg.MaxConnsPerIP <= 0 || ip == "" {
		return func() {}, true
	}
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if l.conns[ip] >= l.cfg.MaxConnsPerIP {
		return nil, false
	}
	l.conns[ip]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.connMu.Lock()
			defer l.connMu.Unlock()
			if l.conns[ip]--; l.conns[ip] <= 0 {
				delete(l.conns, ip)
			}
		})
	}, true
}

// ClientIP is the key r is counted under: its remote address, or, when
// that is a trusted proxy, the client the proxy names (the rightmost
// X-Forwarded-For hop that isn't itself a trusted proxy, else X-Real-IP).
// An IPv6 client is keyed by its /64, the block one host usually holds.
func (l *Limiter) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if l != nil && l.trusted(addr) {
		if a, ok := l.forwarded(r); ok {
			addr = a
		}
	}
	return key(addr)
}

func (l *Limiter) trusted(a netip.Addr) bool {
	for _, p := range l.proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// forwarded reads the client a trusted proxy names.
func (l *Limiter) forwarded(r *http.Request) (netip.Addr, bool) {
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !l.trusted(a) {
			return a, true
		}
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

func key(a netip.Addr) string {
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// AllowBlossom fits nipB7/server's Options.RateLimit: called with pubkey
// "" it takes from r's client IP, and with the authorization's signer from
// that pubkey alone, so a request is counted once per key. upload picks
// Upload, otherwise Download.
func (l *Limiter) AllowBlossom(r *http.Request, upload bool, pubkey string) (time.Duration, bool) {
	if l == nil {
		return 0, true
	}
	action := Download
	if upload {
		action = Upload
	}
	if pubkey != "" {
		return l.Allow(action, "", pubkey)
	}
	return l.Allow(action, l.ClientIP(r), "")
}

// table holds one Rate's buckets, by key, least recently used last. A
// bucket is kept as the time it will be full again (GCRA), so the math is
// exact and a bucket that is full needs no state at all.
type table struct {
	interval  time.Duration
	tolerance time.Duration
	maxKeys   int

	mu   sync.Mutex
	keys map[string]*list.Element
	lru  list.List
}

type bucket struct {
	key string
	// full is when the bucket is full again; each token taken moves it one
	// interval later.
	full time.Time
}

func newTable(r Rate, maxKeys int) *table {
	return &table{interval: r.interval(), tolerance: r.tolerance(), maxKeys: maxKeys, keys: make(map[string]*list.Element)}
}

// take spends one of k's tokens.
func (t *table) take(k string, now time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b *bucket
	if e, ok := t.keys[k]; ok {
		t.lru.MoveToFront(e)
		b = e.Value.(*bucket)
	} else {
		b = &bucket{key: k, full: now}
		t.keys[k] = t.lru.PushFront(b)
	}
	if b.full.Before(now) {
		b.full = now
	}
	t.evict(now)

	if ahead := b.full.Sub(now); ahead > t.tolerance {
		return ahead - t.tolerance, false
	}
	b.full = b.full.Add(t.interval)
	return 0, true
}

// refund gives back a token take spent.
func (t *table) refund(k string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.keys[k]; ok {
		b := e.Value.(*bucket)
		b.full = b.full.Add(-t.interval)
	}
}

// evict forgets buckets that are full again, which a fresh one would
// equal, from the least recently used end, and past maxKeys the oldest
// even if not. Each call does a bounded amount of work.
func (t *table) evict(now time.Time) {
	for range 8 {
		e := t.lru.Back()
		if e == nil || e == t.lru.Front() || e.Value.(*bucket).full.After(now) {
			break
		}
		t.remove(e)
	}
	for len(t.keys) > t.maxKeys {
		t.remove(t.lru.Back())
	}
}

func (t *table) remove(e *list.Element) {
	delete(t.keys, e.Value.(*bucket).key)
	t.lru.Remove(e)
}

// size is how many keys t tracks.
func (t *table) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keys)
}
