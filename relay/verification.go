package relay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/config"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/search"
	"github.com/ohstr/nmilat/utils"
	"github.com/rs/zerolog"
)

// maxCheckBody bounds what's read from a NIP-05 or LNURL response; some
// servers return their whole names map.
const maxCheckBody = 2 << 20

// maxDeferred bounds the pubkeys remembered for a later check when the
// queue was full.
const maxDeferred = 100_000

type VerificationJob struct {
	Pubkey  string
	Nip05   string
	Lud16   string
	Picture string
	// Force fetches every field regardless of its schedule.
	Force bool
}

// ProfileVerificationWorker checks profiles' NIP-05, LUD-16 and picture.
// A field is fetched only when its value is new or changed, when its
// NextCheckAt comes (TTL or retry), or when forced; everything else reuses
// the stored result.
type ProfileVerificationWorker struct {
	store         *EventStore
	searchService search.Service
	cfg           VerificationConfig
	hosts         *hostLimiter
	jobChan       chan VerificationJob
	wg            sync.WaitGroup
	sweepWG       sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	logger        zerolog.Logger
	now           func() time.Time

	mu       sync.Mutex
	inflight map[string]bool
	deferred map[string]bool

	TotalProcessed atomic.Uint64
	TotalErrors    atomic.Uint64
	TotalEnqueued  atomic.Uint64
	// TotalDropped counts jobs that found the queue full; each is checked
	// later from the due queue rather than lost.
	TotalDropped atomic.Uint64
	// TotalFetches counts HTTP checks made.
	TotalFetches atomic.Uint64
	StartTime    time.Time
}

// NewProfileVerificationWorker inherits its logger from store, which already
// carries whatever WithEventStoreLogger the caller configured on it.
func NewProfileVerificationWorker(store *EventStore, searchService search.Service, cfg VerificationConfig) *ProfileVerificationWorker {
	ctx, cancel := context.WithCancel(context.Background())
	cfg = cfg.withDefaults()
	return &ProfileVerificationWorker{
		store:         store,
		searchService: searchService,
		cfg:           cfg,
		hosts:         newHostLimiter(cfg.PerHostInterval),
		jobChan:       make(chan VerificationJob, 1000),
		ctx:           ctx,
		cancel:        cancel,
		logger:        store.logger,
		now:           time.Now,
		inflight:      map[string]bool{},
		deferred:      map[string]bool{},
		StartTime:     time.Now(),
	}
}

// Start runs count workers and the sweeper that picks up due checks.
func (w *ProfileVerificationWorker) Start(count int) {
	for i := 0; i < count; i++ {
		w.wg.Add(1)
		go w.worker()
	}
	w.sweepWG.Add(1)
	go w.sweeper()
}

func (w *ProfileVerificationWorker) Stop() {
	w.cancel()
	w.sweepWG.Wait()
	close(w.jobChan)
	w.wg.Wait()
}

// QueueJob queues a check of a kind 0. When the queue is full the profile
// is remembered and checked later instead of dropped.
func (w *ProfileVerificationWorker) QueueJob(event *nip01.Event) {
	job, ok := jobFromEvent(event)
	if !ok {
		return
	}
	if !w.enqueue(job) {
		w.TotalDropped.Add(1)
		w.mu.Lock()
		if len(w.deferred) < maxDeferred {
			w.deferred[job.Pubkey] = true
		}
		w.mu.Unlock()
	}
}

func jobFromEvent(event *nip01.Event) (VerificationJob, bool) {
	if event == nil || event.Kind != 0 {
		return VerificationJob{}, false
	}
	var profile struct {
		Nip05   string `json:"nip05"`
		Lud16   string `json:"lud16"`
		Picture string `json:"picture"`
	}
	// Invalid content still produces a job: it clears stale results.
	_ = utils.UnmarshalJSON([]byte(event.Content), &profile)
	return VerificationJob{
		Pubkey:  event.PubKey,
		Nip05:   profile.Nip05,
		Lud16:   profile.Lud16,
		Picture: profile.Picture,
	}, true
}

// enqueue adds job without blocking, unless that profile is already queued.
func (w *ProfileVerificationWorker) enqueue(job VerificationJob) bool {
	w.mu.Lock()
	if w.inflight[job.Pubkey] && !job.Force {
		w.mu.Unlock()
		return true
	}
	w.inflight[job.Pubkey] = true
	w.mu.Unlock()

	select {
	case w.jobChan <- job:
		w.TotalEnqueued.Add(1)
		return true
	default:
		w.done(job.Pubkey)
		return false
	}
}

func (w *ProfileVerificationWorker) done(pubkey string) {
	w.mu.Lock()
	delete(w.inflight, pubkey)
	w.mu.Unlock()
}

func (w *ProfileVerificationWorker) isInflight(pubkey string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.inflight[pubkey]
}

func (w *ProfileVerificationWorker) worker() {
	defer w.wg.Done()
	for job := range w.jobChan {
		if w.ctx.Err() != nil {
			return
		}
		w.processJob(w.ctx, job)
		w.done(job.Pubkey)
	}
}

// sweeper persists deferred profiles and queues checks as they come due.
func (w *ProfileVerificationWorker) sweeper() {
	defer w.sweepWG.Done()
	ticker := time.NewTicker(w.cfg.SweepInterval)
	defer ticker.Stop()
	for {
		w.sweep()
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *ProfileVerificationWorker) sweep() {
	w.mu.Lock()
	var deferred []string
	for pk := range w.deferred {
		deferred = append(deferred, pk)
	}
	w.deferred = map[string]bool{}
	w.mu.Unlock()

	now := w.now().Unix()
	if len(deferred) > 0 {
		err := w.store.UpdateProfileMetricsBatch(deferred, func(m *ProfileMetrics) {
			if m.RequeueAt == 0 || m.RequeueAt > now {
				m.RequeueAt = now
			}
		})
		if err != nil {
			w.logger.Error().Err(err).Msg("failed to defer profile checks")
		}
	}

	// Fill at most half the queue so live kind 0s still fit.
	pubkeys, err := w.store.DueVerifications(now, cap(w.jobChan)/2, w.isInflight)
	if err != nil {
		w.logger.Error().Err(err).Msg("failed to read due profile checks")
		return
	}
	if len(pubkeys) == 0 {
		return
	}
	events, err := w.store.FetchProfileEvents(w.ctx, pubkeys)
	if err != nil {
		return
	}
	found := map[string]bool{}
	for _, ev := range events {
		if job, ok := jobFromEvent(ev); ok {
			found[ev.PubKey] = true
			if !w.enqueue(job) {
				return
			}
		}
	}
	// A profile with no stored kind 0 has nothing left to check.
	var gone []string
	for _, pk := range pubkeys {
		if !found[pk] {
			gone = append(gone, pk)
		}
	}
	if len(gone) > 0 {
		_ = w.store.UpdateProfileMetricsBatch(gone, func(m *ProfileMetrics) {
			m.Nip05.NextCheckAt, m.Lud16.NextCheckAt, m.Picture.NextCheckAt, m.RequeueAt = 0, 0, 0, 0
		})
	}
}

// VerifyNow checks a profile's latest stored kind 0 immediately, fetching
// every field regardless of schedule, and returns the stored result.
func (w *ProfileVerificationWorker) VerifyNow(ctx context.Context, pubkey string) (*ProfileMetrics, error) {
	events, err := w.store.FetchProfileEvents(ctx, []string{pubkey})
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, ErrEventNotFound
	}
	job, _ := jobFromEvent(events[0])
	job.Force = true
	w.processJob(ctx, job)
	return w.store.GetProfileMetrics(pubkey)
}

// checkOutcome classifies one fetch.
type checkOutcome int

const (
	outcomeOK checkOutcome = iota
	outcomeFailed
	outcomeTransient
)

type checkResult struct {
	outcome    checkOutcome
	err        string
	retryAfter time.Duration
	pay        *utils.PayResponse
}

func (w *ProfileVerificationWorker) processJob(ctx context.Context, job VerificationJob) {
	defer w.TotalProcessed.Add(1)

	metrics, err := w.store.GetProfileMetrics(job.Pubkey)
	if err != nil {
		w.logger.Error().Err(err).Msg("failed to get profile metrics for verification")
		w.TotalErrors.Add(1)
		return
	}
	now := w.now()

	type field struct {
		state *CheckState
		value string
		valid bool
		check func(context.Context, string) checkResult
	}
	nip05, lud16, picture := normalizeIdentifier(job.Nip05), normalizeIdentifier(job.Lud16), job.Picture
	fields := []field{
		{&metrics.Nip05, nip05, validIdentifier(nip05), func(ctx context.Context, v string) checkResult { return w.checkNip05(ctx, job.Pubkey, v) }},
		{&metrics.Lud16, lud16, validIdentifier(lud16), w.checkLud16},
		{&metrics.Picture, picture, utils.IsValidPictureURL(picture), w.checkPicture},
	}

	// Decide and fetch outside the metrics transaction.
	results := make([]*checkResult, len(fields))
	var wg sync.WaitGroup
	for i, f := range fields {
		if !w.needsFetch(f.state, f.value, f.valid, job.Force, now) {
			continue
		}
		wg.Add(1)
		go func(i int, f field) {
			defer wg.Done()
			r := f.check(ctx, f.value)
			results[i] = &r
		}(i, f)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	appCfg := config.Get()
	update := func(m *ProfileMetrics) {
		m.RequeueAt = 0
		states := []*CheckState{&m.Nip05, &m.Lud16, &m.Picture}
		for i, f := range fields {
			w.apply(states[i], f.value, f.valid, results[i], now)
		}
		if r := results[1]; r != nil && r.outcome == outcomeOK && r.pay != nil {
			m.Lud16Chains = len(r.pay.Chains)
			m.Lud16AllowsNostr = r.pay.AllowsNostr
			m.Lud16NostrPubkey = r.pay.NostrPubkey
		} else if m.Lud16.Status != CheckOK {
			m.Lud16Chains, m.Lud16AllowsNostr, m.Lud16NostrPubkey = 0, false, ""
		}
		scoreChecks(m, appCfg)
	}
	// Most kind 0s change nothing checked: skip the write and the push.
	next := *metrics
	update(&next)
	if next == *metrics {
		return
	}
	if err := w.store.UpdateProfileMetrics(job.Pubkey, update); err != nil {
		w.logger.Error().Err(err).Msg("failed to update profile metrics")
		w.TotalErrors.Add(1)
		return
	}

	if w.searchService != nil {
		if updated, err := w.store.GetProfileMetrics(job.Pubkey); err == nil {
			_ = w.searchService.UpdateScore(context.Background(), job.Pubkey, updated.TotalScore())
		}
	}
}

func normalizeIdentifier(id string) string {
	if name, domain, ok := utils.ParseIdentifier(id); ok {
		return name + "@" + domain
	}
	return id
}

func validIdentifier(id string) bool {
	_, _, ok := utils.ParseIdentifier(id)
	return ok
}

// needsFetch reports whether a field must be fetched now.
func (w *ProfileVerificationWorker) needsFetch(s *CheckState, value string, valid, force bool, now time.Time) bool {
	switch {
	case value == "" || !valid:
		return false
	case force || value != s.Value:
		return true
	default:
		return s.NextCheckAt > 0 && now.Unix() >= s.NextCheckAt
	}
}

// apply records a field's outcome. A transient failure keeps the previous
// status (and so the score) until retries run out.
func (w *ProfileVerificationWorker) apply(s *CheckState, value string, valid bool, r *checkResult, now time.Time) {
	ts := now.Unix()
	switch {
	case value == "":
		*s = CheckState{}
		return
	case !valid:
		*s = CheckState{Value: value, Status: CheckInvalid, CheckedAt: ts}
		return
	case r == nil:
		return
	}

	if value != s.Value {
		// Data from before checks were tracked keeps its score until the
		// first result; a changed identifier doesn't.
		legacy := s.Value == "" && s.Status == ""
		*s = CheckState{Value: value}
		if !legacy {
			s.Status = CheckPending
		}
	}
	s.CheckedAt = ts
	switch r.outcome {
	case outcomeOK, outcomeFailed:
		s.Status = CheckFailed
		if r.outcome == outcomeOK {
			s.Status, s.VerifiedAt = CheckOK, ts
		}
		s.Attempts, s.LastError = 0, ""
		s.NextCheckAt = w.expiry(now)
	case outcomeTransient:
		s.Attempts++
		s.LastError = r.err
		if s.Attempts < w.cfg.MaxAttempts {
			s.NextCheckAt = now.Add(w.backoff(s.Attempts, r.retryAfter)).Unix()
			return
		}
		// Out of retries: a recent success stands until it expires.
		if s.Status != CheckOK || (w.cfg.TTL > 0 && s.VerifiedAt+int64(w.cfg.TTL/time.Second) <= ts) {
			s.Status = CheckError
		}
		s.Attempts = 0
		s.NextCheckAt = w.expiry(now)
	}
}

func (w *ProfileVerificationWorker) expiry(now time.Time) int64 {
	if w.cfg.TTL < 0 {
		return 0
	}
	return now.Add(w.cfg.TTL).Unix()
}

// backoff doubles RetryInitial per attempt up to RetryMax; a longer
// Retry-After wins.
func (w *ProfileVerificationWorker) backoff(attempt int, retryAfter time.Duration) time.Duration {
	d := w.cfg.RetryInitial
	for i := 1; i < attempt && d < w.cfg.RetryMax; i++ {
		d *= 2
	}
	d = min(d, w.cfg.RetryMax)
	return max(d, retryAfter)
}

// scoreChecks derives the verification scores from the check statuses.
func scoreChecks(m *ProfileMetrics, appCfg *config.AppConfig) {
	cfg := appCfg.Search.Verification
	// A field with no status yet (data from before checks were tracked)
	// keeps its score.
	if m.Nip05.Status != "" || m.Nip05.Value == "" {
		m.Nip05Score = 0
		if m.Nip05.Status == CheckOK {
			m.Nip05Score = cfg.Nip05Score
		}
	}
	if m.Lud16.Status != "" || m.Lud16.Value == "" {
		m.Lud16Score = 0
		if m.Lud16.Status == CheckOK {
			m.Lud16Score = int64(max(m.Lud16Chains, 1)) * cfg.Lud16Score
			if cfg.Lud16ChainLimit > 0 && m.Lud16Score > cfg.Lud16ChainLimit {
				m.Lud16Score = cfg.Lud16ChainLimit
			}
		}
	}
	if m.Picture.Status != "" || m.Picture.Value == "" {
		m.PictureScore = 0
		if m.Picture.Status == CheckOK {
			m.PictureScore = appCfg.Search.Scoring.PictureBonus
		}
	}
}

func (w *ProfileVerificationWorker) checkNip05(ctx context.Context, pubkey, nip05 string) checkResult {
	status, body, retryAfter, err := w.fetch(ctx, http.MethodGet, utils.GetNip05URL(nip05), nil)
	if r, done := classify(status, retryAfter, err); done {
		return r
	}
	if !utils.VerifyNip05(bytes.NewReader(body), pubkey, nip05) {
		return checkResult{outcome: outcomeFailed, err: "pubkey not listed"}
	}
	return checkResult{outcome: outcomeOK}
}

func (w *ProfileVerificationWorker) checkLud16(ctx context.Context, lud16 string) checkResult {
	status, body, retryAfter, err := w.fetch(ctx, http.MethodGet, utils.GetLud16URL(lud16), nil)
	if r, done := classify(status, retryAfter, err); done {
		return r
	}
	pay, err := utils.ParsePayResponse(lud16, body)
	if err != nil {
		return checkResult{outcome: outcomeFailed, err: err.Error()}
	}
	return checkResult{outcome: outcomeOK, pay: pay}
}

func (w *ProfileVerificationWorker) checkPicture(ctx context.Context, picture string) checkResult {
	status, _, retryAfter, err := w.fetch(ctx, http.MethodHead, picture, nil)
	if err == nil && (status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented) {
		status, _, retryAfter, err = w.fetch(ctx, http.MethodGet, picture, http.Header{"Range": {"bytes=0-0"}})
	}
	if r, done := classify(status, retryAfter, err); done {
		return r
	}
	return checkResult{outcome: outcomeOK}
}

// classify turns anything but a 2xx into a result: 404/410 are
// definitive, everything else (network errors, 5xx, 429, 403 from a bot
// wall, ...) is transient.
func classify(status int, retryAfter time.Duration, err error) (checkResult, bool) {
	switch {
	case err != nil:
		return checkResult{outcome: outcomeTransient, err: err.Error()}, true
	case status >= 200 && status < 300:
		return checkResult{}, false
	case status == http.StatusNotFound || status == http.StatusGone:
		return checkResult{outcome: outcomeFailed, err: fmt.Sprintf("status %d", status)}, true
	default:
		return checkResult{outcome: outcomeTransient, err: fmt.Sprintf("status %d", status), retryAfter: retryAfter}, true
	}
}

// fetch makes one rate-limited request. GET bodies are read up to
// maxCheckBody.
func (w *ProfileVerificationWorker) fetch(ctx context.Context, method, rawURL string, header http.Header) (int, []byte, time.Duration, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return 0, nil, 0, fmt.Errorf("invalid url %q", rawURL)
	}
	if err := w.hosts.wait(ctx, u.Hostname()); err != nil {
		return 0, nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return 0, nil, 0, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", w.cfg.UserAgent)
	w.TotalFetches.Add(1)
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), w.now())
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		w.hosts.pause(u.Hostname(), max(retryAfter, w.cfg.PerHostInterval))
	}
	var body []byte
	if method == http.MethodGet {
		body, err = io.ReadAll(io.LimitReader(resp.Body, maxCheckBody))
		if err != nil {
			return 0, nil, 0, err
		}
	}
	return resp.StatusCode, body, retryAfter, nil
}

// parseRetryAfter reads seconds or an HTTP date; 0 if absent or invalid.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// hostLimiter spaces requests to each host by interval.
type hostLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     map[string]time.Time
}

func newHostLimiter(interval time.Duration) *hostLimiter {
	return &hostLimiter{interval: interval, next: map[string]time.Time{}}
}

// wait blocks until host may be requested again.
func (l *hostLimiter) wait(ctx context.Context, host string) error {
	l.mu.Lock()
	now := time.Now()
	at := l.next[host]
	if at.Before(now) {
		at = now
	}
	l.next[host] = at.Add(l.interval)
	if len(l.next) > 10_000 {
		for h, t := range l.next {
			if t.Before(now) {
				delete(l.next, h)
			}
		}
	}
	l.mu.Unlock()

	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// pause holds every request to host for d, e.g. after a 429.
func (l *hostLimiter) pause(host string, d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if until := time.Now().Add(d); until.After(l.next[host]) {
		l.next[host] = until
	}
}

// QueueDepth returns the number of jobs waiting for a worker.
func (w *ProfileVerificationWorker) QueueDepth() int { return len(w.jobChan) }

// GetStats returns thread-safe metadata about the worker workload
func (w *ProfileVerificationWorker) GetStats() map[string]interface{} {
	processed := w.TotalProcessed.Load()
	enqueued := w.TotalEnqueued.Load()
	errs := w.TotalErrors.Load()
	queueDepth := len(w.jobChan)

	// Items pending might slightly differ from queueDepth if currently processing
	pending := enqueued - processed

	uptime := time.Since(w.StartTime)
	itemsPerSec := 0.0
	if uptime.Seconds() > 0 {
		itemsPerSec = float64(processed) / uptime.Seconds()
	}

	return map[string]interface{}{
		"status":          "active",
		"uptime":          uptime.Round(time.Second).String(),
		"queue_depth":     queueDepth,
		"pending_jobs":    pending,
		"total_enqueued":  enqueued,
		"total_processed": processed,
		"total_dropped":   w.TotalDropped.Load(),
		"total_fetches":   w.TotalFetches.Load(),
		"total_errors":    errs,
		"items_per_sec":   fmt.Sprintf("%.1f", itemsPerSec),
	}
}
