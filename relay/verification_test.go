package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/config"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/relay/migrations"
	"github.com/ohstr/nmilat/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

const testPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

// fakeWeb answers requests per host without a network; a host with no
// handler fails like an unreachable server.
type fakeWeb struct {
	mu       sync.Mutex
	hosts    map[string]http.HandlerFunc
	requests map[string]int
}

func newFakeWeb() *fakeWeb {
	return &fakeWeb{hosts: map[string]http.HandlerFunc{}, requests: map[string]int{}}
}

func (f *fakeWeb) set(host string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts[host] = h
}

func (f *fakeWeb) count(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[host]
}

func (f *fakeWeb) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	h := f.hosts[req.URL.Hostname()]
	f.requests[req.URL.Hostname()]++
	f.mu.Unlock()
	if h == nil {
		return nil, errors.New("dial tcp: connection refused")
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Result(), nil
}

func nip05JSON(names map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"names": names})
	}
}

func statusHandler(code int, retryAfter string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(code)
	}
}

type verifyFixture struct {
	t     *testing.T
	store *EventStore
	web   *fakeWeb
	w     *ProfileVerificationWorker
	now   time.Time
}

func newVerifyFixture(t *testing.T, cfg VerificationConfig) *verifyFixture {
	f := &verifyFixture{t: t, store: newStore(t), web: newFakeWeb(), now: time.Unix(1_700_000_000, 0)}
	cfg.HTTPClient = &http.Client{Transport: f.web}
	if cfg.PerHostInterval == 0 {
		cfg.PerHostInterval = time.Nanosecond
	}
	f.w = NewProfileVerificationWorker(f.store, nil, cfg)
	f.w.now = func() time.Time { return f.now }
	return f
}

func (f *verifyFixture) profile(content map[string]string) *nip01.Event {
	raw, _ := json.Marshal(content)
	ev := &nip01.Event{PubKey: publicKey, CreatedAt: uint64(f.now.Unix()), Kind: 0, Content: string(raw)}
	require.NoError(f.t, ev.Sign(testPrivKey))
	return ev
}

// run processes a kind 0 synchronously and returns the stored metrics.
func (f *verifyFixture) run(content map[string]string, force bool) *ProfileMetrics {
	job, ok := jobFromEvent(f.profile(content))
	require.True(f.t, ok)
	job.Force = force
	f.w.processJob(context.Background(), job)
	m, err := f.store.GetProfileMetrics(publicKey)
	require.NoError(f.t, err)
	return m
}

func TestVerification_LongTLDIsChecked(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("nostrplebs.social", nip05JSON(map[string]string{"bob": publicKey}))

	m := f.run(map[string]string{"nip05": " Bob@NostrPlebs.social"}, false)

	assert.Equal(t, CheckOK, m.Nip05.Status)
	assert.Equal(t, "bob@nostrplebs.social", m.Nip05.Value)
	assert.Equal(t, int64(50), m.Nip05Score)
	assert.Equal(t, f.now.Add(DefaultVerificationTTL).Unix(), m.Nip05.NextCheckAt)
}

func TestVerification_UnchangedProfileIsNotRefetched(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))

	f.run(map[string]string{"nip05": "bob@example.com"}, false)
	f.now = f.now.Add(time.Hour)
	f.run(map[string]string{"nip05": "bob@example.com"}, false)
	f.run(map[string]string{"nip05": "bob@example.com", "name": "Bob", "about": "changed"}, false)

	assert.Equal(t, 1, f.web.count("example.com"))
}

func TestVerification_ChangedIdentifierIsRefetched(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("old.com", nip05JSON(map[string]string{"bob": publicKey}))
	f.run(map[string]string{"nip05": "bob@old.com"}, false)

	// The new server is down: the old identifier's score must not carry over.
	m := f.run(map[string]string{"nip05": "bob@new.com"}, false)
	assert.Equal(t, 1, f.web.count("new.com"))
	assert.Equal(t, CheckPending, m.Nip05.Status)
	assert.Equal(t, int64(0), m.Nip05Score)

	f.web.set("new.com", nip05JSON(map[string]string{"bob": publicKey}))
	f.now = time.Unix(m.Nip05.NextCheckAt, 0)
	m = f.run(map[string]string{"nip05": "bob@new.com"}, false)
	assert.Equal(t, CheckOK, m.Nip05.Status)
	assert.Equal(t, int64(50), m.Nip05Score)
}

func TestVerification_TransientFailureKeepsScoreAndBacksOff(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))
	f.run(map[string]string{"nip05": "bob@example.com"}, false)

	f.web.set("example.com", statusHandler(http.StatusTooManyRequests, "7200"))
	m := f.run(map[string]string{"nip05": "bob@example.com"}, true)

	assert.Equal(t, CheckOK, m.Nip05.Status, "a blocked check must not erase a good result")
	assert.Equal(t, int64(50), m.Nip05Score)
	assert.Equal(t, 1, m.Nip05.Attempts)
	assert.Equal(t, "status 429", m.Nip05.LastError)
	assert.Equal(t, f.now.Add(2*time.Hour).Unix(), m.Nip05.NextCheckAt, "Retry-After beats the 1h backoff")
}

func TestVerification_RetriesRunOut(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{MaxAttempts: 3, RetryInitial: time.Minute, RetryMax: 3 * time.Minute})
	f.web.set("example.com", statusHandler(http.StatusInternalServerError, ""))

	m := f.run(map[string]string{"nip05": "bob@example.com"}, false)
	var waits []time.Duration
	for m.Nip05.Attempts > 0 {
		next := time.Unix(m.Nip05.NextCheckAt, 0)
		waits = append(waits, next.Sub(f.now))
		f.now = next
		m = f.run(map[string]string{"nip05": "bob@example.com"}, false)
	}

	assert.Equal(t, []time.Duration{time.Minute, 2 * time.Minute}, waits)
	assert.Equal(t, 3, f.web.count("example.com"))
	assert.Equal(t, CheckError, m.Nip05.Status)
	assert.Equal(t, f.now.Add(DefaultVerificationTTL).Unix(), m.Nip05.NextCheckAt)
}

func TestVerification_DefinitiveNegatives(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"not listed": nip05JSON(map[string]string{"bob": "someoneelse"}),
		"404":        statusHandler(http.StatusNotFound, ""),
	} {
		t.Run(name, func(t *testing.T) {
			f := newVerifyFixture(t, VerificationConfig{})
			f.web.set("example.com", h)
			m := f.run(map[string]string{"nip05": "bob@example.com"}, false)
			assert.Equal(t, CheckFailed, m.Nip05.Status)
			assert.Equal(t, int64(0), m.Nip05Score)
			assert.Equal(t, f.now.Add(DefaultVerificationTTL).Unix(), m.Nip05.NextCheckAt)
		})
	}
}

func TestVerification_ExpiryRefetchesAndNegativeTTLNever(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{TTL: time.Hour})
	f.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))
	f.run(map[string]string{"nip05": "bob@example.com"}, false)
	f.now = f.now.Add(time.Hour)
	f.run(map[string]string{"nip05": "bob@example.com"}, false)
	assert.Equal(t, 2, f.web.count("example.com"))

	g := newVerifyFixture(t, VerificationConfig{TTL: -1})
	g.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))
	m := g.run(map[string]string{"nip05": "bob@example.com"}, false)
	assert.Equal(t, int64(0), m.Nip05.NextCheckAt)
	g.now = g.now.Add(365 * 24 * time.Hour)
	g.run(map[string]string{"nip05": "bob@example.com"}, false)
	assert.Equal(t, 1, g.web.count("example.com"))
}

// A profile can't make the relay fetch an internal address.
func TestVerification_RefusesIPsAndPorts(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("169.254.169.254", nip05JSON(map[string]string{"x": publicKey}))
	f.web.set("127.0.0.1", nip05JSON(map[string]string{"x": publicKey}))

	m := f.run(map[string]string{"nip05": "x@169.254.169.254", "lud16": "x@127.0.0.1:2375"}, false)
	assert.Equal(t, CheckInvalid, m.Nip05.Status)
	assert.Equal(t, CheckInvalid, m.Lud16.Status)
	assert.Zero(t, f.web.count("169.254.169.254")+f.web.count("127.0.0.1"))
}

func TestVerification_InvalidAndRemoved(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))
	f.run(map[string]string{"nip05": "bob@example.com"}, false)

	m := f.run(map[string]string{"nip05": "not an identifier"}, false)
	assert.Equal(t, CheckInvalid, m.Nip05.Status)
	assert.Equal(t, int64(0), m.Nip05Score)

	m = f.run(map[string]string{}, false)
	assert.Equal(t, CheckState{}, m.Nip05)
	assert.Equal(t, 1, f.web.count("example.com"))
	assert.Equal(t, int64(0), m.NextDue())
}

func TestVerification_Lud16(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("getalby.com", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/.well-known/lnurlp/bob", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag": "payRequest", "callback": "https://getalby.com/cb",
			"metadata":    `[["text/plain","x"],["chain/bitcoin","sats"],["chain/flokicoin","loki"]]`,
			"allowsNostr": true, "nostrPubkey": "abcd",
		})
	})
	f.web.set("broken.com", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ERROR","reason":"unknown user"}`)
	})

	m := f.run(map[string]string{"lud16": "bob@getalby.com"}, false)
	assert.Equal(t, CheckOK, m.Lud16.Status)
	assert.Equal(t, 2, m.Lud16Chains)
	assert.True(t, m.Lud16AllowsNostr)
	assert.Equal(t, "abcd", m.Lud16NostrPubkey)
	assert.Equal(t, int64(40), m.Lud16Score)

	m = f.run(map[string]string{"lud16": "bob@broken.com"}, false)
	assert.Equal(t, CheckFailed, m.Lud16.Status)
	assert.Equal(t, int64(0), m.Lud16Score)
	assert.False(t, m.Lud16AllowsNostr)
}

func TestVerification_Lud06WhenNoLud16(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("pay.example.com", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/lnurlp/bob", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag": "payRequest", "callback": "https://pay.example.com/cb",
			"allowsNostr": true, "nostrPubkey": "abcd",
		})
	})
	lnurl, err := utils.EncodeLNURL("https://pay.example.com/lnurlp/bob")
	require.NoError(t, err)

	m := f.run(map[string]string{"lud06": strings.ToUpper(lnurl)}, false)
	assert.Equal(t, CheckOK, m.Lud16.Status)
	assert.Equal(t, lnurl, m.Lud16.Value)
	assert.Equal(t, "abcd", m.Lud16NostrPubkey)

	// lud16 wins when both are set.
	f.web.set("getalby.com", nip05JSON(nil))
	f.run(map[string]string{"lud06": lnurl, "lud16": "bob@getalby.com"}, false)
	assert.Equal(t, 1, f.web.count("getalby.com"))
}

func TestVerification_PictureFallsBackToGet(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("img.example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		assert.Equal(t, "bytes=0-0", r.Header.Get("Range"))
		w.WriteHeader(http.StatusPartialContent)
	})
	m := f.run(map[string]string{"picture": "https://img.example.com/a.png"}, false)
	assert.Equal(t, CheckOK, m.Picture.Status)
	assert.Equal(t, 2, f.web.count("img.example.com"))
}

func TestVerification_SendsUserAgent(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{UserAgent: "test-relay"})
	f.web.set("example.com", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-relay", r.Header.Get("User-Agent"))
		nip05JSON(map[string]string{"bob": publicKey})(w, r)
	})
	f.run(map[string]string{"nip05": "bob@example.com"}, false)
	assert.Equal(t, 1, f.web.count("example.com"))
}

func TestVerification_VerifyNowForcesFetch(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))
	ev := f.profile(map[string]string{"nip05": "bob@example.com"})
	InsertTestEvents(t, f.store, []*nip01.Event{ev})

	f.run(map[string]string{"nip05": "bob@example.com"}, false)
	m, err := f.w.VerifyNow(context.Background(), publicKey)
	require.NoError(t, err)
	assert.Equal(t, CheckOK, m.Nip05.Status)
	assert.Equal(t, 2, f.web.count("example.com"))

	_, err = f.w.VerifyNow(context.Background(), "00"+publicKey[2:])
	assert.ErrorIs(t, err, ErrEventNotFound)
}

func TestVerification_FullQueueIsCheckedLater(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))
	ev := f.profile(map[string]string{"nip05": "bob@example.com"})
	InsertTestEvents(t, f.store, []*nip01.Event{ev})

	f.w.jobChan = make(chan VerificationJob) // always full
	f.w.QueueJob(ev)
	assert.Equal(t, uint64(1), f.w.TotalDropped.Load())

	f.w.jobChan = make(chan VerificationJob, 10)
	f.w.sweep()
	m, err := f.store.GetProfileMetrics(publicKey)
	require.NoError(t, err)
	assert.Equal(t, f.now.Unix(), m.RequeueAt)

	require.Len(t, f.w.jobChan, 1, "the sweep queues the stored kind 0")
	job := <-f.w.jobChan
	f.w.processJob(context.Background(), job)
	f.w.done(job.Pubkey)
	m, _ = f.store.GetProfileMetrics(publicKey)
	assert.Equal(t, CheckOK, m.Nip05.Status)
	assert.Equal(t, int64(0), m.RequeueAt)

	due, err := f.store.DueVerifications(f.now.Unix(), 10, nil)
	require.NoError(t, err)
	assert.Empty(t, due, "nothing is due until the TTL")
	due, _ = f.store.DueVerifications(f.now.Add(DefaultVerificationTTL).Unix(), 10, nil)
	assert.Equal(t, []string{publicKey}, due)
}

func TestVerification_Backoff(t *testing.T) {
	w := &ProfileVerificationWorker{cfg: VerificationConfig{RetryInitial: time.Hour, RetryMax: 6 * time.Hour}}
	assert.Equal(t, time.Hour, w.backoff(1, 0))
	assert.Equal(t, 4*time.Hour, w.backoff(3, 0))
	assert.Equal(t, 6*time.Hour, w.backoff(10, 0))
	assert.Equal(t, 8*time.Hour, w.backoff(1, 8*time.Hour))
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	assert.Equal(t, 30*time.Second, parseRetryAfter("30", now))
	assert.Equal(t, time.Minute, parseRetryAfter(now.Add(time.Minute).Format(http.TimeFormat), now))
	assert.Equal(t, time.Duration(0), parseRetryAfter("soon", now))
}

func TestHostLimiter(t *testing.T) {
	l := newHostLimiter(20 * time.Millisecond)
	start := time.Now()
	for i := 0; i < 3; i++ {
		require.NoError(t, l.wait(context.Background(), "a"))
	}
	assert.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond)

	l.pause("b", time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	assert.ErrorIs(t, l.wait(ctx, "b"), context.DeadlineExceeded)
}

func TestScheduleLegacyVerificationMigration(t *testing.T) {
	store := newStore(t)
	now := time.Unix(1_700_000_000, 0)
	put := func(pk string, v string) {
		require.NoError(t, store.Db().Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists(indexProfileMetrics)
			if err != nil {
				return err
			}
			return b.Put([]byte(pk), []byte(v))
		}))
	}
	recent := now.Add(-24 * time.Hour).Unix()
	put("zero", fmt.Sprintf(`{"nip05_score":0,"lud16_score":20,"last_verified_at":%d}`, recent))
	put("good", fmt.Sprintf(`{"nip05_score":50,"lud16_score":20,"last_verified_at":%d}`, recent))
	put("tracked", `{"nip05":{"value":"a@b.co","status":"ok"}}`)

	m := &migrations.ScheduleLegacyVerification{
		MetricsBucket: indexProfileMetrics, DueBucket: indexVerificationDue,
		DueKey: verificationDueKey, Now: func() time.Time { return now },
	}
	require.NoError(t, m.Up(store.Db()))

	get := func(pk string) *ProfileMetrics {
		pm, err := store.GetProfileMetrics(pk)
		require.NoError(t, err)
		return pm
	}
	assert.Equal(t, now.Unix(), get("zero").RequeueAt)
	assert.Equal(t, recent+int64(14*24*time.Hour/time.Second), get("good").RequeueAt)
	assert.Equal(t, int64(50), get("good").Nip05Score, "scores are kept")
	assert.Equal(t, int64(0), get("tracked").RequeueAt)

	due, err := store.DueVerifications(now.Unix(), 10, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"zero"}, due)
}

func TestVerification_PushedScoreKeepsBase(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	var pushed int64
	f.w.searchService = &MockSearchService{UpdateScoreFunc: func(_ context.Context, _ string, score int64) error {
		pushed = score
		return nil
	}}
	f.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))
	f.web.set("img.example.com", statusHandler(http.StatusOK, ""))
	profile := map[string]string{
		"name": "bob", "about": "a bio longer than fifteen characters",
		"picture": "https://img.example.com/a.png", "nip05": "bob@example.com",
	}

	m := f.run(profile, false)
	// Base 10+10+30, NIP-05 +50; a good picture isn't counted twice.
	assert.Equal(t, int64(50), m.BaseScore)
	assert.Equal(t, int64(100), pushed)

	f.web.set("img.example.com", statusHandler(http.StatusNotFound, ""))
	f.run(profile, true)
	assert.Equal(t, int64(70), pushed, "a broken picture takes its bonus back")
}

func TestVerification_ScoreFollowsConfigWithoutFetching(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	f.web.set("example.com", nip05JSON(map[string]string{"bob": publicKey}))
	m := f.run(map[string]string{"name": "bob", "nip05": "bob@example.com"}, false)
	assert.Equal(t, int64(60), m.TotalScore())

	prev := *config.Get()
	t.Cleanup(func() { config.Configure(func(c *config.AppConfig) { *c = prev }) })
	config.Configure(func(c *config.AppConfig) { c.Search.Verification.Nip05Score = 80 })

	m, err := f.store.GetProfileMetrics(publicKey)
	require.NoError(t, err)
	assert.Equal(t, int64(90), m.TotalScore())
	assert.Equal(t, 1, f.web.count("example.com"))
}
