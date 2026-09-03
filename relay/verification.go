package relay

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/config"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/search"
	"github.com/ohstr/nmilat/search/ranking"
	"github.com/ohstr/nmilat/utils"
	"github.com/rs/zerolog"
)

type VerificationJob struct {
	Pubkey  string
	Nip05   string
	Lud16   string
	Picture string
}

type ProfileVerificationWorker struct {
	store         *EventStore
	searchService search.Service
	httpClient    *http.Client
	jobChan       chan VerificationJob
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	logger        zerolog.Logger

	TotalProcessed atomic.Uint64
	TotalErrors    atomic.Uint64
	TotalEnqueued  atomic.Uint64
	StartTime      time.Time
}

// NewProfileVerificationWorker inherits its logger from store, which already
// carries whatever WithEventStoreLogger the caller configured on it.
func NewProfileVerificationWorker(store *EventStore, searchService search.Service) *ProfileVerificationWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProfileVerificationWorker{
		store:         store,
		searchService: searchService,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		jobChan:       make(chan VerificationJob, 1000),
		ctx:           ctx,
		cancel:        cancel,
		logger:        store.logger,
		StartTime:     time.Now(),
	}
}

func (w *ProfileVerificationWorker) Start(count int) {
	for i := 0; i < count; i++ {
		w.wg.Add(1)
		go w.worker()
	}
}

func (w *ProfileVerificationWorker) Stop() {
	w.cancel()
	close(w.jobChan)
	w.wg.Wait()
}

func (w *ProfileVerificationWorker) QueueJob(event *nip01.Event) {
	var profile struct {
		Nip05   string `json:"nip05"`
		Lud16   string `json:"lud16"`
		Picture string `json:"picture"`
	}
	if err := utils.UnmarshalJSON([]byte(event.Content), &profile); err != nil {
		return
	}

	job := VerificationJob{
		Pubkey:  event.PubKey,
		Nip05:   profile.Nip05,
		Lud16:   profile.Lud16,
		Picture: profile.Picture,
	}

	// Only enqueue if there's something to verify
	if job.Nip05 != "" || job.Lud16 != "" || job.Picture != "" {
		select {
		case w.jobChan <- job:
			w.TotalEnqueued.Add(1)
		default:
		}
	}
}

func (w *ProfileVerificationWorker) worker() {
	defer w.wg.Done()
	for job := range w.jobChan {
		select {
		case <-w.ctx.Done():
			return
		default:
			w.processJob(job)
		}
	}
}

func (w *ProfileVerificationWorker) processJob(job VerificationJob) {
	defer w.TotalProcessed.Add(1)

	// 1. Check if verified recently (2 weeks)
	metrics, err := w.store.GetProfileMetrics(job.Pubkey)
	if err != nil {
		w.logger.Error().Err(err).Msg("failed to get profile metrics for verification")
		w.TotalErrors.Add(1)
		return
	}

	now := time.Now().Unix()
	twoWeeks := int64(14 * 24 * 60 * 60)
	if metrics != nil && (now-metrics.LastVerifiedAt) < twoWeeks {
		// Skip network checks if verified within 14 days
		return
	}

	// 2. Perform concurrent network checks
	var wg sync.WaitGroup
	var nip05Valid, pictureValid bool
	var ludChains int

	if job.Nip05 != "" && ranking.IsValidNip05Format(job.Nip05) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			url := utils.GetNip05URL(job.Nip05)
			if url != "" {
				req, _ := http.NewRequestWithContext(w.ctx, "GET", url, nil)
				if resp, err := w.httpClient.Do(req); err == nil {
					defer func() { _ = resp.Body.Close() }()
					nip05Valid = utils.VerifyNip05(resp.Body, job.Pubkey, job.Nip05)
				}
			}
		}()
	}

	if job.Lud16 != "" && ranking.IsValidLud16Format(job.Lud16) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			url := utils.GetLud16URL(job.Lud16)
			if url != "" {
				req, _ := http.NewRequestWithContext(w.ctx, "GET", url, nil)
				if resp, err := w.httpClient.Do(req); err == nil {
					defer func() { _ = resp.Body.Close() }()
					if resp.StatusCode == http.StatusOK {
						body, err := io.ReadAll(resp.Body)
						if err == nil {
							var payResponse struct {
								Metadata string `json:"metadata"`
							}
							if err := utils.UnmarshalJSON(body, &payResponse); err != nil {
								// Alternative: some services return the metadata directly as an array or object
								// but LUD-06 says it's inside a metadata field as a string.
							} else {
								var metadata [][]interface{}
								if err := utils.UnmarshalJSON([]byte(payResponse.Metadata), &metadata); err == nil {
									chainCount := 0
									for _, item := range metadata {
										if len(item) > 0 {
											if tag, ok := item[0].(string); ok && strings.HasPrefix(tag, "chain/") {
												chainCount++
											}
										}
									}
									if chainCount == 0 {
										// Bitcoin is assumed if no chain tags provided
										ludChains = 1
									} else {
										ludChains = chainCount
									}
								}
							}
						}
					}
				}
			}
		}()
	}

	if job.Picture != "" && utils.IsValidPictureURL(job.Picture) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(w.ctx, "HEAD", job.Picture, nil)
			if resp, err := w.httpClient.Do(req); err == nil {
				defer func() { _ = resp.Body.Close() }()
				pictureValid = resp.StatusCode >= 200 && resp.StatusCode < 400
			}
		}()
	}

	wg.Wait()

	// 3. Compute new scores
	appCfg := config.Get()
	cfg := appCfg.Search.Verification

	var nipScore int64
	if nip05Valid {
		nipScore = cfg.Nip05Score
	}

	var ludScore int64
	if ludChains > 0 {
		ludScore = int64(ludChains) * cfg.Lud16Score
		if cfg.Lud16ChainLimit > 0 && ludScore > cfg.Lud16ChainLimit {
			ludScore = cfg.Lud16ChainLimit
		}
	}

	var picScore int64
	// Just reusing the picture bonus from scoring config for an active picture
	if pictureValid {
		picScore = appCfg.Search.Scoring.PictureBonus
	}

	// 4. Update ProfileMetrics
	err = w.store.UpdateProfileMetrics(job.Pubkey, func(m *ProfileMetrics) {
		m.Nip05Score = nipScore
		m.Lud16Score = ludScore
		m.PictureScore = picScore
		m.LastVerifiedAt = now
	})

	if err != nil {
		w.logger.Error().Err(err).Msg("failed to update profile metrics")
		w.TotalErrors.Add(1)
		return
	}

	// 5. Push unified score to the search backend
	updatedMetrics, err := w.store.GetProfileMetrics(job.Pubkey)
	if err == nil && updatedMetrics != nil {
		if w.searchService != nil {
			_ = w.searchService.UpdateScore(context.Background(), job.Pubkey, updatedMetrics.TotalScore())
		}
	}
}

// GetStats returns thread-safe metadata about the worker workload
func (w *ProfileVerificationWorker) GetStats() map[string]interface{} {
	processed := w.TotalProcessed.Load()
	enqueued := w.TotalEnqueued.Load()
	errors := w.TotalErrors.Load()
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
		"total_errors":    errors,
		"items_per_sec":   fmt.Sprintf("%.1f", itemsPerSec),
	}
}
