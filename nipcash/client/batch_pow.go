package client

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// ErrPowTooHard is a relay's proof-of-work minimum above the session's budget,
// or mining not done in time, before the first publish (NIP-CASH §Proof of
// Work). It wraps ErrNotSent: nothing was published, and the caller closes the
// written-ahead call as not sent.
var ErrPowTooHard = fmt.Errorf("%w: proof of work too hard for the budget", ErrNotSent)

// SessionOption configures a session: OpenBatchSession, Connect and
// ConnectCashHub take them.
type SessionOption func(*sessionConfig)

type sessionConfig struct {
	powMaxDifficulty int           // 0: no cap
	powMaxDuration   time.Duration // 0: deadline − MinPublishMargin − now
	withdrawHRP      string        // "": the bill's coin's HRPs (WithWithdrawHRP)
	relayAnswerWait  time.Duration // 0: the time to not_after shared among the relays
}

func newSessionConfig(opts []SessionOption) sessionConfig {
	var c sessionConfig
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	return c
}

// WithPowBudget bounds proof of work: a relay minimum above maxDifficulty, or
// mining longer than maxDuration, is ErrPowTooHard. 0 leaves either unbounded
// (mining is always bounded by the deadline less MinPublishMargin).
func WithPowBudget(maxDifficulty int, maxDuration time.Duration) SessionOption {
	return func(c *sessionConfig) {
		c.powMaxDifficulty, c.powMaxDuration = maxDifficulty, maxDuration
	}
}

// WithRelayAnswerWait sets how long a relay that took a request is given to
// answer before the request also goes to the next untried relay (NIP-CASH
// §Multiple Relay Hints). 0, the default, shares the time left until the
// envelope's not_after between that relay and every untried one.
func WithRelayAnswerWait(d time.Duration) SessionOption {
	return func(c *sessionConfig) { c.relayAnswerWait = d }
}

// outgoing is one kind-23190 ready to publish; pow is set when it was mined, so
// a relay asking for more work gets the same request re-mined.
type outgoing struct {
	ev       *nip01.Event
	pow      *transport.PowRequest
	notAfter int64
}

// powMinimum is the highest proof-of-work minimum among the session's relays,
// each read once per session from its NIP-11 document (an unreadable document
// counts as none).
func (s *BatchSession) powMinimum(ctx context.Context) int {
	highest := 0
	for _, raw := range s.Relays() {
		highest = max(highest, s.relayPow(ctx, raw, false))
	}
	return highest
}

func (s *BatchSession) relayPow(ctx context.Context, raw string, reread bool) int {
	s.mu.Lock()
	n, ok := s.powMin[raw]
	s.mu.Unlock()
	if ok && !reread {
		return n
	}
	n, err := transport.RelayPowMinimum(ctx, raw)
	if err != nil {
		n = 0
	}
	s.mu.Lock()
	if s.powMin == nil {
		s.powMin = map[string]int{}
	}
	s.powMin[raw] = n
	s.mu.Unlock()
	return n
}

// miningContext ends at deadline − MinPublishMargin, or after the budget's
// duration if sooner.
func (s *BatchSession) miningContext(ctx context.Context, notAfter int64) (context.Context, context.CancelFunc) {
	end := time.Unix(notAfter-nipcash.MinPublishMargin, 0)
	if d := s.cfg.powMaxDuration; d > 0 && time.Now().Add(d).Before(end) {
		end = time.Now().Add(d)
	}
	return context.WithDeadline(ctx, end)
}

// wrap builds the request for plaintext: plain when no relay asks for proof of
// work, mined to the highest minimum otherwise. Every failure here is before
// the first publish, so it wraps ErrNotSent.
func (s *BatchSession) wrap(ctx context.Context, plaintext []byte, inbox string, notAfter int64) (*outgoing, [32]byte, error) {
	difficulty := s.powMinimum(ctx)
	if difficulty == 0 {
		ev, key, err := transport.WrapRequest(plaintext, inbox)
		if err != nil {
			return nil, key, fmt.Errorf("%w: wrap: %v", ErrNotSent, err)
		}
		return &outgoing{ev: ev, notAfter: notAfter}, key, nil
	}
	if m := s.cfg.powMaxDifficulty; m > 0 && difficulty > m {
		return nil, [32]byte{}, fmt.Errorf("%w: relay minimum %d, budget %d", ErrPowTooHard, difficulty, m)
	}
	mctx, cancel := s.miningContext(ctx, notAfter)
	defer cancel()
	req, key, err := transport.WrapRequestPow(mctx, plaintext, inbox, notAfter, difficulty)
	if err != nil {
		if mctx.Err() != nil && ctx.Err() == nil {
			return nil, key, fmt.Errorf("%w: mining to %d not done in time", ErrPowTooHard, difficulty)
		}
		return nil, key, fmt.Errorf("%w: wrap: %v", ErrNotSent, err)
	}
	return &outgoing{ev: req.Event, pow: req, notAfter: notAfter}, key, nil
}

// maxPowRetries bounds how often one relay may ask for more work.
const maxPowRetries = 3

// publishTo publishes req to one relay. A refusal "pow: …" re-mines the same
// request to the stated difficulty and publishes it again; the envelope, its
// proofs and its request_id are never rebuilt.
func (s *BatchSession) publishTo(ctx context.Context, relayURL *url.URL, req *outgoing) error {
	for attempt := 0; ; attempt++ {
		if keep := publishFilterFrom(ctx); keep != nil && !keep(req.ev) {
			return nil // dropped by a test hook: as if lost after publish
		}
		ok, err := relayclient.PublishEventToRelay(ctx, relayURL, req.ev)
		if err != nil {
			return err
		}
		if ok.Accepted {
			return nil
		}
		stated, isPow := transport.ParsePowRejection(ok.Message)
		if !isPow || req.pow == nil || attempt >= maxPowRetries {
			// A refusal comes back as an OK, not an error: the request is not on
			// this relay, and waiting here for a reply would only run out not_after.
			return fmt.Errorf("refused: %s", ok.Message)
		}
		if stated == 0 {
			stated = s.relayPow(ctx, relayURL.String(), true)
		}
		if stated == 0 {
			return fmt.Errorf("refused: %s", ok.Message)
		}
		mctx, cancel := context.WithDeadline(ctx, time.Unix(req.notAfter, 0))
		err = req.pow.Remine(mctx, stated)
		cancel()
		if err != nil {
			return fmt.Errorf("re-mine to %d: %w", stated, err)
		}
		req.ev = req.pow.Event
	}
}

// WithPublishFilter is a test hook: keep is asked before each publish of a
// request (a private-transport envelope or a NIP-47 call such as a mint), and
// a request it refuses is dropped as if lost on the way.
func WithPublishFilter(ctx context.Context, keep func(*nip01.Event) bool) context.Context {
	return relayclient.WithPublishFilter(ctx, keep)
}

// WithAfterPublish is a test hook: f runs right after a request was published
// (a private-transport envelope or a NIP-47 call such as a mint).
func WithAfterPublish(ctx context.Context, f func()) context.Context {
	return relayclient.WithAfterPublish(ctx, f)
}

// withoutPublishHooks is ctx with both publish hooks cleared, for a read made
// on the way to the request the hooks are meant for.
func withoutPublishHooks(ctx context.Context) context.Context {
	return relayclient.WithAfterPublish(relayclient.WithPublishFilter(ctx, nil), nil)
}

func publishFilterFrom(ctx context.Context) func(*nip01.Event) bool {
	return relayclient.PublishFilterFrom(ctx)
}

func afterPublishFrom(ctx context.Context) func() { return relayclient.AfterPublishFrom(ctx) }
