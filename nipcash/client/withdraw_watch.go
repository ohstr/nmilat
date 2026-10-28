package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/google/uuid"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCO"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/wire"
)

// keepAccepted remembers the relays that accepted the withdrawal tagged notify.
func (s *BatchSession) keepAccepted(notify string, relays []string) {
	if notify == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accepted == nil {
		s.accepted = map[string][]string{}
	}
	s.accepted[notify] = append([]string(nil), relays...)
}

// payoutWatchRelays is accepted (nil: those this session kept for notify), then
// the session's announced relays, each once.
func (s *BatchSession) payoutWatchRelays(notify string, accepted []string) []string {
	s.mu.Lock()
	if accepted == nil {
		accepted = s.accepted[notify]
	}
	s.mu.Unlock()
	var out []string
	seen := map[string]bool{}
	for _, rs := range [][]string{accepted, s.Relays()} {
		for _, r := range rs {
			if r != "" && !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

// WatchPayout listens for the state notices of the withdrawal tagged notify
// (NIP-CASH §State Notice: NIP-CO's kind 23189 with p = notify), on accepted
// first (the relays that accepted the call; nil: those this session kept, as a
// Journal implementing AcceptedRecorder was told), then the Hub's announced
// relays. Each notice is one signal; the caller then reads the payout with
// LookupWithdraw. No notice marks confirmed or final, and notices can be
// missed: callers poll until PayoutFinished. The channel closes when ctx ends;
// an error only when no relay could be subscribed.
func (c *Client) WatchPayout(ctx context.Context, notify string, accepted []string) (<-chan struct{}, error) {
	s, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	return s.WatchPayout(ctx, notify, accepted)
}

// WatchPayout is (*Client).WatchPayout on this session.
func (s *BatchSession) WatchPayout(ctx context.Context, notify string, accepted []string) (<-chan struct{}, error) {
	if !nipCO.ValidNotify(notify) {
		return nil, fmt.Errorf("nipcash/client: notify is 64 lowercase hex")
	}
	return watchNotices(ctx, notify, s.payoutWatchRelays(notify, accepted))
}

// watchNotices subscribes for notify's kind-23189 notices on relays and sends one
// signal per distinct verified notice.
func watchNotices(ctx context.Context, notify string, relays []string) (<-chan struct{}, error) {
	out := make(chan struct{}, 16)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		seen     = map[string]bool{}
		failures []error
		ok       int
	)
	filter := nipCO.OrderNoticeFilter(notify)
	for _, raw := range relays {
		u, err := url.Parse(raw)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		conn, err := relayclient.Connect(ctx, u)
		if err != nil {
			failures = append(failures, fmt.Errorf("relay %q: %w", raw, err))
			continue
		}
		subID := uuid.NewString()
		if !conn.SubscribeWithID(subID, nip01.NewSubscriptionFilterGroup(&filter)) {
			conn.Close()
			failures = append(failures, fmt.Errorf("relay %q: closed before subscribing", raw))
			continue
		}
		ok++
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case msg, open := <-conn.Read():
					if !open {
						return
					}
					m, isEvent := msg.(*wire.EventSubscriptionResponse)
					if !isEvent || m.SubscriptionID != subID || !nipCO.IsOrderNotice(m.Event, notify) {
						continue
					}
					mu.Lock()
					dup := seen[m.Event.ID]
					seen[m.Event.ID] = true
					mu.Unlock()
					if dup {
						continue
					}
					select {
					case out <- struct{}{}:
					default: // a signal is already waiting; one read covers both
					}
				}
			}
		}()
	}
	if ok == 0 {
		return nil, fmt.Errorf("nipcash/client: no relay to watch on: %w", errors.Join(failures...))
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out, nil
}
