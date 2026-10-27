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

// WatchRelays is the order in which Watch subscribes for notify's notices:
// accepted first (nil: the relays that accepted the order in this session), then
// the connection's relays, then the announcement's, each once.
func (c *OrderClient) WatchRelays(notify string, accepted []string) []string {
	if accepted == nil {
		c.mu.Lock()
		accepted = c.accepted[notify]
		c.mu.Unlock()
	}
	var out []string
	seen := map[string]bool{}
	add := func(rs []string) {
		for _, r := range rs {
			if r != "" && !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	add(accepted)
	add(c.conn.Relays)
	if c.session != nil {
		add(c.session.Relays())
	}
	return out
}

// Watch listens for the order notices of notify (NIP-CO §Order Notice) and sends
// one signal per verified notice: a notice only says something happened, so the
// caller then reads the order with Lookup, and never acts on the notice itself.
// Notices can be missed; callers poll too. The channel closes when ctx ends. It
// subscribes on WatchRelays(notify, accepted); an error only when none of them
// could be subscribed.
func (c *OrderClient) Watch(ctx context.Context, notify string, accepted []string) (<-chan struct{}, error) {
	if !nipCO.ValidNotify(notify) {
		return nil, fmt.Errorf("nipCO/client: notify is 64 lowercase hex")
	}
	out := make(chan struct{}, 16)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		seen     = map[string]bool{}
		failures []error
		ok       int
	)
	filter := nipCO.OrderNoticeFilter(notify)
	for _, raw := range c.WatchRelays(notify, accepted) {
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
		return nil, fmt.Errorf("nipCO/client: no relay to watch on: %w", errors.Join(failures...))
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out, nil
}
