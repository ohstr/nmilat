package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/wire"
)

type CacheHandler struct{}

func (h *CacheHandler) CanHandle(rp *wire.RequestPacket) bool {
	for _, f := range rp.Filters.GetAll() {
		if f.Cache != nil {
			return true
		}
	}
	return false
}

func (h *CacheHandler) Handle(ctx context.Context, s *Session, rp *wire.RequestPacket) (bool, error) {
	for _, f := range rp.Filters.GetAll() {
		if f.Cache == nil {
			continue
		}

		var args []json.RawMessage
		if err := json.Unmarshal(f.Cache, &args); err != nil {
			return false, fmt.Errorf("invalid cache format: %w", err)
		}

		if len(args) < 1 {
			return false, fmt.Errorf("missing cache action")
		}

		var action string
		if err := json.Unmarshal(args[0], &action); err != nil {
			return false, fmt.Errorf("invalid cache action type: %w", err)
		}

		switch action {
		case "top-zapped", "get_top_zapped":
			var opts struct {
				Window string `json:"window"`
				Limit  int    `json:"limit"`
			}
			if len(args) > 1 {
				json.Unmarshal(args[1], &opts)
			}
			return h.handleGetTopZapped(ctx, s, rp, opts.Window, opts.Limit)
		}
	}

	return false, nil
}

func (h *CacheHandler) handleGetTopZapped(ctx context.Context, s *Session, rp *wire.RequestPacket, window string, limit int) (bool, error) {
	if !s.config.EnableTopZapped {
		return true, fmt.Errorf("top-zapped cache queries are disabled on this relay")
	}

	// Parse window
	d := s.config.DefaultCacheWindow
	if window != "" {
		if val, err := time.ParseDuration(window); err == nil {
			d = val
		}
	}

	if limit <= 0 {
		limit = s.config.DefaultCacheLimit
	}

	endTime := uint64(time.Now().Unix())
	startTime := endTime - uint64(d.Seconds())

	// GetTopZapped now returns []ZapStats directly
	stats, err := s.store.GetTopZapped(ctx, startTime, endTime, limit)
	if err != nil {
		return true, fmt.Errorf("failed to get top zapped: %w", err)
	}

	statsBytes, _ := json.Marshal(stats)

	// Construct NIP-01 Event for Kindle 25521
	event := nip01.NewEvent(25521, string(statsBytes))

	// Relay must have a private key and delegation for this to be valid per new requirements
	if s.config.PrivKey == "" {
		return true, fmt.Errorf("relay private key missing, cannot serve signed cache response")
	}

	// Add delegation tag if configured
	if s.config.Delegation != nil {
		event.AddTag([]string{
			"delegation",
			s.config.Delegation.Issuer,
			s.config.Delegation.Conditions,
			s.config.Delegation.Token,
		})
	}

	if err := event.Sign(s.config.PrivKey); err != nil {
		return true, fmt.Errorf("failed to sign top-zapped event: %w", err)
	}

	eventBytes, err := json.Marshal(event)
	if err != nil {
		return true, fmt.Errorf("failed to marshal response event: %w", err)
	}

	evt := &wire.EventSubscriptionResponse{
		SubscriptionID: rp.SubscriptionID,
		EventBytes:     eventBytes,
	}

	s.reply(evt)

	s.reply(&wire.EOSESubscriptionResponse{SubscriptionID: rp.SubscriptionID})
	s.reply(&wire.ClosedSubscriptionResponse{
		SubscriptionID: rp.SubscriptionID,
		Message:        "one-shot cache request completed",
	})

	return true, nil
}
