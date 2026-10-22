package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/wire"
)

// KindZapRanking is the relay-signed, one-shot reply to a zap-ranking
// cache action.
const KindZapRanking = 25521

// CacheHandler answers filters with a "cache" field: ["<action>", {options}].
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
		if err := json.Unmarshal(f.Cache, &args); err != nil || len(args) == 0 {
			return true, &FilterError{Msg: `cache must be ["<action>", {options}]`}
		}
		var action string
		if err := json.Unmarshal(args[0], &action); err != nil {
			return true, &FilterError{Msg: "cache action must be a string"}
		}
		switch action {
		case CacheActionZapRanking:
			var opts zapRankingRequest
			if len(args) > 1 {
				if err := json.Unmarshal(args[1], &opts); err != nil {
					return true, &FilterError{Msg: "zap-ranking options must be {window, coin, limit}"}
				}
			}
			return h.zapRanking(ctx, s, rp, opts)
		default:
			return true, &FilterError{Msg: fmt.Sprintf("unknown cache action %q", action)}
		}
	}
	return false, nil
}

type zapRankingRequest struct {
	Window string `json:"window"`
	Coin   string `json:"coin"`
	Limit  int    `json:"limit"`
}

type rankedZapJSON struct {
	Pubkey string `json:"pubkey"`
	Total  uint64 `json:"total"`
}

func (h *CacheHandler) zapRanking(ctx context.Context, s *Session, rp *wire.RequestPacket, req zapRankingRequest) (bool, error) {
	cfg := s.config.Zaps.withDefaults()
	if !cfg.Enabled {
		s.reply(&wire.ClosedSubscriptionResponse{SubscriptionID: rp.SubscriptionID, Message: "restricted: zap ranking is not enabled on this relay"})
		return true, nil
	}
	if s.config.PrivKey == "" {
		return true, fmt.Errorf("relay private key missing, cannot sign the zap ranking")
	}

	window := cfg.Windows[0]
	if req.Window != "" {
		w, err := ParseZapWindow(req.Window)
		i := -1
		if err == nil {
			i = indexOfWindow(cfg.Windows, w)
		}
		if i < 0 {
			return true, &FilterError{Msg: "window must be one of " + windowLabels(cfg.Windows)}
		}
		window = cfg.Windows[i]
	}
	coin := cfg.Coins[0]
	if req.Coin != "" {
		c, err := ParseCoin(req.Coin)
		if err != nil || !containsCoin(cfg.Coins, c) {
			return true, &FilterError{Msg: "coin must be one of " + coinNamesOf(cfg.Coins)}
		}
		coin = c
	}
	limit := cfg.Limit
	if req.Limit > 0 {
		limit = min(req.Limit, cfg.MaxLimit)
	}

	ranking, err := s.store.ZapRanking(ctx, cfg, window, coin)
	if errors.Is(err, ErrIndexDisabled) {
		s.reply(&wire.ClosedSubscriptionResponse{SubscriptionID: rp.SubscriptionID, Message: "restricted: zap ranking is not enabled on this relay"})
		return true, nil
	}
	if err != nil {
		return true, fmt.Errorf("zap ranking: %w", err)
	}
	zaps := ranking.Zaps
	if len(zaps) > limit {
		zaps = zaps[:limit]
	}
	out := make([]rankedZapJSON, len(zaps))
	for i, z := range zaps {
		out[i] = rankedZapJSON{Pubkey: z.Pubkey, Total: WholeUnits(z.Total)}
	}
	content, err := json.Marshal(out)
	if err != nil {
		return true, err
	}

	event := nip01.NewEvent(KindZapRanking, string(content))
	event.CreatedAt = uint64(ranking.ComputedAt.Unix())
	event.AddTag([]string{"window", window.Label})
	event.AddTag([]string{"coin", coin.String()})
	event.AddTag([]string{"limit", strconv.Itoa(limit)})
	if s.config.Delegation != nil {
		event.AddTag([]string{"delegation", s.config.Delegation.Issuer, s.config.Delegation.Conditions, s.config.Delegation.Token})
	}
	if err := event.Sign(s.config.PrivKey); err != nil {
		return true, fmt.Errorf("failed to sign the zap ranking: %w", err)
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return true, err
	}
	s.reply(&wire.EventSubscriptionResponse{SubscriptionID: rp.SubscriptionID, EventBytes: eventBytes})
	s.reply(&wire.EOSESubscriptionResponse{SubscriptionID: rp.SubscriptionID})
	s.reply(&wire.ClosedSubscriptionResponse{SubscriptionID: rp.SubscriptionID, Message: "one-shot cache request completed"})
	return true, nil
}

func indexOfWindow(ws []ZapWindow, w ZapWindow) int {
	for i, x := range ws {
		if x.D == w.D {
			return i
		}
	}
	return -1
}

func containsCoin(cs []Coin, c Coin) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

func windowLabels(ws []ZapWindow) string {
	labels := make([]string, len(ws))
	for i, w := range ws {
		labels[i] = w.Label
	}
	return strings.Join(labels, ", ")
}

func coinNamesOf(cs []Coin) string {
	names := make([]string, len(cs))
	for i, c := range cs {
		names[i] = c.String()
	}
	return strings.Join(names, ", ")
}
