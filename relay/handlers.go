package relay

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// RequestHandler defines a strategy for handling a subscription request.
type RequestHandler interface {
	// CanHandle returns true if this handler should process the request.
	CanHandle(rp *wire.RequestPacket) bool
	// Handle processes the request. modifying the request or responding directly.
	// Returns true if the request was fully handled and no further processing is needed.
	Handle(ctx context.Context, s *Session, rp *wire.RequestPacket) (bool, error)
}

// ---------------------------------------------------------------------

const (
	// Cache directives
	CacheField            = "cache"
	CacheActionZapRanking = "zap-ranking"

	// NIP-50 constants
	ImpossibleID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// NIP50Handler intercepts requests with "search" filter fields.
type NIP50Handler struct{}

func (h *NIP50Handler) CanHandle(rp *wire.RequestPacket) bool {
	return rp.Filters.HasSearch()
}

func (h *NIP50Handler) Handle(ctx context.Context, s *Session, rp *wire.RequestPacket) (bool, error) {
	// logic adapted from original processRequest
	var searchQuery string
	var clientLimit int
	for _, f := range rp.Filters.GetAll() {
		if f.Search != "" {
			searchQuery = f.Search
			clientLimit = f.Limit
			break
		}
	}

	if searchQuery != "" {
		if s.SearchService == nil {
			// NIP-11 already omits 50 from supported_nips when search is
			// disabled; this is the defense for clients that send it anyway
			// instead of silently returning zero results via ImpossibleID.
			s.reply(&wire.ClosedSubscriptionResponse{
				SubscriptionID: rp.SubscriptionID,
				Message:        "unsupported: search is not enabled on this relay",
			})
			return true, nil
		}

		limit := s.config.DefaultSearchLimit
		if limit <= 0 {
			limit = 100 // fallback
		}
		pubkeys, err := s.SearchService.FindProfiles(ctx, searchQuery, limit)
		if err != nil {
			s.config.Logger.Error().Err(err).Msg("search failed")
			// Treat error as empty results
		}

		// Rewrite Filter
		newGroup := nip01.NewSubscriptionFilterGroup()

		if len(pubkeys) == 0 {
			// Search returned no results.
			for _, f := range rp.Filters.GetAll() {
				newFilter := *f
				newFilter.Search = ""
				newFilter.IDs = []string{ImpossibleID} // Impossible ID
				newGroup.Add(&newFilter)
			}
		} else {
			// Search success
			for _, f := range rp.Filters.GetAll() {
				newFilter := *f             // shallow copy
				newFilter.Search = ""       // clear search
				newFilter.Authors = pubkeys // inject results
				newFilter.Limit = 0         // applied after ranking, not by created_at
				if len(newFilter.Kinds) == 0 {
					newFilter.Kinds = []int{0}
				}
				newGroup.Add(&newFilter)
			}
			rp.Filters = newGroup
			// NIP-50: results in descending search quality, limit after ranking.
			return openSubscription(ctx, s, rp, newSearchRank(pubkeys, clientLimit))
		}
		rp.Filters = newGroup
	}

	// NIP-50 just rewrites the filter, it doesn't "stop" processing.
	// We return false so the next handler (Standard) picks up the rewritten filter.
	return false, nil
}

// ---------------------------------------------------------------------

// StandardRequestHandler handles standard NIP-01 subscriptions.
type StandardRequestHandler struct{}

func (h *StandardRequestHandler) CanHandle(rp *wire.RequestPacket) bool {
	return true // Fallback handler
}

func (h *StandardRequestHandler) Handle(ctx context.Context, s *Session, rp *wire.RequestPacket) (bool, error) {
	return openSubscription(ctx, s, rp, nil)
}

// searchRank orders a search's stored events by their author's position in
// the search results, then caps them at the client's limit (0: no cap).
type searchRank struct {
	rank  map[string]int
	limit int
}

func newSearchRank(pubkeys []string, limit int) *searchRank {
	r := &searchRank{rank: make(map[string]int, len(pubkeys)), limit: limit}
	for i, pk := range pubkeys {
		if _, seen := r.rank[pk]; !seen {
			r.rank[pk] = i
		}
	}
	return r
}

// order sorts events by author rank, newest first within one author, and
// applies the limit.
func (r *searchRank) order(events []*PotentialEvent) []*PotentialEvent {
	ranks := make(map[*PotentialEvent]int, len(events))
	for _, ev := range events {
		var head struct {
			PubKey string `json:"pubkey"`
		}
		rank, ok := 0, false
		if json.Unmarshal(ev.Bytes, &head) == nil {
			rank, ok = r.rank[head.PubKey]
		}
		if !ok {
			rank = len(r.rank)
		}
		ranks[ev] = rank
	}
	slices.SortStableFunc(events, func(a, b *PotentialEvent) int {
		if c := cmp.Compare(ranks[a], ranks[b]); c != 0 {
			return c
		}
		return cmp.Compare(b.CreatedAt, a.CreatedAt)
	})
	if r.limit > 0 && len(events) > r.limit {
		events = events[:r.limit]
	}
	return events
}

// openSubscription opens rp as a live subscription. With rank set, stored
// events are held until EOSE and sent in rank order; the live tail is not.
func openSubscription(ctx context.Context, s *Session, rp *wire.RequestPacket, rank *searchRank) (bool, error) {
	sub, exists := s.subscriptions.Get(rp.SubscriptionID)
	if exists {
		if sub.query.filters.Equals(rp.Filters) {
			return true, nil
		}
		s.subscriptions.Close(sub.id)
	}

	query, err := NewStoreQuery(s.store, rp.Filters)
	if err != nil {
		return true, wire.NewPacketError("failed to create query", err)
	}

	// create new subscription
	sub, toSend, errs, eose := NewSubscription(rp.SubscriptionID, query)
	if !s.subscriptions.Add(sub) {
		s.reply(&wire.NoticeSubscriptionResponse{
			Message: "too many concurrent subscriptions",
		})
		s.reply(&wire.ClosedSubscriptionResponse{
			SubscriptionID: sub.id,
		})
		return true, nil
	}

	// Checked per delivered event, live tail included: a group made private
	// after this subscription opened must not keep leaking to it.
	// deniedPrivateGroupPotentialEvent skips the parse for events with no
	// "d"/"h" tag, so this stays cheap.
	checkGroupPrivacy := s.groups != nil
	// Recipient-only kinds (WithRecipientOnlyKinds), checked per event for
	// the same reason: an identity AUTHed after the REQ is honored.
	checkRecipient := s.config.mayMatchRecipientOnlyKind(allFilters(rp.Filters)...)

	go func() {
		// async subscription loop (same as original)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		defer utils.RecoverPanic(s.config.Logger)

		var wg sync.WaitGroup
		start := time.Now()
		delivered, stored := 0, true
		var ranked []*PotentialEvent
		go sub.Start(ctx, &wg)

		for {
			select {
			case event := <-toSend:
				if (checkGroupPrivacy && s.groups.deniedPrivateGroupPotentialEvent(s, event)) ||
					(checkRecipient && s.config.deniedRecipientOnlyPotentialEvent(s, event)) {
					wg.Done()
					continue
				}
				if rank != nil && stored {
					ranked = append(ranked, event)
					wg.Done()
					continue
				}
				s.reply(&wire.EventSubscriptionResponse{SubscriptionID: sub.id, EventBytes: event.Bytes})
				wg.Done()
				if stored {
					delivered++
				}

			case <-eose:
				if rank != nil && stored {
					for _, event := range rank.order(ranked) {
						s.reply(&wire.EventSubscriptionResponse{SubscriptionID: sub.id, EventBytes: event.Bytes})
						delivered++
					}
					ranked = nil
				}
				s.reply(&wire.EOSESubscriptionResponse{SubscriptionID: sub.id})
				if stored {
					stored = false
					s.config.observer().ReqServed(time.Since(start), delivered)
				}

			case err := <-errs:
				s.reply(&wire.ClosedSubscriptionResponse{
					SubscriptionID: sub.id,
					Message:        fmt.Sprintf("error: %v", err),
				})
				return

			case <-sub.Closed():
				return
			}
		}
	}()

	return true, nil
}
