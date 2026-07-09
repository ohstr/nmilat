package relay

import (
	"context"
	"fmt"
	"sync"

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
	CacheField        = "cache"
	CacheActionTopZap = "top-zapped"

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
	for _, f := range rp.Filters.GetAll() {
		if f.Search != "" {
			searchQuery = f.Search
			break
		}
	}

	if searchQuery != "" {
		var pubkeys []string
		var err error

		if s.SearchService != nil {
			limit := s.config.DefaultSearchLimit
			if limit <= 0 {
				limit = 100 // fallback
			}
			pubkeys, err = s.SearchService.FindProfiles(ctx, searchQuery, limit)
			if err != nil {
				s.config.Logger.Error().Err(err).Msg("search failed")
				// Treat error as empty results
			}
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
				if len(newFilter.Kinds) == 0 {
					newFilter.Kinds = []int{0}
				}
				newGroup.Add(&newFilter)
			}
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

	sub, exists := s.subscriptions.Get(rp.SubscriptionID)
	if exists {
		if sub.query.filters.Equals(rp.Filters) {
			s.config.Logger.Debug().Msgf("filters are equals")
			return true, nil
		}
		s.subscriptions.Close(sub.id)
	}

	s.config.Logger.Info().Msgf("processing request for subscription %s", rp.SubscriptionID)
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

	go func() {
		// async subscription loop (same as original)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		defer utils.RecoverPanic(s.config.Logger)

		var wg sync.WaitGroup
		go sub.Start(ctx, &wg)

		s.config.Logger.Info().Msgf("subscription %s started", sub.id)

		for {
			select {
			case event := <-toSend:
				eventBytes, err := s.store.FindEventBytes(event.Evsid)
				if err == nil {
					s.reply(&wire.EventSubscriptionResponse{SubscriptionID: sub.id, EventBytes: eventBytes})
				}
				wg.Done()

			case <-eose:
				s.reply(&wire.EOSESubscriptionResponse{SubscriptionID: sub.id})

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
