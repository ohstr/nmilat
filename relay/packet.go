package relay

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/nip77"
	"github.com/ohstr/nmilat/search"
	"github.com/ohstr/nmilat/wire"
)

// ProcessPacket dispatches the packet to the appropriate handler.
func (s *Session) ProcessPacket(ctx context.Context, p wire.Packet) error {
	switch packet := p.(type) {
	case *wire.EventPacket:
		return s.processEvent(ctx, packet)
	case *wire.RequestPacket:
		return s.processRequest(ctx, packet)
	case *wire.ClosePacket:
		return s.processClose(ctx, packet)
	case *wire.AuthPacket:
		return s.processAuth(ctx, packet)
	case *wire.CountPacket:
		return s.processCount(ctx, packet)
	case *wire.NegOpenPacket:
		return s.processNegOpen(ctx, packet)
	case *wire.NegMsgPacket:
		return s.processNegMsg(ctx, packet)
	case *wire.NegClosePacket:
		return s.processNegClose(ctx, packet)
	case *wire.NegErrPacket:
		return s.processNegErr(ctx, packet)
	default:
		return fmt.Errorf("unknown packet type: %T", p)
	}
}

/////////////////////////////////////////////////////////////////////
// REQ
/////////////////////////////////////////////////////////////////////

func (s *Session) processRequest(ctx context.Context, rp *wire.RequestPacket) error {

	if s.limitation.AuthRequired && s.authedPubkey == "" {
		s.reply(&wire.NoticeSubscriptionResponse{
			Message: "restricted: valid NIP-42 authentication required",
		})
		s.reply(&wire.ClosedSubscriptionResponse{
			SubscriptionID: rp.SubscriptionID,
			Message:        "restricted: valid NIP-42 authentication required",
		})
		return nil
	}

	// Handlers Chain
	// Handlers Chain
	// We instantiate them here. For further optimization, these could be singletons or initialized once in Session or Server.
	// Since they are stateless, specific instances are cheap, but the slice allocation is repetitive.
	handlers := getRequestHandlers()

	for _, h := range handlers {
		if h.CanHandle(rp) {
			done, err := h.Handle(ctx, s, rp)
			if err != nil {
				// If handler returns error, we might want to close sub or log
				s.config.Logger.Error().Err(err).Str("sub", rp.SubscriptionID).Msg("handler error")
				s.reply(&wire.ClosedSubscriptionResponse{
					SubscriptionID: rp.SubscriptionID,
					Message:        fmt.Sprintf("error: %v", err),
				})
				return nil
			}
			if done {
				return nil
			}
		}
	}

	return nil
}

/////////////////////////////////////////////////////////////////////
// CLOSE
/////////////////////////////////////////////////////////////////////

func (s *Session) processClose(ctx context.Context, cp *wire.ClosePacket) error {

	if exists := s.subscriptions.Close(cp.SubscriptionID); !exists {
		return wire.NewPacketError(fmt.Sprintf("subscription not found ID=%v", cp.SubscriptionID), nil)
	}

	s.reply(&wire.ClosedSubscriptionResponse{
		SubscriptionID: cp.SubscriptionID,
		Message:        "closed",
	})

	return nil
}

/////////////////////////////////////////////////////////////////////
// AUTH
/////////////////////////////////////////////////////////////////////

func (s *Session) processAuth(parent context.Context, ap *wire.AuthPacket) error {

	if s.challenge == "" {
		s.reply(&wire.NoticeSubscriptionResponse{Message: "auth: no challenge sent"})
		return nil
	}

	relayURL := ""
	for _, t := range ap.Event.Tags {
		if len(t) >= 2 && t[0] == "relay" {
			relayURL = t[1]
			break
		}
	}

	// Check challenge
	err := nip42.ValidateAuthEvent(ap.Event.Kind, ap.Event.Tags, ap.Event.CreatedAt, s.challenge, relayURL)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ap.Event.ID,
			Accepted: false,
			Message:  fmt.Sprintf("auth-error: %s", err.Error()),
		})
		return nil
	}

	// Verify signature
	if err := ap.Event.Verify(); err != nil {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ap.Event.ID,
			Accepted: false,
			Message:  "auth-error: invalid signature",
		})
		return nil
	}

	// Success
	s.authedPubkey = ap.Event.PubKey
	s.reply(&wire.OkSubscriptionResponse{
		EventID:  ap.Event.ID,
		Accepted: true,
		Message:  "auth-success",
	})

	s.config.Logger.Info().Str("pubkey", s.authedPubkey).Msg("client authenticated")

	return nil
}

/////////////////////////////////////////////////////////////////////
// COUNT
/////////////////////////////////////////////////////////////////////

func (s *Session) processCount(parent context.Context, cp *wire.CountPacket) error {

	// We calculate count immediately and return
	count, err := s.store.CountEvents(parent, cp.Filters)
	if err != nil {
		s.reply(&wire.NoticeSubscriptionResponse{
			Message: fmt.Sprintf("count failed: %s", err.Error()),
		})
		return nil
	}

	s.reply(&wire.CountSubscriptionResponse{
		SubscriptionID: cp.SubscriptionID,
		Count:          count,
	})

	return nil
}

/////////////////////////////////////////////////////////////////////
// EVENT
/////////////////////////////////////////////////////////////////////

type EventValidator func(context.Context, *nip01.Event) error

var (
	eventValidatorsMu sync.RWMutex
	eventValidators   = make(map[int][]EventValidator)
)

// RegisterEventValidator appends a validator for a specific event kind.
func RegisterEventValidator(kind int, validator EventValidator) {
	if validator == nil {
		return
	}
	eventValidatorsMu.Lock()
	eventValidators[kind] = append(eventValidators[kind], validator)
	eventValidatorsMu.Unlock()
}

func getEventValidators(kind int) []EventValidator {
	eventValidatorsMu.RLock()
	validators := eventValidators[kind]
	eventValidatorsMu.RUnlock()
	if len(validators) == 0 {
		return nil
	}
	copyValidators := make([]EventValidator, len(validators))
	copy(copyValidators, validators)
	return copyValidators
}

func runEventValidators(ctx context.Context, ev *nip01.Event) error {
	if ev == nil {
		return nil
	}
	for _, validator := range getEventValidators(ev.Kind) {
		if validator == nil {
			continue
		}
		if err := validator(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) processEvent(ctx context.Context, ep *wire.EventPacket) error {

	if s.limitation.AuthRequired && s.authedPubkey == "" {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ep.Event.ID,
			Accepted: false,
			Message:  "restricted: valid NIP-42 authentication required",
		})
		return nil
	}

	if err := ep.Event.Validate(); err != nil {

		s.config.Logger.Error().Err(err).Msgf("failed to validate, ID=%s", ep.Event.ID)

		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ep.Event.ID,
			Accepted: false,
			Message:  fmt.Sprintf("invalid: %s", err.Error()),
		})

		return nil
	}

	if err := ep.Event.Verify(); err != nil {

		s.config.Logger.Error().Err(err).Msgf("failed to verify, ID=%s", ep.Event.ID)

		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ep.Event.ID,
			Accepted: false,
			Message:  fmt.Sprintf("invalid: %s", err.Error()),
		})

		return nil
	}

	if err := runEventValidators(ctx, ep.Event); err != nil {
		s.config.Logger.Error().Err(err).Msgf("event validation failed, ID=%s kind=%d", ep.Event.ID, ep.Event.Kind)

		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ep.Event.ID,
			Accepted: false,
			Message:  fmt.Sprintf("invalid: %s", err.Error()),
		})

		return nil
	}

	task := NewEventInsertTask([]*nip01.Event{ep.Event})
	go func() {
		select {

		case <-task.done:

			s.reply(&wire.OkSubscriptionResponse{
				EventID:  ep.Event.ID,
				Accepted: true,
			})

		case err := <-task.errors:

			switch {

			case errors.Is(err, ErrStoreClosed):
				return

			case errors.Is(err, ErrEventDuplicated):

				s.reply(&wire.OkSubscriptionResponse{
					EventID:  ep.Event.ID,
					Accepted: true,
					Message:  fmt.Sprintf("duplicate: %s", err.Error()),
				})

			case errors.Is(err, context.Canceled):
				return

			case errors.Is(err, ErrRateLimited):
				s.reply(&wire.OkSubscriptionResponse{
					EventID:  ep.Event.ID,
					Accepted: false,
					Message:  fmt.Sprintf("%s", err.Error()),
				})

			default:

				// Log the full error server-side, but don't forward it to the client:
				// unrecognized errors here come from the storage layer, not from
				// anything the client did wrong, and may contain internal details
				// (bucket/key layout, etc.) that shouldn't leak over the wire.
				s.config.Logger.Error().Err(err).Msgf("event rejected ID=%s", ep.Event.ID)

				s.reply(&wire.OkSubscriptionResponse{
					EventID:  ep.Event.ID,
					Accepted: false,
					Message:  "error: could not store event",
				})
			}
		}

	}()

	s.executeStoreTask(ctx, task)

	// NIP-50 INDEXING (Async)
	if ep.Event.Kind == 0 && s.SearchService != nil {
		doc := search.FromEvent(ep.Event)
		if doc != nil {
			err := s.SearchService.IndexProfileWithMetrics(ctx, doc, func(pubkey string) (int64, error) {
				m, err := s.store.GetProfileMetrics(pubkey)
				if err != nil || m == nil {
					return 0, err
				}
				// Return the extra metrics to append
				return m.TotalScore() - m.BaseScore, nil
			})
			if err != nil {
				// log.Warn().Err(err).Msg("failed to queue profile for indexing")
			}
		}

		// Verification Workers (Async)
		if s.VerificationWorker != nil {
			s.VerificationWorker.QueueJob(ep.Event)
		}
	}

	return nil

}

/////////////////////////////////////////////////////////////////////
// REPLYER
/////////////////////////////////////////////////////////////////////

type replyer struct {
	incoming  chan wire.SubscriptionResponse
	closeCh   chan interface{}
	closeOnce sync.Once
}

func (r *replyer) reply(sr wire.SubscriptionResponse) {
	select {
	case <-r.closeCh:
	case r.incoming <- sr:
	}
}

/////////////////////////////////////////////////////////////////////
// NEG-OPEN
/////////////////////////////////////////////////////////////////////

func (s *Session) processNegOpen(ctx context.Context, p *wire.NegOpenPacket) error {

	items, err := s.store.QueryNip77Items(ctx, p.Filter)
	if err != nil {
		return fmt.Errorf("failed to query items: %w", err)
	}

	// Reverse to ASCENDING
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}

	neg := nip77.New(items)

	s.negMu.Lock()
	s.negentropySessions[p.SubscriptionID] = neg
	s.negMu.Unlock()

	theirMsg, err := nip77.FromHex(p.Message)
	if err != nil {
		s.reply(&wire.NegErrPacket{
			SubscriptionID: p.SubscriptionID,
			Code:           "parse-error",
		})
		return nil
	}

	responseMsg, _, _, err := neg.Reconcile(theirMsg)
	if err != nil {
		s.reply(&wire.NegErrPacket{
			SubscriptionID: p.SubscriptionID,
			Code:           fmt.Sprintf("reconcile-error: %v", err),
		})
		return nil
	}

	respHex, _ := responseMsg.ToHex()
	s.reply(&wire.NegMsgPacket{
		SubscriptionID: p.SubscriptionID,
		Message:        respHex,
	})

	return nil
}

/////////////////////////////////////////////////////////////////////
// NEG-MSG
/////////////////////////////////////////////////////////////////////

func (s *Session) processNegMsg(ctx context.Context, p *wire.NegMsgPacket) error {

	s.negMu.Lock()
	neg, exists := s.negentropySessions[p.SubscriptionID]
	s.negMu.Unlock()

	if !exists {
		s.reply(&wire.NegErrPacket{
			SubscriptionID: p.SubscriptionID,
			Code:           "unknown-session",
		})
		return nil
	}

	theirMsg, err := nip77.FromHex(p.Message)
	if err != nil {
		s.reply(&wire.NegErrPacket{
			SubscriptionID: p.SubscriptionID,
			Code:           "parse-error",
		})
		return nil
	}

	responseMsg, _, _, err := neg.Reconcile(theirMsg)
	if err != nil {
		s.reply(&wire.NegErrPacket{
			SubscriptionID: p.SubscriptionID,
			Code:           fmt.Sprintf("reconcile-error: %v", err),
		})
		return nil
	}

	respHex, _ := responseMsg.ToHex()
	s.reply(&wire.NegMsgPacket{
		SubscriptionID: p.SubscriptionID,
		Message:        respHex,
	})

	return nil
}

/////////////////////////////////////////////////////////////////////
// NEG-CLOSE
/////////////////////////////////////////////////////////////////////

func (s *Session) processNegClose(ctx context.Context, p *wire.NegClosePacket) error {
	s.negMu.Lock()
	delete(s.negentropySessions, p.SubscriptionID)
	s.negMu.Unlock()

	return nil
}

/////////////////////////////////////////////////////////////////////
// NEG-ERR
/////////////////////////////////////////////////////////////////////

func (s *Session) processNegErr(ctx context.Context, p *wire.NegErrPacket) error {
	s.config.Logger.Warn().Str("sub", p.SubscriptionID).Str("code", p.Code).Msg("received NEG-ERR")
	return nil
}

// IsPacketError checks if the error is a wire.PacketError
func IsPacketError(err error) bool {
	var pe *wire.PacketError
	return errors.As(err, &pe)
}
