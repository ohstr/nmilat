package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/wire"
)

// MembershipRequestHandler serves NIP-43's kind:28935 Invite Request: a
// client REQs for this kind, and the relay generates and signs a fresh
// invite code on the fly. Per spec, this is deliberately in the ephemeral
// kind range so relays "improve security by issuing a different claim for
// each request." Mirrors CacheHandler's shape (relay-signed, one-shot,
// synthetic response to a REQ, not an EVENT).
type MembershipRequestHandler struct{}

func (h *MembershipRequestHandler) CanHandle(rp *wire.RequestPacket) bool {
	for _, f := range rp.Filters.GetAll() {
		if slices.Contains(f.Kinds, nip43.KindInviteRequest) {
			return true
		}
	}
	return false
}

func (h *MembershipRequestHandler) Handle(ctx context.Context, s *Session, rp *wire.RequestPacket) (bool, error) {
	if s.membership == nil {
		s.reply(&wire.ClosedSubscriptionResponse{
			SubscriptionID: rp.SubscriptionID,
			Message:        "unsupported: NIP-43 membership is not enabled on this relay",
		})
		return true, nil
	}
	if s.config.PrivKey == "" {
		return true, fmt.Errorf("relay private key missing, cannot serve signed invite response")
	}

	rec, err := s.membership.IssueInvite(s.config.MembershipInviteTTL, s.config.MembershipInviteMaxUses, nil)
	if err != nil {
		return true, fmt.Errorf("failed to store invite claim: %w", err)
	}

	event := nip43.NewInviteResponse(s.selfPubkey, rec.Code)
	if err := event.Sign(s.config.PrivKey); err != nil {
		return true, fmt.Errorf("failed to sign invite response: %w", err)
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return true, fmt.Errorf("failed to marshal invite response: %w", err)
	}

	s.reply(&wire.EventSubscriptionResponse{SubscriptionID: rp.SubscriptionID, EventBytes: eventBytes})
	s.reply(&wire.EOSESubscriptionResponse{SubscriptionID: rp.SubscriptionID})
	s.reply(&wire.ClosedSubscriptionResponse{
		SubscriptionID: rp.SubscriptionID,
		Message:        "one-shot invite request completed",
	})

	return true, nil
}
