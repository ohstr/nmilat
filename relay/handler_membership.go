package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/wire"
)

// InviteRequestAuthorizer decides whether a connection may receive a
// NIP-43 invite code through a kind:28935 REQ. A nil error allows it; any
// other refuses it, and its text is the CLOSED reason. s.Identities()
// lists every identity authenticated on the connection, NIP-AA virtual
// ones included. It runs on the connection's read loop and must be safe
// for concurrent use.
type InviteRequestAuthorizer func(ctx context.Context, s *Session) error

// MembershipRequestHandler serves NIP-43's kind:28935 Invite Request: a
// client REQs for this kind, and the relay generates and signs a fresh
// invite code on the fly. Per spec, this is deliberately in the ephemeral
// kind range so relays "improve security by issuing a different claim for
// each request." Mirrors CacheHandler's shape (relay-signed, one-shot,
// synthetic response to a REQ, not an EVENT).
//
// Upstream NIP-43 has since dropped this REQ flow in favour of NIP-86's
// createclaim; it is kept for compatibility. An embedder should set
// SessionConfig.InviteRequestAuthorizer (WithInviteRequestAuthorizer) to
// decide who may receive a code: leaving it nil, which issues a code to
// every connection that passes the read gate, is deprecated.
type MembershipRequestHandler struct{}

// CanHandle takes a REQ only when every one of its filters asks for kind
// 28935 and nothing else. A REQ that mixes it with other filters, or with
// other kinds in the same filter, is an ordinary subscription and is left
// to the standard handler.
func (h *MembershipRequestHandler) CanHandle(rp *wire.RequestPacket) bool {
	filters := rp.Filters.GetAll()
	if len(filters) == 0 {
		return false
	}
	for _, f := range filters {
		if len(f.Kinds) == 0 {
			return false
		}
		for _, k := range f.Kinds {
			if k != nip43.KindInviteRequest {
				return false
			}
		}
	}
	return true
}

func (h *MembershipRequestHandler) Handle(ctx context.Context, s *Session, rp *wire.RequestPacket) (bool, error) {
	if s.membership == nil {
		s.reply(&wire.ClosedSubscriptionResponse{
			SubscriptionID: rp.SubscriptionID,
			Message:        "unsupported: NIP-43 membership is not enabled on this relay",
		})
		return true, nil
	}
	if authorize := s.config.InviteRequestAuthorizer; authorize != nil {
		if err := authorize(ctx, s); err != nil {
			s.refuse(rp.SubscriptionID, inviteRefusal(s, err))
			return true, nil
		}
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

// inviteRefusal is the reason an invite request the authorizer refused is
// closed with: NIP-42's "auth-required:" while the connection has no
// authenticated identity, so the client knows to AUTH, else "restricted:"
// with the authorizer's reason.
func inviteRefusal(s *Session, err error) string {
	if s.AuthedPubkey() == "" {
		return "auth-required: authentication required to request an invite"
	}
	reason := strings.TrimSpace(err.Error())
	if reason == "" {
		reason = "invite requests are not allowed for this connection"
	}
	return "restricted: " + reason
}
