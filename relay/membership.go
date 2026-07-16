package relay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/wire"
)

// init registers NIP-43's purely structural, session-independent
// validators through the existing RegisterEventValidator hook -- tag
// shape, hex format, and (for Join/Leave) timestamp freshness. This is
// deliberately the only NIP-43 enforcement that goes through that
// mechanism: everything else (self-authored-pubkey checks, join/leave side
// effects) needs *Session/*SessionContext, which EventValidator's
// signature has no access to (see relay/packet.go's processEvent gate,
// and a later phase's join/leave handling).
func init() {
	for _, kind := range []int{
		nip43.KindRoleDefinition,
		nip43.KindMembershipList,
		nip43.KindAddUser,
		nip43.KindRemoveUser,
		nip43.KindInviteRequest,
	} {
		RegisterEventValidator(kind, validateNip43Structure)
	}
	RegisterEventValidator(nip43.KindJoinRequest, validateNip43RequestStructure)
	RegisterEventValidator(nip43.KindLeaveRequest, validateNip43RequestStructure)
}

func validateNip43Structure(_ context.Context, ev *nip01.Event) error {
	switch ev.Kind {
	case nip43.KindRoleDefinition:
		_, err := nip43.ParseRole(ev)
		return err
	case nip43.KindMembershipList:
		_, err := nip43.ParseMembershipList(ev)
		return err
	case nip43.KindAddUser:
		_, err := nip43.ParseAddUser(ev)
		return err
	case nip43.KindRemoveUser:
		_, err := nip43.ParseRemoveUser(ev)
		return err
	case nip43.KindInviteRequest:
		_, err := nip43.ParseInviteResponse(ev)
		return err
	}
	return nil
}

// validateNip43RequestStructure checks Join/Leave request tag shape and
// created_at freshness. Claim-validity (is this actually a live invite
// code) is session/store-aware and handled separately by a later phase.
func validateNip43RequestStructure(_ context.Context, ev *nip01.Event) error {
	switch ev.Kind {
	case nip43.KindJoinRequest:
		if _, err := nip43.ParseJoinRequest(ev); err != nil {
			return err
		}
	case nip43.KindLeaveRequest:
		if _, err := nip43.ParseLeaveRequest(ev); err != nil {
			return err
		}
	default:
		return nil
	}
	return nip43.ValidateFreshness(ev.CreatedAt, time.Now(), nip43.DefaultRequestFreshnessWindow)
}

// HandleEvent processes a NIP-43 Join (kind 28934) or Leave (kind 28936)
// request, replying via s and mutating membership state as a side effect.
// Callers (processEvent) should invoke this only for those two kinds; it
// always replies (never falls through silently), since a client sending
// one of these kinds is unambiguously attempting to use this feature --
// including when m is nil (NIP-43 membership isn't configured on this
// relay at all), which gets an explicit "restricted" reply rather than
// being silently accepted as an ordinary ephemeral event.
func (m *MembershipService) HandleEvent(ctx context.Context, s *Session, ev *nip01.Event) {
	if m == nil {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: false,
			Message:  "restricted: NIP-43 membership is not enabled on this relay",
		})
		return
	}
	switch ev.Kind {
	case nip43.KindJoinRequest:
		m.handleJoin(ctx, s, ev)
	case nip43.KindLeaveRequest:
		m.handleLeave(ctx, s, ev)
	}
}

func (m *MembershipService) handleJoin(ctx context.Context, s *Session, ev *nip01.Event) {
	// Structural validation (claim tag present, freshness) already ran via
	// the RegisterEventValidator hook before processEvent ever reached
	// this point -- this re-parse is defensive, not expected to fail in
	// practice.
	jr, err := nip43.ParseJoinRequest(ev)
	if err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}

	if m.IsMember(ev.PubKey) {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: true,
			Message:  "duplicate: you are already a member of this relay.",
		})
		return
	}

	claim, err := s.store.ConsumeInviteClaim(jr.Claim, time.Now().Unix())
	if err != nil {
		// ErrInviteClaimNotFound and ErrInviteClaimExhausted both read as
		// "invalid invite code" to the requester -- a used-up single-use
		// code is indistinguishable from an unknown one from their side.
		msg := "restricted: that is an invalid invite code."
		if errors.Is(err, ErrInviteClaimExpired) {
			msg = "restricted: that invite code is expired."
		} else if !errors.Is(err, ErrInviteClaimNotFound) && !errors.Is(err, ErrInviteClaimExhausted) {
			s.config.Logger.Error().Err(err).Str("pubkey", ev.PubKey).Msg("failed to consume invite claim")
			msg = "error: could not validate invite code"
		}
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: msg})
		return
	}

	if err := m.Join(ev.PubKey, claim.Roles); err != nil {
		s.config.Logger.Error().Err(err).Str("pubkey", ev.PubKey).Msg("failed to persist new member")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not store membership"})
		return
	}

	if s.config.MembershipPublishAddRemove {
		m.publishSelfSigned(ctx, s, nip43.NewAddUser(s.selfPubkey, ev.PubKey))
	}

	s.reply(&wire.OkSubscriptionResponse{
		EventID:  ev.ID,
		Accepted: true,
		Message:  fmt.Sprintf("info: welcome to %s!", s.relayURL),
	})
}

func (m *MembershipService) handleLeave(ctx context.Context, s *Session, ev *nip01.Event) {
	if _, err := nip43.ParseLeaveRequest(ev); err != nil {
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "restricted: " + err.Error()})
		return
	}

	if !m.IsMember(ev.PubKey) {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ev.ID,
			Accepted: true,
			Message:  "duplicate: you are not a member of this relay.",
		})
		return
	}

	if err := m.Leave(ev.PubKey); err != nil {
		s.config.Logger.Error().Err(err).Str("pubkey", ev.PubKey).Msg("failed to remove member")
		s.reply(&wire.OkSubscriptionResponse{EventID: ev.ID, Accepted: false, Message: "error: could not update membership"})
		return
	}

	if s.config.MembershipPublishAddRemove {
		m.publishSelfSigned(ctx, s, nip43.NewRemoveUser(s.selfPubkey, ev.PubKey))
	}

	s.reply(&wire.OkSubscriptionResponse{
		EventID:  ev.ID,
		Accepted: true,
		Message:  "info: you have left this relay.",
	})
}

// publishSelfSigned signs ev with the relay's own PrivKey and inserts it
// directly into the store, bypassing the async EventInsertTask/OK-reply
// machinery entirely -- this is a relay-initiated side effect (kind
// 8000/8001), not something the requesting client is waiting on an OK
// for. Failures are logged, not propagated: a failed advisory
// add/remove-user broadcast must never fail the join/leave itself, since
// the authoritative membership state (relay/store_membership.go) was
// already committed by the time this runs.
func (m *MembershipService) publishSelfSigned(ctx context.Context, s *Session, ev *nip01.Event) {
	if s.config.PrivKey == "" {
		return
	}
	if err := ev.Sign(s.config.PrivKey); err != nil {
		s.config.Logger.Error().Err(err).Int("kind", ev.Kind).Msg("failed to sign membership add/remove event")
		return
	}
	if err := s.store.InsertEvents(ctx, []*nip01.Event{ev}); err != nil {
		s.config.Logger.Error().Err(err).Int("kind", ev.Kind).Msg("failed to publish membership add/remove event")
	}
}

// CheckSelfAuthored reports whether ev is allowed given selfPubkey, the
// relay's own configured NIP-11 "self" identity (relay/nip11.Metadata.Self).
// Kinds NIP-43 requires to be relay-authored (role definitions, membership
// lists, add/remove-user, invite responses) MUST be signed by selfPubkey;
// every other kind passes unconditionally. selfPubkey == "" (no self
// identity configured) means every relay-authored kind is rejected outright
// -- there is no valid signer for them, so failing closed is the only sound
// default.
func CheckSelfAuthored(ev *nip01.Event, selfPubkey string) (ok bool, message string) {
	if !nip43.IsRelayAuthoredKind(ev.Kind) {
		return true, ""
	}
	if selfPubkey == "" || ev.PubKey != selfPubkey {
		return false, "restricted: this event kind may only be published by the relay itself"
	}
	return true, ""
}
