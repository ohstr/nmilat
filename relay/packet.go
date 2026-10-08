package relay

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/nip70"
	"github.com/ohstr/nmilat/nip77"
	"github.com/ohstr/nmilat/nipAA"
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

// readGate is the connection-level check REQ and COUNT share, returning
// the refusal reason or "". NIP-42: "auth-required:" when the client has
// not authenticated (so it knows to AUTH), "restricted:" when it has and
// still may not read. NIP-43: a request passes "if at least one
// authenticated pubkey on the connection holds active or virtual
// membership" -- unlike the per-event gate in processEvent.
// groupRefusal is the reason a private group read is refused: NIP-42's
// "auth-required:" until the client authenticates, then "restricted:".
func groupRefusal(s *Session, groupID string) string {
	if s.AuthedPubkey() == "" {
		return fmt.Sprintf("auth-required: valid membership in group %s is required", groupID)
	}
	return fmt.Sprintf("restricted: valid membership in group %s is required", groupID)
}

func (s *Session) readGate() string {
	authed := s.AuthedPubkey() != ""
	if s.limitation.AuthRequired && !authed {
		return "auth-required: valid NIP-42 authentication required"
	}
	if s.limitation.MembershipRequired && !s.HasMembership() {
		if !authed {
			return "auth-required: valid NIP-43 membership required"
		}
		return "restricted: valid NIP-43 membership required"
	}
	return ""
}

// refuse answers a REQ/COUNT the relay won't serve: a NOTICE, and the
// CLOSED NIP-01 and NIP-45 call for so the client stops waiting.
func (s *Session) refuse(subID, msg string) {
	s.reply(&wire.NoticeSubscriptionResponse{Message: msg})
	s.reply(&wire.ClosedSubscriptionResponse{SubscriptionID: subID, Message: msg})
}

func (s *Session) processRequest(ctx context.Context, rp *wire.RequestPacket) error {

	if msg := s.readGate(); msg != "" {
		s.refuse(rp.SubscriptionID, msg)
		return nil
	}

	// NIP-29: a REQ naming a private group's id (via a "d"/"h" tag filter)
	// must come from a session with a member identity in that group -- see
	// GroupsService.deniedPrivateGroupFilter and
	// docs/specs/nip29-groups-plan.md's "Visibility gating" section. Public
	// groups, and ids naming no known group, are unaffected.
	if groupID, denied := s.groups.deniedPrivateGroupFilter(s, rp.Filters); denied {
		msg := groupRefusal(s, groupID)
		s.reply(&wire.NoticeSubscriptionResponse{Message: msg})
		s.reply(&wire.ClosedSubscriptionResponse{
			SubscriptionID: rp.SubscriptionID,
			Message:        msg,
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

	// A CLOSE naming a subscription that's already gone -- most commonly
	// because the relay itself already ended it (a restricted CLOSED, an
	// EOSE the client is closing out of habit after, or any other reply
	// that calls s.subscriptions.Close on this package's own behalf) --
	// is not a protocol violation worth tearing the whole connection
	// down over. This used to return a wire.PacketError here, which
	// (unlike processRequest's own per-handler error replies, or Recv's
	// soft handling of a PacketError from a malformed wire message)
	// nothing catches on this path: it propagated all the way up through
	// ProcessPacket/Recv as fatal, killing a connection that was
	// otherwise perfectly healthy over one stray/late/redundant CLOSE.
	// Subscriptions.Close is already a safe no-op on an unknown id (a
	// map-lookup miss), so there is nothing left to guard here.
	s.subscriptions.Close(cp.SubscriptionID)

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

	// Step 1 (NIP-42): check against the relay's own configured URL, not a
	// value read off the client's own tag -- otherwise the check is a
	// tautology.
	if err := nip42.ValidateAuthEvent(ap.Event.Kind, ap.Event.Tags, ap.Event.CreatedAt, s.challenge, s.relayURL); err != nil {
		return s.rejectAuth(ap.Event.ID, fmt.Sprintf("auth-error: %s", err.Error()))
	}

	if err := ap.Event.Verify(); err != nil {
		return s.rejectAuth(ap.Event.ID, "auth-error: invalid signature")
	}

	// Step 1 (NIP-AA addendum): an additional, narrower freshness window
	// on top of (not instead of) NIP-42's own ValidateAuthEvent check
	// above -- only enforced when NIP-AA is actually in play, since a
	// tighter window than NIP-42's own ±600s is specific to NIP-AA's
	// concerns (bounding how long a credential's created_at< condition can
	// be satisfied by backdating), not a general NIP-42 requirement.
	if s.config.AgentAuthEnabled {
		window := s.config.AgentAuthFreshnessWindow
		if window <= 0 {
			window = nipAA.DefaultFreshnessWindow
		}
		if err := nipAA.ValidateFreshness(ap.Event.CreatedAt, time.Now(), window); err != nil {
			return s.rejectAuth(ap.Event.ID, fmt.Sprintf("auth-error: %s", err.Error()))
		}
	}

	// Step 2: the fast path. If event.pubkey is already a direct/active
	// NIP-43 member, grant access immediately -- no NIP-OA parsing or
	// Schnorr verification ever runs for this, the overwhelmingly common
	// case (any direct member, including every reconnect). This is the
	// single biggest performance property of the whole NIP-43/NIP-AA
	// design: Steps 3-6's extra crypto work is paid only for pubkeys that
	// are NOT already direct members.
	if s.membership.IsMember(ap.Event.PubKey) {
		s.addIdentity(AuthedIdentity{Pubkey: ap.Event.PubKey, Membership: MembershipActive})
		return s.acceptAuth(ap.Event.ID, ap.Event.PubKey)
	}

	if !s.config.AgentAuthEnabled {
		// Plain NIP-43 (NIP-AA off): AUTH always succeeds regardless of
		// membership -- access decisions are deferred to the
		// MembershipRequired gate at REQ/EVENT time, matching NIP-42's own
		// "AUTH proves identity, doesn't itself grant access" philosophy
		// and this relay's existing behavior before NIP-AA existed.
		s.addIdentity(AuthedIdentity{Pubkey: ap.Event.PubKey, Membership: MembershipNone})
		return s.acceptAuth(ap.Event.ID, ap.Event.PubKey)
	}

	// Steps 3-4: find and verify the auth tag's signature and conditions'
	// created_at clauses (kind= clauses deliberately not evaluated here --
	// see nipAA.EvaluateCredential's doc comment).
	cred, err := nipAA.EvaluateCredential(ap.Event.PubKey, ap.Event.Tags, ap.Event.CreatedAt)
	if err != nil {
		return s.rejectAuth(ap.Event.ID, "restricted: "+err.Error())
	}
	if cred == nil {
		// Step 3's "no credential offered, and not a direct member"
		// case.
		return s.rejectAuth(ap.Event.ID, "restricted: not a member")
	}

	// Step 5: the owner named in the credential must itself be an active
	// member.
	if !s.membership.IsMember(cred.OwnerPubkey) {
		return s.rejectAuth(ap.Event.ID, "restricted: owner is not a member")
	}

	// Step 6: grant virtual membership, scoped to event.pubkey
	// specifically -- never persisted, never the connection as a whole.
	// addIdentity overwrites in place if this pubkey already has an
	// identity on this connection, per spec: "If the same agent pubkey
	// completes NIP-AA authentication again on the same connection... the
	// relay MUST replace the previously stored credential with the new
	// one... MUST NOT combine credentials."
	s.addIdentity(AuthedIdentity{
		Pubkey:     ap.Event.PubKey,
		Membership: MembershipVirtual,
		Owner:      cred.OwnerPubkey,
		Conditions: &cred.Conditions,
	})
	return s.acceptAuth(ap.Event.ID, ap.Event.PubKey)
}

func (s *Session) acceptAuth(eventID, pubkey string) error {
	s.reply(&wire.OkSubscriptionResponse{EventID: eventID, Accepted: true, Message: "auth-success"})
	s.config.Logger.Info().Str("pubkey", pubkey).Msg("client authenticated")
	return nil
}

func (s *Session) rejectAuth(eventID, message string) error {
	s.reply(&wire.OkSubscriptionResponse{EventID: eventID, Accepted: false, Message: message})
	return nil
}

/////////////////////////////////////////////////////////////////////
// COUNT
/////////////////////////////////////////////////////////////////////

func (s *Session) processCount(parent context.Context, cp *wire.CountPacket) error {

	// Same gates as REQ: a count is a read too.
	if msg := s.readGate(); msg != "" {
		s.refuse(cp.SubscriptionID, msg)
		return nil
	}

	// NIP-29: see the matching gate in processRequest.
	if groupID, denied := s.groups.deniedPrivateGroupFilter(s, cp.Filters); denied {
		s.refuse(cp.SubscriptionID, groupRefusal(s, groupID))
		return nil
	}

	// We calculate count immediately and return.
	//
	// NIP-29: deniedPrivateGroupFilter above only catches a filter that
	// names a group by its own "d"/"h" tag -- an untagged query like
	// {"kinds":[39000]} names none, so it reaches here unfiltered. A raw
	// CountEvents would then return the total number of groups on the
	// relay, private ones included, even though a REQ for the identical
	// filter would never deliver that many events (relay/handlers.go's
	// delivery loop drops each one deniedPrivateGroupPotentialEvent
	// denies). Route exactly the kinds that could be group metadata
	// through the same per-event predicate before counting; every other
	// kind keeps the fast raw-count path.
	var count int64
	var err error
	if s.groups.needsPrivacyCheck(cp.Filters) {
		count, err = s.store.CountEventsFiltered(parent, cp.Filters, func(pe *PotentialEvent) bool {
			return s.groups.deniedPrivateGroupPotentialEvent(s, pe)
		})
	} else {
		count, err = s.store.CountEvents(parent, cp.Filters)
	}
	if err != nil {
		s.refuse(cp.SubscriptionID, fmt.Sprintf("error: count failed: %s", err.Error()))
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

	if s.limitation.AuthRequired && s.AuthedPubkey() == "" {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ep.Event.ID,
			Accepted: false,
			Message:  "auth-required: valid NIP-42 authentication required",
		})
		return nil
	}

	// NIP-AA: optional per-event kind= enforcement for virtual members.
	// Off by default. ep.Event.Kind and ep.Event.PubKey are both readable
	// straight off the wire struct with no crypto, so this runs before
	// Validate/Verify/PoW -- rejecting a disallowed kind before paying any
	// signature-verification cost on an event that's going to be thrown
	// away anyway. No signature re-verification here either:
	// id.Conditions is the credential already verified once, at AUTH time
	// (see AuthedIdentity) -- this is a pure, cheap clause comparison.
	if s.config.AgentAuthEnabled && s.config.AgentKindEnforcement {
		if id, ok := s.IdentityMembership(ep.Event.PubKey); ok && id.Membership == MembershipVirtual && id.Conditions != nil {
			if !id.Conditions.EvaluateKind(ep.Event.Kind) {
				s.reply(&wire.OkSubscriptionResponse{
					EventID:  ep.Event.ID,
					Accepted: false,
					Message:  "restricted: kind not authorized by credential",
				})
				return nil
			}
		}
	}

	// NIP-43: reject impersonation of relay-authored kinds (role
	// definitions, membership lists, add/remove-user, invite responses)
	// before spending any Validate/Verify/PoW CPU on them -- ev.Kind and
	// ev.PubKey are both readable straight off the wire struct, no crypto
	// needed to make this determination.
	if ok, msg := CheckSelfAuthored(ep.Event, s.selfPubkey); !ok {
		s.reply(&wire.OkSubscriptionResponse{
			EventID:  ep.Event.ID,
			Accepted: false,
			Message:  msg,
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

	// A nonce tag's declared difficulty is only checked against the event's
	// actual ID when StrictPow is on -- same gate as the MinPowDifficulty
	// floor below. Off (the default), a nonce tag that overclaims its
	// difficulty is tolerated rather than treated as an invalid event: NIP-13
	// PoW is opt-in per-event, and a relay that hasn't opted into enforcing
	// it shouldn't reject an event just because its self-reported difficulty
	// doesn't hold up.
	var verifyOpts []nip01.VerifyOption
	if !s.limitation.StrictPow {
		verifyOpts = append(verifyOpts, nip01.WithoutPowCheck())
	}
	// Hand the difficulty floor to Verify rather than checking it afterwards.
	// Verify applies it once the ID is known to match the event's contents but
	// before the schnorr signature check, so an event that fails the floor no
	// longer costs this relay a secp256k1 verification first. Checked after
	// Verify — as this did — the floor could not defend against flooding at all.
	if s.limitation.StrictPow && s.limitation.MinPowDifficulty > 0 {
		verifyOpts = append(verifyOpts, nip01.WithMinPowDifficulty(s.limitation.MinPowDifficulty))
	}

	if err := ep.Event.Verify(verifyOpts...); err != nil {
		// Preserve the distinct "pow: ..." rejection message; a client
		// distinguishes "mine harder" from "your event is malformed".
		var powErr *nip01.InsufficientPowError
		if errors.As(err, &powErr) {
			s.config.Logger.Info().
				Str("id", ep.Event.ID).
				Int("difficulty", powErr.Got).
				Int("required", powErr.Want).
				Msg("event rejected: insufficient proof of work")

			s.reply(&wire.OkSubscriptionResponse{
				EventID:  ep.Event.ID,
				Accepted: false,
				Message:  powErr.Error(),
			})

			return nil
		}

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

	// NIP-70: a protected event may only be published by its own author, and
	// a valid signature is not enough to establish that -- anyone who has
	// seen the event can replay it. So the author must have authenticated on
	// *this* connection. The NIP-43 join below carries ["-"], which is why
	// this gate sits above it: without it a captured join could be replayed
	// by a third party to burn an invite's remaining uses.
	if nip70.IsProtected(ep.Event.Tags) {
		if _, authed := s.IdentityMembership(ep.Event.PubKey); !authed {
			// auth-required when nothing has authenticated as this pubkey, so
			// a client knows to run AUTH and retry; restricted once something
			// else has, since retrying cannot help.
			message := "auth-required: this event is protected and its author must authenticate first"
			if s.AuthedPubkey() != "" {
				message = "restricted: a protected event may only be published by its author"
			}
			s.reply(&wire.OkSubscriptionResponse{
				EventID:  ep.Event.ID,
				Accepted: false,
				Message:  message,
			})
			return nil
		}
	}

	// NIP-43: Join/Leave requests are fully owned by MembershipService from
	// here -- structural/freshness validation already passed above
	// (runEventValidators), the signature is verified, and NIP-70 above
	// established that the author authenticated on this connection, so
	// ep.Event.PubKey can be trusted for the membership mutation this
	// performs. These kinds never reach the generic store-and-OK path
	// below: they're commands, not content to persist/broadcast (and, per
	// NIP-16, ephemeral kinds like these wouldn't be persisted through it
	// anyway).
	if ep.Event.Kind == nip43.KindJoinRequest || ep.Event.Kind == nip43.KindLeaveRequest {
		s.membership.HandleEvent(ctx, s, ep.Event)
		return nil
	}

	// NIP-29: every moderation event (kind:9000-9020: create/delete group,
	// put/remove user, edit metadata, moderator delete-event, create
	// invite, update pin list) and group-scoped user request (kind:9021/
	// 9022 join/leave, distinct from NIP-43's own relay-wide join/leave) is
	// fully owned by GroupsService from here, the same way NIP-43's
	// Join/Leave above are fully owned by MembershipService -- structural
	// validation already passed above (runEventValidators, when
	// nip29/relayreg is blank-imported), the signature is verified, and
	// ep.Event.PubKey can be trusted. Like Join/Leave, these are commands,
	// not content to persist/broadcast through the generic store-and-OK
	// path below.
	if nip29.IsModerationKind(ep.Event.Kind) || nip29.IsUserRequestKind(ep.Event.Kind) {
		s.groups.HandleEvent(ctx, s, ep.Event)
		return nil
	}

	// NIP-29 content: only members post into a private or closed group.
	if msg := s.groups.deniedGroupWrite(ep.Event); msg != "" {
		s.reply(&wire.OkSubscriptionResponse{EventID: ep.Event.ID, Accepted: false, Message: msg})
		return nil
	}

	// NIP-43: relay-authored kinds already passed the stricter
	// self-authored check above; everything else needs active-or-virtual
	// membership on the specific pubkey that signed this event, when
	// membership is required. Per NIP-AA's later wording: "relay MUST
	// verify event.pubkey is authenticated on the connection AND holds
	// active or virtual membership" -- a specific-signer check, not merely
	// "is anything authenticated on this connection" (a real tightening
	// versus AuthRequired's own connection-level-only semantics above).
	if s.limitation.MembershipRequired && !nip43.IsRelayAuthoredKind(ep.Event.Kind) {
		if id, ok := s.IdentityMembership(ep.Event.PubKey); !ok || id.Membership == MembershipNone {
			msg := "restricted: valid NIP-43 membership required"
			if !ok {
				// The signer never authenticated here: NIP-42 says so with
				// auth-required, so the client can AUTH as it and retry.
				msg = "auth-required: valid NIP-43 membership required"
			}
			s.reply(&wire.OkSubscriptionResponse{
				EventID:  ep.Event.ID,
				Accepted: false,
				Message:  msg,
			})
			return nil
		}
	}

	task := NewEventInsertTask([]*nip01.Event{ep.Event})

	// Every EVENT gets exactly one OK: a queued event that outlives
	// StoreReplyTimeout is answered "relay busy" rather than left hanging,
	// and the store's eventual outcome is then dropped.
	var replyOnce sync.Once
	ok := func(accepted bool, msg string) {
		replyOnce.Do(func() {
			s.reply(&wire.OkSubscriptionResponse{EventID: ep.Event.ID, Accepted: accepted, Message: msg})
		})
	}
	stopTimer := func() bool { return false }
	if d := s.config.StoreReplyTimeout; d > 0 {
		stopTimer = time.AfterFunc(d, func() { ok(false, "error: relay busy, try again later") }).Stop
	}

	go func() {
		defer stopTimer()
		select {

		case <-task.done:

			ok(true, "")

			// Belt-and-suspenders resync: an operator who manually
			// publishes a raw kind:13534 event directly (bypassing
			// MembershipService.Join/Leave) still gets the authoritative
			// store and in-memory cache brought in line with it. This
			// extends the *existing* single consumer of task.done/.errors
			// rather than adding a second reader -- task.errors is a
			// buffered channel of capacity 1 with exactly one send, so a
			// second concurrent reader would race this goroutine for that
			// one value and whichever loses would block forever.
			if ep.Event.Kind == nip43.KindMembershipList && s.membership != nil {
				if err := s.membership.ReplaceFromEvent(ep.Event); err != nil {
					s.config.Logger.Error().Err(err).Msg("failed to resync NIP-43 membership from published kind:13534 event")
				}
			}

		case err := <-task.errors:

			switch {

			case errors.Is(err, ErrEventDuplicated):
				ok(true, fmt.Sprintf("duplicate: %s", err.Error()))

			case errors.Is(err, ErrRateLimited):
				ok(false, err.Error())

			case errors.Is(err, ErrStoreClosed), errors.Is(err, ErrSessionClosed), errors.Is(err, context.Canceled):
				ok(false, "error: relay unavailable")

			default:

				// Log the full error server-side, but don't forward it to the client:
				// unrecognized errors here come from the storage layer, not from
				// anything the client did wrong, and may contain internal details
				// (bucket/key layout, etc.) that shouldn't leak over the wire.
				s.config.Logger.Error().Err(err).Int("kind", ep.Event.Kind).Msgf("event rejected ID=%s", ep.Event.ID)
				ok(false, "error: could not store event")
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
				s.config.Logger.Warn().Err(err).Msg("failed to queue profile for indexing")
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
