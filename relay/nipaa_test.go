package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/nipOA"
	"github.com/ohstr/nmilat/wire"
)

// Official NIP-OA test vector keys (see nipOA/nipOA_test.go) -- reused
// here so these integration tests exercise the real cryptographic path
// against known-good key material, not throwaway generated keys.
const (
	ownerPrivKey = "0000000000000000000000000000000000000000000000000000000000000001"
	ownerPubkey  = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	agentPrivKey = "0000000000000000000000000000000000000000000000000000000000000002"
	agentPubkey  = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)

// signAuthTag builds a valid NIP-OA "auth" tag signed by ownerPrivHex,
// authorizing eventPubkey under conditions.
func signAuthTag(t *testing.T, ownerPrivHex, eventPubkey, conditions string) []string {
	t.Helper()
	privBytes, err := hex.DecodeString(ownerPrivHex)
	if err != nil {
		t.Fatalf("decode owner priv key: %v", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)
	digest := sha256.Sum256(nipOA.Preimage(eventPubkey, conditions))
	sig, err := schnorr.Sign(privKey, digest[:])
	if err != nil {
		t.Fatalf("sign auth tag: %v", err)
	}
	ownerPub, err := nip11.DerivePubKey(ownerPrivHex)
	if err != nil {
		t.Fatalf("derive owner pubkey: %v", err)
	}
	return []string{"auth", ownerPub, conditions, hex.EncodeToString(sig.Serialize())}
}

// newAgentAuthTestSession builds a Session with NIP-AA enabled, a real
// store-backed MembershipService, and ownerPubkey already enrolled as an
// active member -- the precondition every "virtual membership granted"
// test needs.
func newAgentAuthTestSession(t *testing.T, relayURL, challenge string, kindEnforcement bool) *Session {
	t.Helper()
	store := newStore(t)
	cfg := defaultSessionConfig()
	cfg.AgentAuthEnabled = true
	cfg.AgentKindEnforcement = kindEnforcement
	sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{
		URL:        relayURL,
		Limitation: nip11.Limitation{AuthRequired: true},
	}, nil, nil, cfg)
	sc.membership = NewMembershipService(store)
	if err := sc.membership.Join(ownerPubkey, nil); err != nil {
		t.Fatalf("enroll owner as member: %v", err)
	}
	return &Session{SessionContext: sc, challenge: challenge}
}

// agentAuthEvent builds a kind:22242 AUTH event for agentPubkey, signed by
// agentPrivKey, carrying authTag (if non-nil) alongside the usual
// relay/challenge tags.
func agentAuthEvent(t *testing.T, relayURL, challenge string, authTag []string) *nip01.Event {
	t.Helper()
	ev := nip42.NewAuthEvent(challenge, relayURL)
	if authTag != nil {
		ev.AddTag(authTag)
	}
	if err := ev.Sign(agentPrivKey); err != nil {
		t.Fatalf("sign agent auth event: %v", err)
	}
	return ev
}

func processAuthAndAwaitOK(t *testing.T, sess *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	t.Helper()
	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: ev}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}
	reply := <-sess.incoming
	ok, isOk := reply.(*wire.OkSubscriptionResponse)
	if !isOk {
		t.Fatalf("reply type = %T, want *wire.OkSubscriptionResponse", reply)
	}
	return ok
}

func TestProcessAuth_DirectMember_FastPath(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-fast", false)

	// ownerPubkey is already enrolled -- AUTH as the owner directly,
	// carrying no auth tag at all. Must succeed via Step 2's fast path.
	ev := nip42.NewAuthEvent("chal-fast", "wss://relay.example")
	if err := ev.Sign(ownerPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := processAuthAndAwaitOK(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a direct member (message: %s)", resp.Message)
	}

	id, ok := sess.IdentityMembership(ownerPubkey)
	if !ok || id.Membership != MembershipActive {
		t.Fatalf("IdentityMembership(owner) = %+v, %v; want MembershipActive", id, ok)
	}
}

func TestProcessAuth_VirtualMembership_Granted(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-1", false)

	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, "")
	ev := agentAuthEvent(t, "wss://relay.example", "chal-1", authTag)

	resp := processAuthAndAwaitOK(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a valid NIP-OA credential from an active-member owner (message: %s)", resp.Message)
	}

	id, ok := sess.IdentityMembership(agentPubkey)
	if !ok {
		t.Fatal("IdentityMembership(agent) not found after a granted AUTH")
	}
	if id.Membership != MembershipVirtual {
		t.Fatalf("Membership = %v, want MembershipVirtual", id.Membership)
	}
	if id.Owner != ownerPubkey {
		t.Fatalf("Owner = %q, want %q", id.Owner, ownerPubkey)
	}
	if id.Conditions == nil {
		t.Fatal("Conditions = nil, want the retained parsed credential")
	}

	// HasMembership()/HasOwnerIdentity() must reflect the grant too.
	if !sess.HasMembership() {
		t.Fatal("HasMembership() = false after a virtual membership grant")
	}
	if !sess.HasOwnerIdentity(ownerPubkey) {
		t.Fatal("HasOwnerIdentity(owner) = false after a virtual membership grant")
	}
}

func TestProcessAuth_RejectsInvalidSignature(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-2", false)

	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, "")
	// Corrupt the signature only.
	authTag[3] = "00" + authTag[3][2:]
	ev := agentAuthEvent(t, "wss://relay.example", "chal-2", authTag)

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for a forged signature")
	}
	if _, ok := sess.IdentityMembership(agentPubkey); ok {
		t.Fatal("IdentityMembership(agent) found after a rejected AUTH, want none")
	}
}

func TestProcessAuth_RejectsSelfAttestation(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-3", false)

	// owner == event's own pubkey.
	authTag := signAuthTag(t, agentPrivKey, agentPubkey, "")
	ev := agentAuthEvent(t, "wss://relay.example", "chal-3", authTag)

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for self-attestation")
	}
}

func TestProcessAuth_RejectsWrongElementCount(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-4", false)

	authTag := []string{"auth", ownerPubkey, ""} // missing sig element
	ev := agentAuthEvent(t, "wss://relay.example", "chal-4", authTag)

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for a malformed (wrong element count) auth tag")
	}
}

func TestProcessAuth_RejectsMalformedConditions(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-5", false)

	// The signature is computed over the *bad* conditions string itself,
	// so it verifies fine cryptographically -- the rejection must come
	// from conditions-grammar parsing (leading zero), not signature
	// failure.
	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, "kind=01")
	ev := agentAuthEvent(t, "wss://relay.example", "chal-5", authTag)

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for malformed conditions (leading zero)")
	}
}

func TestProcessAuth_RejectsStaleAuthEventFreshnessWindow(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-6", false)

	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, "")
	ev := nip42.NewAuthEvent("chal-6", "wss://relay.example")
	ev.AddTag(authTag)
	// Push created_at far outside NIP-AA's ±120s window (but still within
	// NIP-42's own wider ±600s window, so Step 1's *original* check
	// passes -- this must fail on the NIP-AA-specific addendum).
	ev.CreatedAt = uint64(time.Now().Add(-5 * time.Minute).Unix())
	if err := ev.Sign(agentPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for an AUTH event outside NIP-AA's freshness window")
	}
}

func TestProcessAuth_RejectsStaleCredentialCreatedAtCondition(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-7", false)

	// The credential itself is scoped to expire in the past relative to
	// "now" -- the AUTH event's own (fresh, current) created_at fails the
	// credential's created_at< condition at Step 4, distinct from Step 1's
	// freshness check.
	pastDeadline := time.Now().Add(-1 * time.Hour).Unix()
	conditions := "created_at<" + timeUnixString(pastDeadline)
	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, conditions)
	ev := agentAuthEvent(t, "wss://relay.example", "chal-7", authTag)

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for a credential whose created_at< condition the AUTH event fails")
	}
}

func TestProcessAuth_RejectsOwnerNotMember(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-8", false)
	// Deliberately don't enroll the owner -- this session's constructor
	// always enrolls ownerPubkey, so remove it to test the negative case.
	if err := sess.membership.Leave(ownerPubkey); err != nil {
		t.Fatalf("Leave: %v", err)
	}

	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, "")
	ev := agentAuthEvent(t, "wss://relay.example", "chal-8", authTag)

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false when the credential's owner is not an active member")
	}
}

func TestProcessAuth_RejectsTwoAuthTags(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-9", false)

	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, "")
	ev := nip42.NewAuthEvent("chal-9", "wss://relay.example")
	ev.AddTag(authTag)
	ev.AddTag(authTag)
	if err := ev.Sign(agentPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for an AUTH event with two auth tags")
	}
}

func TestProcessAuth_RejectsNoAuthTagNonMember(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-10", false)

	// agentPubkey is not a member and carries no credential at all.
	ev := agentAuthEvent(t, "wss://relay.example", "chal-10", nil)

	resp := processAuthAndAwaitOK(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for a non-member with no credential when NIP-AA is enabled")
	}
}

func TestProcessAuth_PlainNIP43_NonMemberWithoutCredentialStillAuths(t *testing.T) {
	// AgentAuthEnabled is off entirely here -- this is the pre-NIP-AA
	// behavior this design is explicit about preserving: AUTH proves
	// identity, it doesn't itself grant access.
	store := newStore(t)
	sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{
		URL:        "wss://relay.example",
		Limitation: nip11.Limitation{AuthRequired: true},
	}, nil, nil, nil)
	sc.membership = NewMembershipService(store)
	sess := &Session{SessionContext: sc, challenge: "chal-11"}

	ev := agentAuthEvent(t, "wss://relay.example", "chal-11", nil)
	resp := processAuthAndAwaitOK(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true -- plain NIP-43 (no NIP-AA) always AUTHs regardless of membership (message: %s)", resp.Message)
	}
	id, ok := sess.IdentityMembership(agentPubkey)
	if !ok || id.Membership != MembershipNone {
		t.Fatalf("IdentityMembership(agent) = %+v, %v; want MembershipNone", id, ok)
	}
}

func TestProcessAuth_ReplacesCredentialOnReauth(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-12", false)

	// First AUTH: agent presents a valid credential from ownerPubkey.
	authTag1 := signAuthTag(t, ownerPrivKey, agentPubkey, "")
	ev1 := agentAuthEvent(t, "wss://relay.example", "chal-12", authTag1)
	if resp := processAuthAndAwaitOK(t, sess, ev1); !resp.Accepted {
		t.Fatalf("first AUTH rejected: %s", resp.Message)
	}
	id, _ := sess.IdentityMembership(agentPubkey)
	if id.Owner != ownerPubkey {
		t.Fatalf("after first AUTH, Owner = %q, want %q", id.Owner, ownerPubkey)
	}

	// Second AUTH on the SAME connection, same agent pubkey, a
	// *different* credential (narrower conditions) -- must replace, not
	// combine.
	sess.challenge = "chal-12b"
	authTag2 := signAuthTag(t, ownerPrivKey, agentPubkey, "kind=1")
	ev2 := agentAuthEvent(t, "wss://relay.example", "chal-12b", authTag2)
	if resp := processAuthAndAwaitOK(t, sess, ev2); !resp.Accepted {
		t.Fatalf("second AUTH rejected: %s", resp.Message)
	}

	id, ok := sess.IdentityMembership(agentPubkey)
	if !ok {
		t.Fatal("IdentityMembership(agent) missing after re-AUTH")
	}
	if id.Conditions == nil || len(id.Conditions.Kinds) != 1 || id.Conditions.Kinds[0] != 1 {
		t.Fatalf("Conditions = %+v, want the second credential's kind=1 condition, not a combination", id.Conditions)
	}
	// Still exactly one identity for this pubkey -- not appended twice.
	all := sess.Identities()
	count := 0
	for _, i := range all {
		if i.Pubkey == agentPubkey {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Identities() has %d entries for agentPubkey, want exactly 1 (replaced, not combined)", count)
	}
}

func TestVirtualMember_CannotModifyRelayMembership(t *testing.T) {
	// A virtual member has relay-level read/write access, but per spec
	// MUST NOT be able to modify relay membership (publish
	// role/list/add/remove-user events) -- CheckSelfAuthored already
	// blocks this for any non-self pubkey, virtual member or not.
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-13", false)
	sess.selfPubkey = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" // some other relay identity

	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, "")
	ev := agentAuthEvent(t, "wss://relay.example", "chal-13", authTag)
	if resp := processAuthAndAwaitOK(t, sess, ev); !resp.Accepted {
		t.Fatalf("AUTH rejected: %s", resp.Message)
	}

	membershipListEv := nip43.NewMembershipList(nip43.MembershipListParams{SelfPubkey: agentPubkey})
	if err := membershipListEv.Sign(agentPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, membershipListEv)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false -- a virtual member must not be able to publish a relay-authored membership-list event")
	}
}

func timeUnixString(u int64) string {
	if u < 0 {
		u = 0
	}
	return strconv.FormatInt(u, 10)
}
