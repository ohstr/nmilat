package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// AUDIT-C QA: the chain bill -> minter -> announcement -> inbox has NO test.
//
// ParseAnnouncement's own doc calls itself "the link that refuses to be skipped",
// and billSession (client.go:79) is the only place that walks it: it recovers the
// minting node from the bill's mint signature and passes THAT to NewBatchSession
// as the identity the announcement is verified against.
//
// No test reached it. Every test in this package builds `&Client{}` with a nil
// token and calls c.NewBatchSession(ctx, hub.hubXOnly, ...) directly, injecting
// the very value production has to derive. So the fixture supplies the answer.
//
// Mutation this catches, and which nothing else did:
//
//	client.go:88-92
//	  minter, ok := nipcash.VerifyProvenance(*c.token)
//	  if !ok { return nil, ... }
//	->
//	  minter := c.token.WalletPubkey   // no provenance check at all
//
// Applied to nmilat @1140377, `GOWORK=off go test -count=1 ./nipcash/...` produced
// a failing-test set identical to the baseline. Provenance verification could be
// deleted outright and the suite stayed green.

// auditCQASignProvenance mirrors nipcash's own unexported signProvenance test
// helper (nipcash/provenance_test.go), which this package cannot reach.
// doubleSHA256 is unexported there too, so the two-line convention is repeated.
func auditCQASignProvenance(t *testing.T, privHex, hrp, walletPubkeyHex string, amountMillis uint64) []byte {
	t.Helper()
	raw, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("decode signing key: %v", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(raw)
	payload := nipcash.MintPayload(hrp, walletPubkeyHex, amountMillis)
	first := sha256.Sum256([]byte(nipcash.LNSignedMessagePrefix + payload))
	digest := sha256.Sum256(first[:])
	return ecdsa.SignCompact(priv, digest[:], true)
}

// auditCQABillToken builds the bill a real holder would receive: a wallet pubkey,
// its connection secret, relay hints, and a mint signature from the hub's node key
// — which is the ONLY thing in the token that names the hub.
func auditCQABillToken(t *testing.T, hubPriv, walletPubkey, connSecret, relay string) nipcash.Token {
	t.Helper()
	amount := uint64(40000)
	return nipcash.Token{
		HRP:                  "lokicash",
		WalletPubkey:         walletPubkey,
		Secret:               connSecret,
		RelayURLs:            []string{relay},
		MintSignature:        auditCQASignProvenance(t, hubPriv, "lokicash", walletPubkey, amount),
		AttestedAmountMillis: &amount,
	}
}

// TestAuditCQA_BillSessionWalksTheProvenanceChain is the mutation killer: the hub
// identity must come from the bill's mint signature and from nowhere else.
func TestAuditCQA_BillSessionWalksTheProvenanceChain(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	relay := startFakeHub(t, hub)

	connSecret, walletPubkey := sessionKeypair(t)
	token := auditCQABillToken(t, hub.hubPriv, walletPubkey, connSecret, relay)

	// Premise check, so a failure below is never mistaken for a broken fixture:
	// provenance must recover a key that normalizes to the hub's Nostr identity.
	// Recovery yields a 33-byte COMPRESSED pubkey; an event author is 32-byte
	// x-only. That shape mismatch is what NormalizeNodeIdentity exists for, and it
	// is on the production path here rather than assumed away.
	recovered, ok := nipcash.VerifyProvenance(token)
	if !ok {
		t.Fatal("fixture: the mint signature this test built does not recover")
	}
	normalized, err := transport.NormalizeNodeIdentity(recovered)
	if err != nil {
		t.Fatalf("fixture: recovered minter %q does not normalize: %v", recovered, err)
	}
	if normalized != hub.hubXOnly {
		t.Fatalf("fixture: recovered minter normalizes to %s, hub identity is %s", normalized, hub.hubXOnly)
	}
	if len(recovered) != 66 {
		t.Errorf("recovered minter is %d hex chars, want the 66 of a compressed pubkey; "+
			"if this becomes 64 the normalization step is no longer being exercised", len(recovered))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := &Client{walletPubkey: walletPubkey, connSecret: connSecret, token: &token}
	s, err := c.billSession(ctx)
	if err != nil {
		t.Fatalf("billSession() error = %v; the bill's own mint signature must be enough "+
			"to reach its hub's private transport", err)
	}
	if s.HubIdentity() != hub.hubXOnly {
		t.Errorf("HubIdentity() = %s, want %s — the identity proofs bind to must be the "+
			"one recovered from the mint signature", s.HubIdentity(), hub.hubXOnly)
	}
	if s.Inbox() != hub.inboxXOnly {
		t.Errorf("Inbox() = %s, want the ANNOUNCED inbox %s, never the identity key",
			s.Inbox(), hub.inboxXOnly)
	}
	t.Logf("AUDITC-QA: bill -> minter %s -> x-only %s -> announcement -> inbox %s",
		recovered[:16]+"...", s.HubIdentity()[:16]+"...", s.Inbox()[:16]+"...")

	// And the session is cached, so a second bill method does not re-fetch.
	again, err := c.billSession(ctx)
	if err != nil || again != s {
		t.Errorf("billSession() did not reuse the open session (err=%v, same=%v)", err, again == s)
	}
}

// TestAuditCQA_ForeignProvenanceDoesNotReachTheHonestHub: a bill whose mint
// signature was produced by someone other than the hub must NOT resolve to that
// hub, even though the token's relay hints point straight at it.
//
// This is the assertion behind ParseAnnouncement's claim. The relay is honest and
// serving the honest hub's announcement; the only thing that must stop the client
// adopting it is that the recovered minter is a different key.
func TestAuditCQA_ForeignProvenanceDoesNotReachTheHonestHub(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	relay := startFakeHub(t, hub)

	connSecret, walletPubkey := sessionKeypair(t)
	foreignPriv, _ := sessionKeypair(t)
	token := auditCQABillToken(t, foreignPriv, walletPubkey, connSecret, relay)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := &Client{walletPubkey: walletPubkey, connSecret: connSecret, token: &token}
	s, err := c.billSession(ctx)
	if err == nil {
		t.Fatalf("billSession() succeeded on a bill signed by a foreign key: identity=%s inbox=%s",
			s.HubIdentity(), s.Inbox())
	}
	t.Logf("AUDITC-QA: foreign provenance refused with %v", err)
}

// TestAuditCQA_UnverifiableProvenanceFailsClosed: garbage in the signature slot
// must be refused by name, not turned into some arbitrary recovered key that the
// client then goes looking for. VerifyProvenance is ECDSA *recovery*, so it
// succeeds on far more inputs than it rejects — the length and format checks are
// what keep this path closed.
func TestAuditCQA_UnverifiableProvenanceFailsClosed(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	relay := startFakeHub(t, hub)

	connSecret, walletPubkey := sessionKeypair(t)
	token := auditCQABillToken(t, hub.hubPriv, walletPubkey, connSecret, relay)
	token.MintSignature = token.MintSignature[:len(token.MintSignature)-1] // wrong length

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := &Client{walletPubkey: walletPubkey, connSecret: connSecret, token: &token}
	if _, err := c.billSession(ctx); err == nil {
		t.Fatal("billSession() succeeded on a bill with a malformed mint signature")
	} else if !strings.Contains(err.Error(), "mint signature") {
		t.Errorf("billSession() error = %v; a caller must be told the mint signature is "+
			"the problem, not be handed a relay error", err)
	}
}

// TestAuditCQA_PairingURIClientFailsClosedWithoutTouchingTheNetwork pins the
// documented half-capable client: Connect accepts a pairing URI as well as a cash
// token, and a URI-built client can mint but cannot act on a bill. That failure is
// the right direction, and until now nothing asserted it.
//
// Also pins that it costs no relay round trip — the nil-token guard runs before
// anything is fetched, so the message is immediate and not a timeout.
func TestAuditCQA_PairingURIClientFailsClosedWithoutTouchingTheNetwork(t *testing.T) {
	connSecret, walletPubkey := sessionKeypair(t)
	c := &Client{walletPubkey: walletPubkey, connSecret: connSecret} // token nil: a pairing URI

	// No relay is running and none is configured; a cancelled context proves the
	// guard fires before any I/O rather than after it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.billSession(ctx)
	if err == nil {
		t.Fatal("billSession() succeeded with no token; bill methods have no hub identity to verify against")
	}
	if !strings.Contains(err.Error(), "cash token") {
		t.Errorf("billSession() error = %v; it must name the missing cash token, since that "+
			"is the only thing the caller can act on", err)
	}
	if strings.Contains(err.Error(), "context canceled") {
		t.Error("billSession() reached the network before checking for a token")
	}
}
