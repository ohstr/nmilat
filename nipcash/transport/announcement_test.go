package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
)

// signAsNode stands in for the Lightning node: it signs the event's own ID with a
// BIP340 signature, which is exactly what signrpc.SignMessage{schnorr_sig} returns.
func signAsNode(t *testing.T, ev *nip01.Event, nodePrivHex string) {
	t.Helper()
	digest, err := AnnouncementDigest(ev)
	if err != nil {
		t.Fatalf("AnnouncementDigest: %v", err)
	}
	privBytes, err := hex.DecodeString(nodePrivHex)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	sig, err := schnorr.Sign(priv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ev.Sig = hex.EncodeToString(sig.Serialize())
}

func TestAnnouncement_RoundTrip(t *testing.T) {
	nodePriv, nodeXOnly := testKeypair(t)
	_, inbox := testKeypair(t)
	limits := DefaultLimits()

	ev, err := NewAnnouncement(nodeXOnly, inbox, limits, []string{"wss://relay.hub.example"})
	if err != nil {
		t.Fatalf("NewAnnouncement: %v", err)
	}
	if ev.Kind != KindHubAnnouncement {
		t.Errorf("kind = %d, want %d", ev.Kind, KindHubAnnouncement)
	}
	// Unsigned until the node signs it — nothing in-process can produce this.
	if ev.Sig != "" {
		t.Error("NewAnnouncement returned a signed event; the node must sign it")
	}

	signAsNode(t, ev, nodePriv)

	got, err := ParseAnnouncement(ev, nodeXOnly)
	if err != nil {
		t.Fatalf("ParseAnnouncement: %v", err)
	}
	if got.Inbox != inbox {
		t.Errorf("inbox = %q, want %q", got.Inbox, inbox)
	}
	if got.Limits.Limits() != limits {
		t.Errorf("limits = %+v, want %+v", got.Limits.Limits(), limits)
	}
	if len(got.Relays) != 1 || got.Relays[0] != "wss://relay.hub.example" {
		t.Errorf("relays = %v", got.Relays)
	}
}

// TestAnnouncement_NodeAndLocalSigningAgree pins the distinction that fails
// silently when you get it wrong.
//
// A signer you hand a key to signs the event ID. A signer that hashes its own
// input — flnd's signrpc computes sha256(msg) then signs — must be handed the
// SERIALIZATION instead. Pass it the ID and it signs sha256(id): a perfectly valid
// signature over the wrong digest, which fails verification with nothing pointing
// at why.
//
// Both routes must yield a signature that verifies as the same event.
func TestAnnouncement_NodeAndLocalSigningAgree(t *testing.T) {
	nodePrivHex, nodeXOnly := testKeypair(t)
	_, inbox := testKeypair(t)

	privBytes, err := hex.DecodeString(nodePrivHex)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)

	ev, err := NewAnnouncement(nodeXOnly, inbox, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// What a local signer signs.
	digest, err := AnnouncementDigest(ev)
	if err != nil {
		t.Fatal(err)
	}
	// What the node is handed; it hashes this itself.
	payload, err := AnnouncementSigningPayload(ev)
	if err != nil {
		t.Fatal(err)
	}
	nodeComputed := sha256.Sum256(payload)

	if !bytes.Equal(digest, nodeComputed[:]) {
		t.Fatalf("the node would sign a different digest than a local signer:\n  local %x\n  node  %x",
			digest, nodeComputed)
	}

	// And a signature produced the node's way verifies as this event.
	sig, err := schnorr.Sign(priv, nodeComputed[:])
	if err != nil {
		t.Fatal(err)
	}
	ev.Sig = hex.EncodeToString(sig.Serialize())
	if _, err := ParseAnnouncement(ev, nodeXOnly); err != nil {
		t.Fatalf("a node-produced signature must verify: %v", err)
	}
}

// TestAnnouncement_RejectsImpersonation is the security property, and the reason
// expectedNodeXOnly is a required argument rather than an option.
//
// Alice recovers her hub's node identity from her bill's mint signature. An attacker
// publishes a perfectly valid announcement of their own, naming an inbox key they
// hold, hoping Alice encrypts to it. Nothing about that event is malformed — it is
// correctly signed, by the wrong key. Only the author check catches it, and if it
// did not, the attacker would read every envelope Alice sent.
func TestAnnouncement_RejectsImpersonation(t *testing.T) {
	_, realNodeXOnly := testKeypair(t)
	attackerPriv, attackerXOnly := testKeypair(t)
	_, attackerInbox := testKeypair(t)

	ev, err := NewAnnouncement(attackerXOnly, attackerInbox, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signAsNode(t, ev, attackerPriv)

	// Valid on its own terms: it parses fine against its real author.
	if _, err := ParseAnnouncement(ev, attackerXOnly); err != nil {
		t.Fatalf("the attacker's own announcement should be internally valid: %v", err)
	}
	// But Alice checks against HER hub, and that is what refuses it.
	if _, err := ParseAnnouncement(ev, realNodeXOnly); !errors.Is(err, ErrAnnouncementAuthor) {
		t.Fatalf("ParseAnnouncement() = %v, want ErrAnnouncementAuthor", err)
	}
}

// TestAnnouncement_RejectsForgedSignature covers the other half: claiming the right
// author without holding its key.
func TestAnnouncement_RejectsForgedSignature(t *testing.T) {
	_, nodeXOnly := testKeypair(t)
	attackerPriv, _ := testKeypair(t)
	_, inbox := testKeypair(t)

	// Author field says the real hub; signature is the attacker's.
	ev, err := NewAnnouncement(nodeXOnly, inbox, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signAsNode(t, ev, attackerPriv)

	if _, err := ParseAnnouncement(ev, nodeXOnly); !errors.Is(err, ErrAnnouncementSignature) {
		t.Fatalf("ParseAnnouncement() = %v, want ErrAnnouncementSignature", err)
	}
}

// retag rewrites one tag of an announcement and re-signs it as the node.
func retag(t *testing.T, ev *nip01.Event, nodePriv string, edit func([][]string) [][]string) {
	t.Helper()
	ev.Tags = edit(ev.Tags)
	ev.Sig = ""
	id, err := ev.HashID()
	if err != nil {
		t.Fatal(err)
	}
	ev.ID = hex.EncodeToString(id)
	signAsNode(t, ev, nodePriv)
}

// TestAnnouncement_RejectsTamperedContent pins that the signature covers the inbox
// key. Swapping it after signing must invalidate the event, or an intermediary could
// redirect Alice's traffic without holding any key.
func TestAnnouncement_RejectsTamperedContent(t *testing.T) {
	nodePriv, nodeXOnly := testKeypair(t)
	_, realInbox := testKeypair(t)
	_, attackerInbox := testKeypair(t)

	ev, err := NewAnnouncement(nodeXOnly, realInbox, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signAsNode(t, ev, nodePriv)
	ev.Tags[0][1] = attackerInbox

	if _, err := ParseAnnouncement(ev, nodeXOnly); !errors.Is(err, ErrAnnouncementSignature) {
		t.Fatalf("ParseAnnouncement() = %v, want ErrAnnouncementSignature", err)
	}
}

// TestAnnouncement_NodeKeyAsInbox: a Hub never announces its node key as its inbox
// (the node will not perform the ECDH), but a reader uses whatever inbox the
// announcement names (NIP-CASH §The Hub Announcement), so it accepts one.
func TestAnnouncement_NodeKeyAsInbox(t *testing.T) {
	nodePriv, nodeXOnly := testKeypair(t)
	if _, err := NewAnnouncement(nodeXOnly, nodeXOnly, DefaultLimits(), nil); !errors.Is(err, ErrAnnouncementMalformed) {
		t.Fatalf("NewAnnouncement() = %v, want ErrAnnouncementMalformed", err)
	}
	_, other := testKeypair(t)
	ev, err := NewAnnouncement(nodeXOnly, other, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	retag(t, ev, nodePriv, func(tags [][]string) [][]string { tags[0][1] = nodeXOnly; return tags })
	a, err := ParseAnnouncement(ev, nodeXOnly)
	if err != nil || a.Inbox != nodeXOnly {
		t.Fatalf("ParseAnnouncement() = %v", err)
	}
}

// TestAnnouncement_RejectsUnusableAnnouncedLimits stops a hostile or misconfigured
// hub talking a client into building an envelope that cannot be encrypted. The
// announced policy is validated, never simply adopted.
func TestAnnouncement_RejectsUnusableAnnouncedLimits(t *testing.T) {
	nodePriv, nodeXOnly := testKeypair(t)
	_, inbox := testKeypair(t)

	bad := DefaultLimits()
	bad.MaxEnvelopeBytes = MaxNIP44Plaintext + 1
	if _, err := NewAnnouncement(nodeXOnly, inbox, bad, nil); err == nil {
		t.Error("NewAnnouncement accepted a policy past the NIP-44 ceiling")
	}
	ev, err := NewAnnouncement(nodeXOnly, inbox, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	retag(t, ev, nodePriv, func(tags [][]string) [][]string {
		for _, tag := range tags {
			if tag[0] == "limit" && tag[1] == LimitMaxBytes {
				tag[2] = strconv.Itoa(MaxNIP44Plaintext + 1)
			}
		}
		return tags
	})
	// A max_bytes over 65535 is clamped for the client, never a rejection (T09-14).
	a, err := ParseAnnouncement(ev, nodeXOnly)
	if err != nil {
		t.Fatalf("ParseAnnouncement() = %v", err)
	}
	if a.EffectiveLimits().MaxEnvelopeBytes != MaxNIP44Plaintext {
		t.Errorf("effective max_bytes %d", a.EffectiveLimits().MaxEnvelopeBytes)
	}
	// A consolidate cap no max_bytes can hold is non-conforming.
	retag(t, ev, nodePriv, func(tags [][]string) [][]string {
		for _, tag := range tags {
			if tag[0] == "limit" && tag[1] == LimitMaxConsolidateSources {
				tag[2] = "200"
			}
		}
		return tags
	})
	if _, err := ParseAnnouncement(ev, nodeXOnly); !errors.Is(err, ErrHubNonConforming) {
		t.Fatalf("ParseAnnouncement() = %v, want ErrHubNonConforming", err)
	}
}

// T07-16, T09-14 (tag form): the reader's refusals and tolerances.
func TestAnnouncement_TagForm(t *testing.T) {
	nodePriv, nodeXOnly := testKeypair(t)
	_, inbox := testKeypair(t)
	build := func(edit func([][]string) [][]string) *nip01.Event {
		ev, err := NewAnnouncement(nodeXOnly, inbox, DefaultLimits(), []string{"wss://r.example"}, "[::1]:9735")
		if err != nil {
			t.Fatal(err)
		}
		retag(t, ev, nodePriv, edit)
		return ev
	}
	ev := build(func(x [][]string) [][]string { return x })
	if ev.Content != "" {
		t.Errorf("content %q", ev.Content)
	}
	a, err := ParseAnnouncement(ev, nodeXOnly)
	if err != nil || a.Inbox != inbox || len(a.Relays) != 1 || len(a.Addrs) != 1 || a.Limits.MaxRequestAge != DefaultMaxRequestAge {
		t.Fatalf("round trip: %+v %v", a, err)
	}
	if err := a.ValidateForBillCalls(); err != nil {
		t.Errorf("ValidateForBillCalls: %v", err)
	}
	for name, edit := range map[string]func([][]string) [][]string{
		"no inbox":       func(x [][]string) [][]string { return x[1:] },
		"two inboxes":    func(x [][]string) [][]string { return append(x, []string{"inbox", inbox}) },
		"bad inbox":      func(x [][]string) [][]string { x[0][1] = strings.ToUpper(inbox); return x },
		"two max_items":  func(x [][]string) [][]string { return append(x, []string{"limit", LimitMaxItems, "4"}) },
		"leading zero":   func(x [][]string) [][]string { x[2][2] = "0" + x[2][2]; return x },
		"bad r":          func(x [][]string) [][]string { return append(x, []string{"r", "https://x"}) },
		"limit no value": func(x [][]string) [][]string { return append(x, []string{"limit", "max_bytes"}) },
	} {
		if _, err := ParseAnnouncement(build(edit), nodeXOnly); !errors.Is(err, ErrAnnouncementMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	tolerated := build(func(x [][]string) [][]string {
		return append(x, []string{"addr", "not an addr"}, []string{"limit", "future_limit", "7"}, []string{"x", "y"})
	})
	if a, err := ParseAnnouncement(tolerated, nodeXOnly); err != nil || len(a.Addrs) != 1 {
		t.Errorf("tolerated tags: %+v %v", a, err)
	}
	noH := build(func(x [][]string) [][]string {
		var out [][]string
		for _, tag := range x {
			if !(tag[0] == "limit" && tag[1] == LimitMaxRequestAge) {
				out = append(out, tag)
			}
		}
		return out
	})
	a, err = ParseAnnouncement(noH, nodeXOnly)
	if err != nil {
		t.Fatalf("no max_request_age still parses: %v", err)
	}
	if err := a.ValidateForBillCalls(); !errors.Is(err, ErrHubUnusable) {
		t.Errorf("no max_request_age: %v", err)
	}
	for _, h := range []int64{0, 59} {
		l := DefaultLimits()
		l.MaxRequestAgeSeconds = h
		if _, err := NewAnnouncement(nodeXOnly, inbox, l, nil); err == nil {
			t.Errorf("announced H %d", h)
		}
		if (Announcement{Limits: AnnouncedLimits{MaxRequestAge: h}}).ValidateForBillCalls() == nil {
			t.Errorf("H %d usable", h)
		}
	}
	for _, h := range []int64{60, 300, 86401} {
		if err := (Announcement{Limits: AnnouncedLimits{MaxRequestAge: h}}).ValidateForBillCalls(); err != nil {
			t.Errorf("H %d: %v", h, err)
		}
	}
	for _, addr := range []string{"1.2.3.4:9735", "[2001:db8::1]:9735", strings.Repeat("a", 56) + ".onion:9735"} {
		if !ValidAddr(addr) {
			t.Errorf("%s refused", addr)
		}
	}
	for _, addr := range []string{"example.com:9735", "2001:db8::1:9735", "1.2.3.4", "1.2.3.4:0", "[1.2.3.4]:1"} {
		if ValidAddr(addr) {
			t.Errorf("%s accepted", addr)
		}
		if _, err := NewAnnouncement(nodeXOnly, inbox, DefaultLimits(), nil, addr); !errors.Is(err, ErrBadAddr) {
			t.Errorf("NewAnnouncement with %s: %v", addr, err)
		}
	}
}

func TestAnnouncement_RejectsMalformedInput(t *testing.T) {
	nodePriv, nodeXOnly := testKeypair(t)
	_, inbox := testKeypair(t)

	if _, err := NewAnnouncement("not-hex", inbox, DefaultLimits(), nil); !errors.Is(err, ErrAnnouncementMalformed) {
		t.Error("accepted a non-hex node pubkey")
	}
	if _, err := NewAnnouncement(nodeXOnly, "short", DefaultLimits(), nil); !errors.Is(err, ErrAnnouncementMalformed) {
		t.Error("accepted a short inbox pubkey")
	}

	ev, err := NewAnnouncement(nodeXOnly, inbox, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	signAsNode(t, ev, nodePriv)

	if _, err := ParseAnnouncement(nil, nodeXOnly); !errors.Is(err, ErrAnnouncementMalformed) {
		t.Error("accepted a nil event")
	}
	if _, err := ParseAnnouncement(ev, "not-hex"); !errors.Is(err, ErrAnnouncementMalformed) {
		t.Error("accepted a non-hex expected node pubkey")
	}

	wrongKind := *ev
	wrongKind.Kind = KindPrivateRequest
	if _, err := ParseAnnouncement(&wrongKind, nodeXOnly); !errors.Is(err, ErrAnnouncementMalformed) {
		t.Error("accepted the wrong kind")
	}
}
