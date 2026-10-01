package transport

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip44"
)

// auditD_privacy: can RECORDED traffic be decrypted later?
//
// The observer model here is the one that makes retention matter: O-net keeps every
// kind-23190 and kind-23191 it ever saw — the relay does not store them (both kinds
// are ephemeral), but nothing stops an observer from doing so — and later comes into
// possession of a key. Two keys are candidates:
//
//   - the BILL's connection secret, which a token archive retains after the bill is
//     destroyed, and which any former holder has;
//   - the HUB's inbox key, m/3'/0' off the hub's seed, pinned at rotation index 0.
//
// recorded is exactly what a passive observer keeps: no private keys, nothing the
// relay did not publish.
type auditDRecorded struct {
	requestAuthor  string // the ephemeral pubkey, straight off the event
	requestContent string // base64 NIP-44 ciphertext
	requestPTag    string // the hub inbox key
	replyContent   string
	replyPTag      string // the reply_to the hub echoed
}

func auditDBillPlaintext(t *testing.T) ([]byte, string, string) {
	t.Helper()
	nonce := auditDNonce(t)
	_, target := testKeypair(t)
	_, counterparty := testKeypair(t)

	params := `{"target_pubkey":"` + counterparty + `","amount_millis":4200000}`
	item := newTestItem(t, "x1", "cash_transfer", params, nonce)
	item.Target = target

	env := Envelope{
		Version:  EnvelopeVersion,
		NotAfter: time.Now().Add(60 * time.Second).Unix(),
		Nonce:    nonce,
		ReplyTo:  auditDNonce(t),
		Items:    []Item{item},
	}
	pt, err := env.Encode(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return pt, env.ReplyTo, target
}

// auditDRecordTraffic plays one request/response exchange and returns ONLY what an
// observer could have written down.
func auditDRecordTraffic(t *testing.T, inboxPriv, inboxXOnly string) (auditDRecorded, string) {
	t.Helper()

	plaintext, replyTo, target := auditDBillPlaintext(t)
	ev, convKey, err := WrapRequest(plaintext, inboxXOnly)
	if err != nil {
		t.Fatal(err)
	}

	// The hub's side of the exchange, so the recording contains a real reply.
	hubConvKey, err := ConversationKeyFor(ev.PubKey, inboxPriv)
	if err != nil {
		t.Fatal(err)
	}
	if hubConvKey != convKey {
		t.Fatalf("hub and client derived different conversation keys")
	}
	replyKey, err := DeriveReplyKey(hubConvKey, replyTo)
	if err != nil {
		t.Fatal(err)
	}
	resp := ResponseEnvelope{
		Version: EnvelopeVersion, ReqNonce: mustEnvelopeNonce(t, plaintext), Seq: 1, Total: 1,
		Results: []Result{{
			ID: "x1", ResultType: "cash_transfer",
			Result: json.RawMessage(`{"new_token":"lokicash1` + strings.Repeat("z", 120) + `","amount_millis":4200000}`),
		}},
	}
	respPT, err := resp.EncodeResponse(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := nip44.Encrypt(string(respPT), replyKey[:])
	if err != nil {
		t.Fatal(err)
	}

	return auditDRecorded{
		requestAuthor:  ev.PubKey,
		requestContent: ev.Content,
		requestPTag:    ev.Tags[0][1],
		replyContent:   sealed,
		replyPTag:      replyTo,
	}, target
}

func mustEnvelopeNonce(t *testing.T, plaintext []byte) string {
	t.Helper()
	env, err := Decode(plaintext, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return env.Nonce
}

// TestAuditDPrivacy_ArchivedTokenCannotDecryptRecordedTraffic is the CONTROL, and it
// confirms (does not re-derive) the Session A refutation: a bill's connection secret
// is not an input to the conversation key, so holding an archived token later is
// worth nothing against traffic recorded earlier.
func TestAuditDPrivacy_ArchivedTokenCannotDecryptRecordedTraffic(t *testing.T) {
	inboxPriv, inboxXOnly := testKeypair(t)
	rec, _ := auditDRecordTraffic(t, inboxPriv, inboxXOnly)

	// The archived token's connection secret. In the real archive this is the value
	// retained after the bill is destroyed.
	connSecret, _ := testKeypair(t)

	// Every ECDH a token holder can reach, against both ends of the exchange.
	for _, attempt := range []struct {
		name          string
		priv, peerPub string
	}{
		{"ECDH(connSecret, hubInbox)", connSecret, inboxXOnly},
		{"ECDH(connSecret, ephemeralAuthor)", connSecret, rec.requestAuthor},
	} {
		key := auditDECDH(t, attempt.priv, attempt.peerPub)
		if _, err := nip44.Decrypt(rec.requestContent, key[:]); err == nil {
			t.Fatalf("%s DECRYPTED the recorded request; forward secrecy against a token holder is broken", attempt.name)
		}
		// And the reply, for both the raw key and the reply-key derivation.
		if _, err := nip44.Decrypt(rec.replyContent, key[:]); err == nil {
			t.Fatalf("%s DECRYPTED the recorded reply", attempt.name)
		}
		derived, err := DeriveReplyKey(key, rec.replyPTag)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nip44.Decrypt(rec.replyContent, derived[:]); err == nil {
			t.Fatalf("DeriveReplyKey(%s, reply_to) DECRYPTED the recorded reply", attempt.name)
		}
		t.Logf("%s: request and reply both remain opaque", attempt.name)
	}

	// The positive half: nothing about the bill varies the ciphertext, so two
	// requests for the SAME bill are not even linkable to each other.
	one, _ := auditDRecordTraffic(t, inboxPriv, inboxXOnly)
	two, _ := auditDRecordTraffic(t, inboxPriv, inboxXOnly)
	if one.requestAuthor == two.requestAuthor {
		t.Errorf("two envelopes shared an author key; the ephemeral is not per-envelope")
	}
	if one.replyPTag == two.replyPTag {
		t.Errorf("two envelopes shared a reply_to; it is not single-use")
	}
	t.Logf("two recorded requests: authors %s… / %s…, reply_to %s… / %s… — no shared value",
		one.requestAuthor[:12], two.requestAuthor[:12], one.replyPTag[:12], two.replyPTag[:12])
}

// TestAuditDPrivacy_HubInboxKeyDecryptsAllRecordedTraffic is the finding the control
// above isolates: forward secrecy holds against a token holder and does NOT hold
// against the hub's inbox key, which is long-term, seed-derived and never rotated.
//
// The observer needs nothing but the two strings it already wrote down.
func TestAuditDPrivacy_HubInboxKeyDecryptsAllRecordedTraffic(t *testing.T) {
	inboxPriv, inboxXOnly := testKeypair(t)
	rec, target := auditDRecordTraffic(t, inboxPriv, inboxXOnly)

	// --- time passes; the observer later obtains the hub's inbox key ---

	convKey, err := ConversationKeyFor(rec.requestAuthor, inboxPriv)
	if err != nil {
		t.Fatalf("conversation key from the recorded author alone: %v", err)
	}
	plaintext, err := nip44.Decrypt(rec.requestContent, convKey[:])
	if err != nil {
		t.Fatalf("recorded request did NOT decrypt: %v", err)
	}
	env, err := Decode([]byte(plaintext), DefaultLimits())
	if err != nil {
		t.Fatalf("decode recovered plaintext: %v", err)
	}

	if len(env.Items) != 1 {
		t.Fatalf("recovered %d items, want 1", len(env.Items))
	}
	got := env.Items[0]
	if got.Target != target {
		t.Fatalf("recovered target %q, want %q", got.Target, target)
	}
	t.Logf("RECOVERED from the request, with no key but the hub's inbox key:")
	t.Logf("  bill wallet pubkey (target) = %s", got.Target)
	t.Logf("  method                      = %s", got.Method)
	t.Logf("  params                      = %s", string(got.Params))
	t.Logf("  envelope nonce / reply_to   = %s… / %s…", env.Nonce[:12], env.ReplyTo[:12])

	// The reply too, because the reply key is a KDF over the same conversation key
	// and a reply_to the recovered plaintext just handed over.
	replyKey, err := DeriveReplyKey(convKey, env.ReplyTo)
	if err != nil {
		t.Fatal(err)
	}
	replyPT, err := nip44.Decrypt(rec.replyContent, replyKey[:])
	if err != nil {
		t.Fatalf("recorded reply did NOT decrypt: %v", err)
	}
	resp, err := DecodeResponse([]byte(replyPT), env.Nonce, []string{got.ID}, DefaultLimits())
	if err != nil {
		t.Fatalf("decode recovered reply: %v", err)
	}
	t.Logf("RECOVERED from the reply: %d result(s), first = %s %s",
		len(resp.Results), resp.Results[0].ResultType, string(resp.Results[0].Result))

	if len(resp.Results) == 0 {
		t.Fatal("reply decrypted but carried no results")
	}
	t.Log("CONSEQUENCE: the transport has no forward secrecy against the hub's inbox key. " +
		"That key is derived at m/3'/0' from the hub's seed and privateTransportKeyIndex " +
		"is a const 0, so it never changes for the life of the hub: one seed disclosure " +
		"retroactively decrypts every request and reply any observer ever recorded.")
}

func auditDECDH(t *testing.T, privHex, peerXOnly string) [32]byte {
	t.Helper()
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(peerXOnly)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], key)
	return out
}
