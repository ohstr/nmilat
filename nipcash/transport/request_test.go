package transport

import (
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip59"
)

// hubAcceptanceRule replicates, exactly, the three cheap gates a hub applies
// before it will spend an ECDH on an inbound event
// (lokihub service/private_transport.go, acceptsPrivateEvent). Duplicated here on
// purpose: F1 was a case of each side being self-consistent while disagreeing with
// the other, and the only test that catches that is one where the sender's output
// is judged by the receiver's rule.
func hubAcceptanceRule(t *testing.T, kind int, firstPTag, content, wantInbox string) {
	t.Helper()
	if kind != KindPrivateRequest {
		t.Fatalf("hub subscribes to kind %d and ignores everything else; got kind %d",
			KindPrivateRequest, kind)
	}
	if firstPTag != wantInbox {
		t.Fatalf("hub compares the first p-tag against its inbox; got %q want %q", firstPTag, wantInbox)
	}
	const minWrapBytes = 128 // the hub's own floor
	if len(content) < minWrapBytes {
		t.Fatalf("hub drops content shorter than %d bytes; got %d", minWrapBytes, len(content))
	}
}

func firstPTag(tags [][]string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "p" {
			return tag[1]
		}
	}
	return ""
}

// TestWrapRequest_SatisfiesTheHubsOwnAcceptanceRule is F1's regression test: the
// wrapped event must pass the receiver's gates AND decrypt back to the exact
// plaintext, using the hub's half of the ECDH.
func TestWrapRequest_SatisfiesTheHubsOwnAcceptanceRule(t *testing.T) {
	inboxPriv, inboxXOnly := testKeypair(t)

	env := newTestEnvelope(t)
	plaintext, err := env.Encode(DefaultLimits())
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	ev, _, err := WrapRequest(plaintext, inboxXOnly)
	if err != nil {
		t.Fatalf("WrapRequest() error = %v", err)
	}

	hubAcceptanceRule(t, ev.Kind, firstPTag(ev.Tags), ev.Content, inboxXOnly)

	// The hub's side of the ECDH, from the event's own author key.
	conversationKey, err := ConversationKeyFor(ev.PubKey, inboxPriv)
	if err != nil {
		t.Fatalf("ConversationKeyFor() error = %v", err)
	}
	got, err := nip44.Decrypt(ev.Content, conversationKey[:])
	if err != nil {
		t.Fatalf("hub cannot decrypt the request: %v", err)
	}
	if got != string(plaintext) {
		t.Fatal("decrypted plaintext does not match what was wrapped")
	}

	// And it must round-trip back to an envelope, not merely to bytes.
	back, err := Decode([]byte(got), DefaultLimits())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if back.Nonce != env.Nonce {
		t.Errorf("nonce = %q, want %q", back.Nonce, env.Nonce)
	}
}

// TestWrapRequest_AuthorIsEphemeralAndUnlinkable: the author key must differ every
// time and must never be the inbox. If it were stable, the whole transport would
// leak a sender identifier in the clear and the batching would buy nothing.
func TestWrapRequest_AuthorIsEphemeralAndUnlinkable(t *testing.T) {
	_, inboxXOnly := testKeypair(t)
	plaintext, err := newTestEnvelope(t).Encode(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]struct{}, 8)
	for i := 0; i < 8; i++ {
		ev, _, err := WrapRequest(plaintext, inboxXOnly)
		if err != nil {
			t.Fatalf("WrapRequest() error = %v", err)
		}
		if ev.PubKey == inboxXOnly {
			t.Fatal("author key must not be the inbox key")
		}
		if _, dup := seen[ev.PubKey]; dup {
			t.Fatalf("author key %q reused across requests — it must be ephemeral", ev.PubKey)
		}
		seen[ev.PubKey] = struct{}{}
	}
}

// TestWrapRequest_CreatedAtIsBackdated: created_at must not be a freshness signal,
// which is precisely why the envelope carries not_after. A stated time at or after
// "now" would mean the randomisation is not happening.
func TestWrapRequest_CreatedAtIsBackdated(t *testing.T) {
	_, inboxXOnly := testKeypair(t)
	plaintext, err := newTestEnvelope(t).Encode(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	// Randomised, so a single sample can legitimately land near now. Take several
	// and require the spread that randomisation implies.
	var oldest int64 = 1 << 62
	for i := 0; i < 24; i++ {
		ev, _, err := WrapRequest(plaintext, inboxXOnly)
		if err != nil {
			t.Fatal(err)
		}
		if got := int64(ev.CreatedAt); got < oldest {
			oldest = got
		}
	}
	if age := time.Now().Unix() - oldest; age < 60 {
		t.Errorf("oldest created_at across 24 requests is only %ds in the past; "+
			"created_at is meant to be randomised up to two days back", age)
	}
}

// TestWrapRequest_AGiftWrapWouldNotBeAccepted is the test that makes F1 concrete.
//
// An earlier draft of NIP-CASH described a private request as a NIP-59 gift wrap.
// This proves what would have happened to anyone who implemented that: the event is
// the wrong KIND, so a hub discards it at the subscription filter, before any
// decryption — meaning the sender gets silence, with nothing to diagnose.
func TestWrapRequest_AGiftWrapWouldNotBeAccepted(t *testing.T) {
	senderPriv, _ := testKeypair(t)
	_, inboxXOnly := testKeypair(t)

	plaintext, err := newTestEnvelope(t).Encode(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	// A NIP-59 wrap of the same payload: structurally valid, and useless here.
	inner := nip01.NewEvent(KindPrivateRequest, string(plaintext))
	if err := inner.Sign(senderPriv); err != nil {
		t.Fatal(err)
	}
	wrap, err := nip59.Wrap(inner, senderPriv, inboxXOnly)
	if err != nil {
		t.Fatalf("nip59.Wrap() error = %v", err)
	}

	if wrap.Kind == KindPrivateRequest {
		t.Fatal("a NIP-59 wrap must NOT share the private-request kind; if it does, " +
			"the two constructions are no longer distinguishable and F1's reasoning breaks")
	}
	if wrap.Kind != nip59.KindGiftWrap {
		t.Fatalf("nip59.Wrap produced kind %d, expected the gift-wrap kind %d",
			wrap.Kind, nip59.KindGiftWrap)
	}
}

func TestWrapRequest_RejectsMalformedInput(t *testing.T) {
	_, inboxXOnly := testKeypair(t)
	plaintext, err := newTestEnvelope(t).Encode(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		plaintext []byte
		inbox     string
	}{
		{"empty payload", nil, inboxXOnly},
		{"inbox too short", plaintext, strings.Repeat("ab", 20)},
		{"inbox uppercase hex", plaintext, strings.ToUpper(inboxXOnly)},
		{"inbox not on the curve", plaintext, strings.Repeat("ff", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := WrapRequest(tc.plaintext, tc.inbox); err == nil {
				t.Error("WrapRequest() error = nil, want an error")
			}
		})
	}
}

// TestWrapRequest_ClientCanReadTheReply is the regression test for a design error
// this function had when first written: it discarded the ephemeral key and returned
// only the event.
//
// That looked tidy and made the reply unreadable. The response is encrypted under
// DeriveReplyKey(conversationKey, replyTo), and conversationKey is
// ECDH(ephemeral_priv, inbox_pub). The HUB can recompute it from its own inbox key
// and the event's author, but the CLIENT cannot recompute it from anything on the
// wire — it would need the ephemeral private key, which must never be kept.
//
// So the key is returned. This test proves both sides arrive at the same one by
// deriving it from opposite halves and round-tripping an actual reply, which is the
// only way to catch the class of bug where each end is self-consistent.
func TestWrapRequest_ClientCanReadTheReply(t *testing.T) {
	inboxPriv, inboxXOnly := testKeypair(t)

	env := newTestEnvelope(t)
	plaintext, err := env.Encode(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	ev, clientKey, err := WrapRequest(plaintext, inboxXOnly)
	if err != nil {
		t.Fatalf("WrapRequest() error = %v", err)
	}
	if clientKey == ([32]byte{}) {
		t.Fatal("WrapRequest returned a zero conversation key; the reply would be unreadable")
	}

	// The hub's half: derived from its own inbox key and the event's author.
	hubKey, err := ConversationKeyFor(ev.PubKey, inboxPriv)
	if err != nil {
		t.Fatalf("ConversationKeyFor() error = %v", err)
	}
	if hubKey != clientKey {
		t.Fatal("client and hub derived different conversation keys from the same exchange")
	}

	// A hub encrypts its response under the reply key; the client must read it.
	hubReplyKey, err := DeriveReplyKey(hubKey, env.ReplyTo)
	if err != nil {
		t.Fatal(err)
	}
	clientReplyKey, err := DeriveReplyKey(clientKey, env.ReplyTo)
	if err != nil {
		t.Fatal(err)
	}
	if hubReplyKey != clientReplyKey {
		t.Fatal("client and hub derived different REPLY keys")
	}

	response := ResponseEnvelope{
		Version:  EnvelopeVersion,
		ReqNonce: env.Nonce,
		Results:  []Result{{ID: env.Items[0].ID, ResultType: "cash_status"}},
	}
	encoded, err := response.EncodeResponse(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := nip44.Encrypt(string(encoded), hubReplyKey[:])
	if err != nil {
		t.Fatal(err)
	}

	opened, err := nip44.Decrypt(sealed, clientReplyKey[:])
	if err != nil {
		t.Fatalf("client cannot decrypt the hub's reply: %v", err)
	}
	ids := []string{env.Items[0].ID}
	decoded, err := DecodeResponse([]byte(opened), env.Nonce, ids, DefaultLimits())
	if err != nil {
		t.Fatalf("DecodeResponse() error = %v", err)
	}
	if len(decoded.Results) != 1 || decoded.Results[0].ID != ids[0] {
		t.Errorf("decoded results = %+v, want one result for %q", decoded.Results, ids[0])
	}
}
