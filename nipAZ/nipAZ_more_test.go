package nipAZ

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
)

const zapsTestPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

// A real bech32-decodable lnurl (utils.ValidateLNURL requires this, not a
// placeholder string) shared across tests that build+parse a request.
const validTestLnurl = "lnurl1dp68gurn8ghj7um9wfmxjcm99e3k7mf0v9cxj0m385ekvcenxc6r2c35xvukxefcv5mkvv34x5ekzd3ev56nyd3hxqurzepexejxxepnxscrvwfnv9nxzcn9xq6xyefhvgcxxcmyxymnserxfq5fns"

func signedZapRequestEvent(t *testing.T, kind int, extraTags [][]string) *nip01.Event {
	t.Helper()
	pubkeyPlaceholder := "0000000000000000000000000000000000000000000000000000000000000001"

	tags := [][]string{
		{"p", pubkeyPlaceholder, "nostr"},
		{"amount", "1000"},
		{"lnurl", "lnurl1dp68gurn8ghj7um9wfmxjcm99e3k7mf0v9cxj0m385ekvcenxc6r2c35xvukxefcv5mkvv34x5ekzd3ev56nyd3hxqurzepexejxxepnxscrvwfnv9nxzcn9xq6xyefhvgcxxcmyxymnserxfq5fns"},
		{"chain", "flokicoin"},
		{"relays", "wss://relay.example.com"},
	}
	tags = append(tags, extraTags...)

	ev := &nip01.Event{Kind: kind, Tags: tags}
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	return ev
}

func TestValidateAltZapRequest_Success(t *testing.T) {
	ev := signedZapRequestEvent(t, KindAltZapRequest, nil)
	if err := ValidateAltZapRequest(ev, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateAltZapRequest(ev, 1000); err != nil {
		t.Fatalf("unexpected error with matching expected amount: %v", err)
	}
}

func TestValidateAltZapRequest_AmountMismatch(t *testing.T) {
	ev := signedZapRequestEvent(t, KindAltZapRequest, nil)
	if err := ValidateAltZapRequest(ev, 9999); err == nil {
		t.Fatal("expected error for amount mismatch")
	}
}

func TestValidateAltZapRequest_InvalidSignature(t *testing.T) {
	ev := signedZapRequestEvent(t, KindAltZapRequest, nil)
	ev.Content = "tampered after signing"

	if err := ValidateAltZapRequest(ev, 0); err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestValidateAltZapRequest_DirectPaymentHashLock(t *testing.T) {
	pubkeyPlaceholder := "0000000000000000000000000000000000000000000000000000000000000001"
	ev := &nip01.Event{
		Kind: KindAltZapDirectPayment,
		Tags: [][]string{
			{"amount", "1000"},
			{"bolt11", "lnfc-direct-payment"},
			{"chain", "flokicoin"},
			{"relays", "wss://relay.example.com"},
			{"P", pubkeyPlaceholder},
		},
	}
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}

	eventJSON, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}
	descHash := sha256.Sum256(eventJSON)
	descHashHex := hex.EncodeToString(descHash[:])

	originalDecode := nip57.DecodeBolt11
	defer func() { nip57.DecodeBolt11 = originalDecode }()
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000, DescriptionHash: descHashHex}, nil
	}

	if err := ValidateAltZapRequest(ev, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000, DescriptionHash: "wrong-hash"}, nil
	}
	if err := ValidateAltZapRequest(ev, 0); err == nil {
		t.Fatal("expected hash-lock failure error")
	}

	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return nil, fmt.Errorf("decode failed")
	}
	if err := ValidateAltZapRequest(ev, 0); err == nil {
		t.Fatal("expected error when bolt11 decoding fails")
	}
}

func TestNewAltZapRequest(t *testing.T) {
	relays := []string{"wss://relay.example.com"}
	eventID := strings.Repeat("1", 63) + "a"

	validLnurl := "lnurl1dp68gurn8ghj7um9wfmxjcm99e3k7mf0v9cxj0m385ekvcenxc6r2c35xvukxefcv5mkvv34x5ekzd3ev56nyd3hxqurzepexejxxepnxscrvwfnv9nxzcn9xq6xyefhvgcxxcmyxymnserxfq5fns"
	ev, err := NewAltZapRequest(AltZapRequestParams{
		PrivateKey:  zapsTestPrivKey,
		Chain:       "flokicoin",
		Recipient:   Pubkey("recipient1"),
		Lnurl:       validLnurl,
		AmountMloki: 5000,
		Relays:      relays,
		Sender:      Connection("discord", "sender-external-id"),
		EventID:     &eventID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Kind != KindAltZapRequest {
		t.Errorf("expected kind %d, got %d", KindAltZapRequest, ev.Kind)
	}
	if err := ev.Verify(); err != nil {
		t.Errorf("expected a validly signed event, got: %v", err)
	}

	req, err := ParseAltZapRequest(ev)
	if err != nil {
		t.Fatalf("expected NewAltZapRequest output to be parseable, got error: %v", err)
	}
	if req.Amount != 5000 || req.Lnurl != validLnurl || req.Chain != "flokicoin" {
		t.Errorf("unexpected parsed request: %+v", req)
	}
	if req.Sender.WebIdentity() != "discord" || req.Sender.Value() != Connection("discord", "sender-external-id").Value() {
		t.Errorf("expected sender identity to round-trip, got %+v", req.Sender)
	}
	if req.EventID != eventID {
		t.Errorf("expected event ID %q, got %q", eventID, req.EventID)
	}
}

func TestNewAltZapRequest_ContentRoundTrips(t *testing.T) {
	ev, err := NewAltZapRequest(AltZapRequestParams{
		PrivateKey:  zapsTestPrivKey,
		Chain:       "flokicoin",
		Recipient:   Pubkey("recipient1"),
		Lnurl:       validTestLnurl,
		AmountMloki: 5000,
		Relays:      []string{"wss://relay.example.com"},
		Content:     "Great post!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Content != "Great post!" {
		t.Errorf("expected content to round-trip, got %q", ev.Content)
	}
}

func TestNewAltZapRequest_InvalidPrivateKeyErrors(t *testing.T) {
	_, err := NewAltZapRequest(AltZapRequestParams{
		PrivateKey:  "not-a-valid-key",
		Chain:       "flokicoin",
		Recipient:   Pubkey("recipient1"),
		Lnurl:       validTestLnurl,
		AmountMloki: 5000,
		Relays:      []string{"wss://relay.example.com"},
	})
	if err == nil {
		t.Error("expected error for invalid private key")
	}
}

func TestNewAltZapOnBehalfRequest(t *testing.T) {
	relays := []string{"wss://relay.example.com"}
	ev, err := NewAltZapOnBehalfRequest(
		Connection("discord", "sender-external-id"),
		AltZapRequestParams{
			PrivateKey:  zapsTestPrivKey,
			Chain:       "flokicoin",
			Recipient:   Connection("discord", "recipient-external-id"),
			Lnurl:       validTestLnurl,
			AmountMloki: 5000,
			Relays:      relays,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Kind != KindAltZapOnBehalfRequest {
		t.Errorf("expected kind %d, got %d", KindAltZapOnBehalfRequest, ev.Kind)
	}

	req, err := ParseAltZapRequest(ev)
	if err != nil {
		t.Fatalf("expected output to be parseable, got: %v", err)
	}
	if req.Sender.IsZero() {
		t.Error("expected sender identity to be present on an on-behalf request")
	}
	if req.Sender.WebIdentity() != "discord" {
		t.Errorf("expected sender platform 'discord', got %q", req.Sender.WebIdentity())
	}
}

// Kind 5523 must always carry a sender — sender being a required positional
// argument (not an optional params field) makes this a compile-time
// guarantee rather than a runtime check, but confirm the resulting event
// really does parse with a non-zero sender regardless of what's in Params.
func TestNewAltZapOnBehalfRequest_SenderParamIsIgnoredInFavorOfPositionalArg(t *testing.T) {
	ev, err := NewAltZapOnBehalfRequest(
		Pubkey("real-sender"),
		AltZapRequestParams{
			PrivateKey:  zapsTestPrivKey,
			Chain:       "flokicoin",
			Recipient:   Pubkey("recipient1"),
			Lnurl:       validTestLnurl,
			AmountMloki: 5000,
			Relays:      []string{"wss://relay.example.com"},
			Sender:      Pubkey("this-should-be-overridden"),
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req, err := ParseAltZapRequest(ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Sender.Value() != "real-sender" {
		t.Errorf("expected the positional sender argument to win, got %q", req.Sender.Value())
	}
}

func TestNewAltZapDirectPaymentRequest(t *testing.T) {
	relays := []string{"wss://relay.example.com"}
	ev, err := NewAltZapDirectPaymentRequest(AltZapDirectPaymentParams{
		PrivateKey:  zapsTestPrivKey,
		Chain:       "flokicoin",
		Bolt11:      "lnfc-invoice",
		AmountMloki: 5000,
		Relays:      relays,
		Sender:      Pubkey("sender1"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ev.Kind != KindAltZapDirectPayment {
		t.Errorf("expected kind %d, got %d", KindAltZapDirectPayment, ev.Kind)
	}
	if err := ev.Verify(); err != nil {
		t.Errorf("expected a validly signed event, got: %v", err)
	}

	var hasBolt11, hasSender bool
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "bolt11" && tag[1] == "lnfc-invoice" {
			hasBolt11 = true
		}
		if len(tag) >= 2 && tag[0] == "P" && tag[1] == "sender1" {
			hasSender = true
		}
	}
	if !hasBolt11 {
		t.Error("expected bolt11 tag to be present")
	}
	if !hasSender {
		t.Error("expected P (sender) tag to be present")
	}
}

// Replaces TestNewAltZapReceipt_ExtractsTagsFromDescription: the old
// fallback silently copied p/P tags (handle included) back out of the
// embedded request's description JSON, which could reintroduce a value the
// ZSP never verified — see NIPAZ-NIPIC-API-EXAMPLES.md scenario 6. Confirm
// that no longer happens: Recipient/Sender always come from the caller's
// explicit params, never from Description, even when Description embeds a
// conflicting identity.
func TestNewAltZapReceipt_RecipientNeverOverriddenByDescription(t *testing.T) {
	originalDecode := nip57.DecodeBolt11
	defer func() { nip57.DecodeBolt11 = originalDecode }()
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000}, nil
	}

	// The embedded request's own p tag names a *different* recipient than
	// what the ZSP has authoritatively resolved server-side.
	reqEvent := &nip01.Event{
		Kind: KindAltZapRequest,
		Tags: [][]string{
			{"p", "some-other-unverified-recipient", "discord", "unverified-handle"},
			{"amount", "1000"},
			{"lnurl", validTestLnurl},
			{"chain", "flokicoin"},
			{"relays", "wss://relay.example.com"},
		},
	}
	if err := reqEvent.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign embedded request: %v", err)
	}
	descBytes, err := json.Marshal(reqEvent)
	if err != nil {
		t.Fatalf("failed to marshal embedded request: %v", err)
	}

	preimage := "abc123"
	verifiedRecipient := Connection("discord", "server-verified-id").WithHandle("server-verified-handle")
	receipt, err := NewAltZapReceipt(AltZapReceiptParams{
		PrivateKey:  zapsTestPrivKey,
		Chain:       "flokicoin",
		Recipient:   verifiedRecipient,
		Bolt11:      "lnfc-invoice",
		Description: string(descBytes),
		Preimage:    &preimage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := ParseAltZapReceipt(receipt)
	if err != nil {
		t.Fatalf("unexpected error parsing constructed receipt: %v", err)
	}
	if parsed.Recipient.Value() != verifiedRecipient.Value() {
		t.Errorf("expected server-verified recipient to win, got value %q", parsed.Recipient.Value())
	}
	if parsed.Recipient.Handle() != "server-verified-handle" {
		t.Errorf("expected server-verified handle to win, got %q", parsed.Recipient.Handle())
	}
}

// New coverage: a receipt's Recipient handle (set via WithHandle) is emitted
// as the 4th tag element and round-trips through Parse.
func TestNewAltZapReceipt_HandleRoundTrips(t *testing.T) {
	originalDecode := nip57.DecodeBolt11
	defer func() { nip57.DecodeBolt11 = originalDecode }()
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000}, nil
	}

	preimage := "abc123"
	receipt, err := NewAltZapReceipt(AltZapReceiptParams{
		PrivateKey: zapsTestPrivKey,
		Chain:      "flokicoin",
		Recipient:  Connection("discord", "id1").WithHandle("cool_username"),
		Bolt11:     "lnfc-invoice",
		Preimage:   &preimage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := ParseAltZapReceipt(receipt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Recipient.Handle() != "cool_username" {
		t.Errorf("expected handle to round-trip, got %q", parsed.Recipient.Handle())
	}
}

// Ported from zapf's internal/nostr/events_test.go:TestBuildZapReceipt's
// "Proxy Request (Intent 5523) with Resolved Sender" case — a proxy sender
// (ConnectionKey scoped to a platform, no handle) combined with a resolved
// native pubkey on the R tag.
func TestNewAltZapReceipt_ProxySenderWithResolvedSender(t *testing.T) {
	originalDecode := nip57.DecodeBolt11
	defer func() { nip57.DecodeBolt11 = originalDecode }()
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000}, nil
	}

	preimage := "preimage_hex"
	receipt, err := NewAltZapReceipt(AltZapReceiptParams{
		PrivateKey:           zapsTestPrivKey,
		Chain:                "flokicoin",
		Recipient:            Pubkey("recipientpubkey"),
		Sender:               Connection("discord", "someconnectionkey-external-id").WithHandle(""),
		ResolvedSenderPubkey: "actualsenderpubkey",
		Bolt11:               "lnbc1...",
		Preimage:             &preimage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := ParseAltZapReceipt(receipt)
	if err != nil {
		t.Fatalf("unexpected error parsing constructed receipt: %v", err)
	}
	if parsed.Sender.WebIdentity() != "discord" {
		t.Errorf("expected P tag platform 'discord', got %q", parsed.Sender.WebIdentity())
	}
	if parsed.Sender.Handle() != "" {
		t.Errorf("expected no handle on the P tag, got %q", parsed.Sender.Handle())
	}
	if parsed.ResolvedSenderPubkey != "actualsenderpubkey" {
		t.Errorf("expected R tag 'actualsenderpubkey', got %q", parsed.ResolvedSenderPubkey)
	}
}

// New coverage: request-side identities never emit a handle on the wire,
// even if one is (mistakenly) set — matches the original NewAltZapRequest's
// wire behavior (2/3-element p/P tags only).
func TestNewAltZapRequest_NeverEmitsHandleOnRequests(t *testing.T) {
	ev, err := NewAltZapRequest(AltZapRequestParams{
		PrivateKey:  zapsTestPrivKey,
		Chain:       "flokicoin",
		Recipient:   Connection("discord", "id1").WithHandle("should-not-appear"),
		Lnurl:       validTestLnurl,
		AmountMloki: 5000,
		Relays:      []string{"wss://relay.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tag := range ev.Tags {
		if len(tag) >= 1 && tag[0] == "p" && len(tag) > 3 {
			t.Errorf("expected request p tag to have at most 3 elements, got %v", tag)
		}
	}
}

func TestValidateAltZapReceipt_DirectPayment(t *testing.T) {
	ev := &nip01.Event{
		Kind: KindAltZapReceipt,
		Tags: [][]string{
			{"bolt11", "lnfc-direct"},
			{"chain", "flokicoin"},
			{"preimage", "preimage1"},
		},
	}
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}

	originalDecode := nip57.DecodeBolt11
	defer func() { nip57.DecodeBolt11 = originalDecode }()
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000}, nil
	}

	if err := ValidateAltZapReceipt(ev); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 0}, nil
	}
	if err := ValidateAltZapReceipt(ev); err == nil {
		t.Fatal("expected error for zero/invalid invoice amount on a direct payment receipt")
	}
}

func TestValidateAltZapReceipt_WithEmbeddedRequest(t *testing.T) {
	reqEvent := signedZapRequestEvent(t, KindAltZapRequest, nil)
	descBytes, err := json.Marshal(reqEvent)
	if err != nil {
		t.Fatalf("failed to marshal embedded request: %v", err)
	}
	descHash := sha256.Sum256(descBytes)
	descHashHex := hex.EncodeToString(descHash[:])

	recipient := "0000000000000000000000000000000000000000000000000000000000000001" // matches signedZapRequestEvent's p tag

	receipt := &nip01.Event{
		Kind: KindAltZapReceipt,
		Tags: [][]string{
			{"bolt11", "lnfc-zap"},
			{"chain", "flokicoin"},
			{"preimage", "preimage1"},
			{"p", recipient},
			{"description", string(descBytes)},
		},
	}
	if err := receipt.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign receipt: %v", err)
	}

	originalDecode := nip57.DecodeBolt11
	defer func() { nip57.DecodeBolt11 = originalDecode }()
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000, DescriptionHash: descHashHex}, nil
	}

	if err := ValidateAltZapReceipt(receipt); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Amount mismatch between invoice and the embedded request.
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 42, DescriptionHash: descHashHex}, nil
	}
	if err := ValidateAltZapReceipt(receipt); err == nil {
		t.Fatal("expected amount mismatch error")
	}

	// Description hash mismatch.
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000, DescriptionHash: "wrong"}, nil
	}
	if err := ValidateAltZapReceipt(receipt); err == nil {
		t.Fatal("expected description hash mismatch error")
	}
}

// ── Identity ─────────────────────────────────────────────────────────────

func TestIdentity_ZeroValueIsZero(t *testing.T) {
	var id Identity
	if !id.IsZero() {
		t.Error("expected the zero Identity to report IsZero() == true")
	}
}

func TestIdentity_PubkeyIsNotZero(t *testing.T) {
	if Pubkey("abc").IsZero() {
		t.Error("expected a Pubkey identity to be non-zero")
	}
}

func TestIdentity_ConnectionComputesConnectionKeyInternally(t *testing.T) {
	id := Connection("discord", "123456")
	if len(id.Value()) != 64 {
		t.Errorf("expected a 64-hex-char ConnectionKey, got %d chars: %q", len(id.Value()), id.Value())
	}
	if id.Value() != Connection("discord", "123456").Value() {
		t.Error("expected Connection() to be deterministic for the same (platform, externalID) pair")
	}
	if id.Value() == Connection("discord", "654321").Value() {
		t.Error("expected different externalIDs to produce different ConnectionKeys")
	}
	if id.WebIdentity() != "discord" {
		t.Errorf("expected platform 'discord', got %q", id.WebIdentity())
	}
}

// Resolves design-doc open question #2: a caller that already has a
// ConnectionKey (resolved upstream, e.g. by a caller like zapf's
// BuildZapReceipt which receives an already-resolved identity string from
// several layers up) must not have to pay for — or risk diverging from — a
// second hash computation.
func TestIdentity_ResolvedConnectionDoesNotRehash(t *testing.T) {
	key := ConnectionKey(Connection("discord", "123456").Value())
	id := ResolvedConnection(key, "discord")
	if id.Value() != key.String() {
		t.Errorf("expected ResolvedConnection to use the given key verbatim, got %q want %q", id.Value(), key.String())
	}
	if id.WebIdentity() != "discord" {
		t.Errorf("expected platform 'discord', got %q", id.WebIdentity())
	}
	// Cross-check against the hashing constructor: both paths must agree for
	// the same logical (platform, externalID) identity.
	if id.Value() != Connection("discord", "123456").Value() {
		t.Error("expected ResolvedConnection(NewConnectionKey(...)) to equal Connection(...) for the same inputs")
	}
}

func TestIdentity_ResolvedConnectionSupportsHandle(t *testing.T) {
	key := ConnectionKey(Connection("discord", "123456").Value())
	id := ResolvedConnection(key, "discord").WithHandle("cool_username")
	if id.Handle() != "cool_username" {
		t.Errorf("expected handle to round-trip, got %q", id.Handle())
	}
}

// ── DescriptionHash ──────────────────────────────────────────────────────
// New coverage: this was previously duplicated (and undertested) across
// zapf's pkg/nostr/altzap.go and internal/nostr/events.go.

func TestDescriptionHash_MatchesRawSHA256(t *testing.T) {
	input := `{"kind":5520,"tags":[]}`
	want := sha256.Sum256([]byte(input))
	wantHex := hex.EncodeToString(want[:])

	if got := DescriptionHash(input); got != wantHex {
		t.Errorf("DescriptionHash(%q) = %q, want %q", input, got, wantHex)
	}
}

func TestDescriptionHash_Deterministic(t *testing.T) {
	input := "some description string"
	if DescriptionHash(input) != DescriptionHash(input) {
		t.Error("expected DescriptionHash to be deterministic")
	}
}

func TestDescriptionHash_HashesVerbatimNotReserialized(t *testing.T) {
	// Two JSON strings that decode to the same object but differ byte-for-byte
	// (key order, whitespace) MUST hash differently — DescriptionHash must
	// never re-marshal its input, since a receiver later hashes the exact
	// stored wire string to verify a match (see the doc comment).
	a := `{"a":1,"b":2}`
	b := `{"b": 2, "a": 1}`
	if DescriptionHash(a) == DescriptionHash(b) {
		t.Error("expected DescriptionHash to hash the raw string verbatim, not a re-serialized form")
	}
}

func TestIdentity_WithHandleIsImmutable(t *testing.T) {
	base := Pubkey("abc")
	withHandle := base.WithHandle("alice")
	if base.Handle() != "" {
		t.Error("expected WithHandle to not mutate the receiver")
	}
	if withHandle.Handle() != "alice" {
		t.Errorf("expected handle 'alice', got %q", withHandle.Handle())
	}
}
