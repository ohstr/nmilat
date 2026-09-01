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
	ev := NewAltZapRequest(AltZapRequestParams{
		Chain:             "flokicoin",
		Recipient:         "recipient1",
		Lnurl:             validLnurl,
		AmountMloki:       5000,
		Relays:            relays,
		Sender:            "sender1",
		SenderProvider:    "discord",
		RecipientProvider: "nostr",
		EventID:           &eventID,
	})

	if ev.Kind != KindAltZapRequest {
		t.Errorf("expected kind %d, got %d", KindAltZapRequest, ev.Kind)
	}
	if ev.PubKey != "sender1" {
		t.Errorf("expected pubkey sender1, got %s", ev.PubKey)
	}

	req, err := ParseAltZapRequest(ev)
	if err != nil {
		t.Fatalf("expected NewAltZapRequest output to be parseable, got error: %v", err)
	}
	if req.Amount != 5000 || req.Lnurl != validLnurl || req.Chain != "flokicoin" {
		t.Errorf("unexpected parsed request: %+v", req)
	}
	if req.Sender != "sender1" || req.SenderProvider != "discord" {
		t.Errorf("expected sender tags to round-trip, got %+v", req)
	}
	if req.EventID != eventID {
		t.Errorf("expected event ID %q, got %q", eventID, req.EventID)
	}
}

func TestNewAltZapOnBehalfRequest(t *testing.T) {
	relays := []string{"wss://relay.example.com"}
	ev := NewAltZapOnBehalfRequest(AltZapRequestParams{
		Chain:       "flokicoin",
		Recipient:   "recipient1",
		Lnurl:       "lnurl1",
		AmountMloki: 5000,
		Relays:      relays,
		Sender:      "sender1",
	})

	if ev.Kind != KindAltZapOnBehalfRequest {
		t.Errorf("expected kind %d, got %d", KindAltZapOnBehalfRequest, ev.Kind)
	}
}

func TestNewAltZapDirectPaymentRequest(t *testing.T) {
	relays := []string{"wss://relay.example.com"}
	ev := NewAltZapDirectPaymentRequest(AltZapDirectPaymentParams{
		Chain:          "flokicoin",
		Bolt11:         "lnfc-invoice",
		AmountMloki:    5000,
		Relays:         relays,
		Sender:         "sender1",
		SenderProvider: "nostr",
	})

	if ev.Kind != KindAltZapDirectPayment {
		t.Errorf("expected kind %d, got %d", KindAltZapDirectPayment, ev.Kind)
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

func TestNewAltZapReceipt_ExtractsTagsFromDescription(t *testing.T) {
	originalDecode := nip57.DecodeBolt11
	defer func() { nip57.DecodeBolt11 = originalDecode }()
	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		return &nip57.Invoice{AmountMloki: 1000}, nil
	}

	reqEvent := signedZapRequestEvent(t, KindAltZapRequest, nil)
	descBytes, err := json.Marshal(reqEvent)
	if err != nil {
		t.Fatalf("failed to marshal embedded request: %v", err)
	}

	preimage := "abc123"
	receipt, err := NewAltZapReceipt(AltZapReceiptParams{
		Chain:           "flokicoin",
		ProviderPubkey:  "provider1",
		RecipientPubkey: "recipient1",
		SenderPubkey:    "sender1",
		Bolt11:          "lnfc-invoice",
		Description:     string(descBytes),
		Preimage:        &preimage,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var eTagFound, detailedPTagFound bool
	for _, tag := range receipt.Tags {
		if len(tag) >= 2 && tag[0] == "e" {
			eTagFound = true
		}
		if len(tag) >= 3 && tag[0] == "p" {
			detailedPTagFound = true
		}
	}
	_ = eTagFound // the mock request has no "e" tag; kept for readability of intent
	if !detailedPTagFound {
		t.Error("expected the basic 'p' tag to be replaced by the detailed one from the embedded request")
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
