package nip57

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestParseZapRequest(t *testing.T) {
	validPubkey := "0000000000000000000000000000000000000000000000000000000000000001"

	tests := []struct {
		name    string
		event   *nip01.Event
		wantErr bool
	}{
		{
			name: "Valid request with all optional tags",
			event: mockEvent(KindZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"P", validPubkey},
				{"amount", "21000"},
				{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
				{"e", validPubkey},
				{"a", "1:" + validPubkey + ":d-tag"},
				{"k", "1"},
			}, "Zap!"),
			wantErr: false,
		},
		{
			name: "Valid minimal request (only p and relays)",
			event: mockEvent(KindZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
			}, ""),
			wantErr: false,
		},
		{
			name: "Invalid kind",
			event: mockEvent(KindAltZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
			}, ""),
			wantErr: true,
		},
		{
			name: "Missing p tag",
			event: mockEvent(KindZapRequest, [][]string{
				{"relays", "wss://relay.com"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Multiple p tags",
			event: mockEvent(KindZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"p", validPubkey},
			}, ""),
			wantErr: true,
		},
		{
			name: "Multiple P tags",
			event: mockEvent(KindZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"P", validPubkey},
				{"P", validPubkey},
			}, ""),
			wantErr: true,
		},
		{
			name: "Missing relays",
			event: mockEvent(KindZapRequest, [][]string{
				{"p", validPubkey},
			}, ""),
			wantErr: true,
		},
		{
			name: "Invalid relay scheme",
			event: mockEvent(KindZapRequest, [][]string{
				{"relays", "httpx://invalid-scheme.com"},
				{"p", validPubkey},
			}, ""),
			wantErr: true,
		},
		{
			name: "Invalid amount",
			event: mockEvent(KindZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"amount", "-100"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Multiple e tags",
			event: mockEvent(KindZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"e", validPubkey},
				{"e", validPubkey},
			}, ""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseZapRequest(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseZapRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewZapRequest_RoundTrip(t *testing.T) {
	relays := []string{"wss://relay.example.com"}
	eventID := "0000000000000000000000000000000000000000000000000000000000000001"
	validLnurl := "lnurl1dp68gurn8ghj7um9wfmxjcm99e3k7mf0v9cxj0m385ekvcenxc6r2c35xvukxefcv5mkvv34x5ekzd3ev56nyd3hxqurzepexejxxepnxscrvwfnv9nxzcn9xq6xyefhvgcxxcmyxymnserxfq5fns"

	ev := NewZapRequest(ZapRequestParams{
		Recipient:  "0000000000000000000000000000000000000000000000000000000000000002",
		Relays:     relays,
		AmountMsat: 21000,
		Lnurl:      validLnurl,
		EventID:    &eventID,
	})

	if ev.Kind != KindZapRequest {
		t.Fatalf("expected kind %d, got %d", KindZapRequest, ev.Kind)
	}
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}

	req, err := ParseZapRequest(ev)
	if err != nil {
		t.Fatalf("expected NewZapRequest output to be parseable, got error: %v", err)
	}
	if req.Amount != 21000 || req.Lnurl != validLnurl {
		t.Errorf("unexpected parsed request: %+v", req)
	}
	if req.EventID != eventID {
		t.Errorf("expected event ID %q, got %q", eventID, req.EventID)
	}
	if err := ValidateZapRequest(ev, 21000); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateZapRequest_AmountMismatch(t *testing.T) {
	ev := NewZapRequest(ZapRequestParams{
		Recipient:  "0000000000000000000000000000000000000000000000000000000000000002",
		Relays:     []string{"wss://relay.example.com"},
		AmountMsat: 21000,
	})
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}

	if err := ValidateZapRequest(ev, 9999); err == nil {
		t.Fatal("expected error for amount mismatch")
	}
}

func TestValidateZapRequest_InvalidSignature(t *testing.T) {
	ev := NewZapRequest(ZapRequestParams{
		Recipient: "0000000000000000000000000000000000000000000000000000000000000002",
		Relays:    []string{"wss://relay.example.com"},
	})
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	ev.Content = "tampered after signing"

	if err := ValidateZapRequest(ev, 0); err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestParseZapReceipt(t *testing.T) {
	validPubkey := "0000000000000000000000000000000000000000000000000000000000000001"

	signedZapReq := NewZapRequest(ZapRequestParams{
		Recipient:  validPubkey,
		Relays:     []string{"wss://relay.com"},
		AmountMsat: 1000,
		Lnurl:      "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5",
	})
	if err := signedZapReq.Sign(validPubkey); err != nil {
		t.Fatalf("failed to sign zap request: %v", err)
	}
	signedZapReqJSON, _ := json.Marshal(signedZapReq)

	forgedZapReq := mockEvent(KindZapRequest, [][]string{
		{"relays", "wss://relay.com"},
		{"p", validPubkey},
	}, "")
	forgedZapReqJSON, _ := json.Marshal(forgedZapReq)

	tests := []struct {
		name    string
		event   *nip01.Event
		wantErr bool
		check   func(*ZapReceipt) error
	}{
		{
			name: "Valid receipt with description",
			event: mockEvent(KindZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"description", string(signedZapReqJSON)},
			}, ""),
			wantErr: false,
			check: func(zr *ZapReceipt) error {
				if zr.Request == nil {
					return fmt.Errorf("expected embedded request to be parsed")
				}
				if zr.Bolt11 != "lnfc1..." {
					return fmt.Errorf("unexpected bolt11")
				}
				return nil
			},
		},
		{
			name:    "Invalid kind",
			event:   mockEvent(KindZapRequest, [][]string{}, ""),
			wantErr: true,
		},
		{
			name: "Missing p tag",
			event: mockEvent(KindZapReceipt, [][]string{
				{"bolt11", "lnfc1..."},
				{"description", string(signedZapReqJSON)},
			}, ""),
			wantErr: true,
		},
		{
			name: "Missing bolt11",
			event: mockEvent(KindZapReceipt, [][]string{
				{"p", validPubkey},
				{"description", string(signedZapReqJSON)},
			}, ""),
			wantErr: true,
		},
		{
			name: "Missing description",
			event: mockEvent(KindZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
			}, ""),
			wantErr: true,
		},
		{
			name: "Invalid description JSON",
			event: mockEvent(KindZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"description", "{invalid-json"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Forged embedded zap request signature",
			event: mockEvent(KindZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"description", string(forgedZapReqJSON)},
			}, ""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zr, err := ParseZapReceipt(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseZapReceipt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil {
				if err := tt.check(zr); err != nil {
					t.Errorf("check failed: %v", err)
				}
			}
		})
	}
}

func TestNewZapReceipt_ValidateRoundTrip(t *testing.T) {
	recipient := "0000000000000000000000000000000000000000000000000000000000000001"

	zapReq := NewZapRequest(ZapRequestParams{
		Recipient:  recipient,
		Relays:     []string{"wss://relay.com"},
		AmountMsat: 1000,
	})
	if err := zapReq.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign zap request: %v", err)
	}
	descBytes, err := json.Marshal(zapReq)
	if err != nil {
		t.Fatalf("failed to marshal zap request: %v", err)
	}
	descHash := sha256.Sum256(descBytes)
	descHashHex := hex.EncodeToString(descHash[:])

	originalDecode := DecodeBolt11
	defer func() { DecodeBolt11 = originalDecode }()
	DecodeBolt11 = func(bolt11 string) (*Invoice, error) {
		return &Invoice{AmountMloki: 1000, DescriptionHash: descHashHex}, nil
	}

	preimage := "abc123"
	receipt := NewZapReceipt(ZapReceiptParams{
		ProviderPubkey: "provider1",
		Recipient:      recipient,
		Bolt11:         "lnfc1...",
		Description:    string(descBytes),
		Preimage:       &preimage,
	})
	if receipt.Kind != KindZapReceipt {
		t.Fatalf("expected kind %d, got %d", KindZapReceipt, receipt.Kind)
	}
	if err := receipt.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("failed to sign receipt: %v", err)
	}

	if err := ValidateZapReceipt(receipt); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Description hash mismatch.
	DecodeBolt11 = func(bolt11 string) (*Invoice, error) {
		return &Invoice{AmountMloki: 1000, DescriptionHash: "wrong"}, nil
	}
	if err := ValidateZapReceipt(receipt); err == nil {
		t.Fatal("expected description hash mismatch error")
	}

	// Amount mismatch.
	DecodeBolt11 = func(bolt11 string) (*Invoice, error) {
		return &Invoice{AmountMloki: 42, DescriptionHash: descHashHex}, nil
	}
	if err := ValidateZapReceipt(receipt); err == nil {
		t.Fatal("expected amount mismatch error")
	}
}
