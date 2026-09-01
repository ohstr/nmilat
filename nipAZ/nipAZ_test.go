package nipAZ

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
)

// Mock helpers
func mockEvent(kind int, tags [][]string, content string) *nip01.Event {
	return &nip01.Event{
		Kind:      kind,
		Tags:      tags,
		Content:   content,
		CreatedAt: uint64(time.Now().Unix()),
		PubKey:    "pubkey",
		ID:        "mock-id",
		Sig:       "mock-sig",
	}
}

func TestParseAltZapRequest(t *testing.T) {
	validPubkey := "0000000000000000000000000000000000000000000000000000000000000001"

	tests := []struct {
		name    string
		event   *nip01.Event
		wantErr bool
	}{
		{
			name: "Valid Request",
			event: mockEvent(KindAltZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"amount", "1000"},
				{"chain", "flokicoin"},
				{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
			}, ""),
			wantErr: false,
		},
		{
			name: "Invalid Kind",
			event: mockEvent(1, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
			}, ""),
			wantErr: true,
		},
		{
			name: "Valid 5522 Direct Payment Request",
			event: mockEvent(KindAltZapDirectPayment, [][]string{
				{"relays", "wss://relay.com"},
				{"amount", "1000"},
				{"chain", "flokicoin"},
				{"bolt11", "lnfc1..."},
			}, ""),
			wantErr: false,
		},
		{
			name: "Invalid 5522 Direct Payment Request (has p tag)",
			event: mockEvent(KindAltZapDirectPayment, [][]string{
				{"relays", "wss://relay.com"},
				{"amount", "1000"},
				{"chain", "flokicoin"},
				{"bolt11", "lnfc1..."},
				{"p", validPubkey},
			}, ""),
			wantErr: true,
		},
		{
			name: "Valid 5523 On-Behalf Request",
			event: mockEvent(KindAltZapOnBehalfRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"P", validPubkey},
				{"amount", "1000"},
				{"chain", "flokicoin"},
				{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
			}, ""),
			wantErr: false,
		},
		{
			name: "Invalid 5523 On-Behalf Request (missing P tag)",
			event: mockEvent(KindAltZapOnBehalfRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"amount", "1000"},
				{"chain", "flokicoin"},
				{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Missing Relays",
			event: mockEvent(KindAltZapRequest, [][]string{
				{"p", validPubkey},
				{"amount", "1000"},
				{"chain", "flokicoin"},
				{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
			}, ""),
			wantErr: true, // Relays are mandatory
		},
		{
			name: "Missing Chain",
			event: mockEvent(KindAltZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"amount", "1000"},
				{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Multiple P tags (recipient)",
			event: mockEvent(KindAltZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"p", validPubkey},
				{"amount", "1000"},
				{"chain", "flokicoin"},
				{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Invalid Amount",
			event: mockEvent(KindAltZapRequest, [][]string{
				{"relays", "wss://relay.com"},
				{"p", validPubkey},
				{"amount", "-100"},
				{"chain", "flokicoin"},
				{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Invalid Relay URL",
			event: mockEvent(KindAltZapRequest, [][]string{
				{"relays", "httpx://invalid-scheme.com"},
				{"p", validPubkey},
			}, ""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAltZapRequest(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAltZapRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseAltZapReceipt(t *testing.T) {
	validPubkey := "0000000000000000000000000000000000000000000000000000000000000001"

	// Use a real key to produce a validly signed zap request
	testPrivKey := "0000000000000000000000000000000000000000000000000000000000000001"

	// Create and properly sign an embedded zap request
	signedZapReq := &nip01.Event{
		Kind:      KindAltZapRequest,
		CreatedAt: uint64(time.Now().Unix()),
		PubKey:    validPubkey,
		Content:   "",
		Tags: [][]string{
			{"relays", "wss://relay.com"},
			{"p", validPubkey},
			{"amount", "1000"},
			{"chain", "flokicoin"},
			{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
		},
	}
	if err := signedZapReq.Sign(testPrivKey); err != nil {
		t.Fatalf("Failed to sign zap request: %v", err)
	}
	signedZapReqJSON, _ := json.Marshal(signedZapReq)

	// Create an unsigned/forged zap request for the invalid sig test
	forgedZapReq := mockEvent(KindAltZapRequest, [][]string{
		{"relays", "wss://relay.com"},
		{"p", validPubkey},
		{"amount", "1000"},
		{"chain", "flokicoin"},
		{"lnurl", "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"},
	}, "")
	forgedZapReqJSON, _ := json.Marshal(forgedZapReq)

	tests := []struct {
		name    string
		event   *nip01.Event
		wantErr bool
		check   func(*AltZapReceipt) error
	}{
		{
			name: "Valid Receipt with Description",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"chain", "flokicoin"},
				{"preimage", "0000000000000000000000000000000000000000000000000000000000000000"},
				{"description", string(signedZapReqJSON)},
			}, ""),
			wantErr: false,
			check: func(zr *AltZapReceipt) error {
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
			name: "Parse Receipt WITHOUT Description (Request is nil)",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"chain", "flokicoin"},
				{"preimage", "0000000000000000000000000000000000000000000000000000000000000000"},
			}, ""),
			wantErr: false,
			check: func(zr *AltZapReceipt) error {
				if zr.Request != nil {
					return fmt.Errorf("expected no embedded request")
				}
				if zr.Description != "" {
					return fmt.Errorf("expected empty description")
				}
				return nil
			},
		},
		{
			name: "Kind 5522 Anonymous Direct Payment Receipt",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"bolt11", "lnfc1..."},
				{"chain", "flokicoin"},
				{"preimage", "0000000000000000000000000000000000000000000000000000000000000000"},
			}, ""),
			wantErr: false,
			check: func(zr *AltZapReceipt) error {
				if zr.Recipient != "" {
					return fmt.Errorf("expected empty recipient")
				}
				return nil
			},
		},
		{
			name: "Missing Preimage",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"chain", "flokicoin"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Missing Chain",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"preimage", "0000000000000000000000000000000000000000000000000000000000000000"},
			}, ""),
			wantErr: true,
		},
		{
			name:    "Invalid Kind",
			event:   mockEvent(KindAltZapRequest, [][]string{}, ""), // Wrong kind
			wantErr: true,
		},
		{
			name: "Missing P tag with Description Present",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"bolt11", "lnfc1..."},
				{"chain", "flokicoin"},
				{"preimage", "1122"},
				{"description", "{}"}, // Missing p while description is present
			}, ""),
			wantErr: true,
		},
		{
			name: "Missing Bolt11",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"p", validPubkey},
				{"chain", "flokicoin"},
				{"preimage", "1122"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Invalid Description JSON",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"chain", "flokicoin"},
				{"preimage", "1122"},
				{"description", "{invalid-json"},
			}, ""),
			wantErr: true,
		},
		{
			name: "Forged Zap Request Signature",
			event: mockEvent(KindAltZapReceipt, [][]string{
				{"p", validPubkey},
				{"bolt11", "lnfc1..."},
				{"chain", "flokicoin"},
				{"preimage", "1122"},
				{"description", string(forgedZapReqJSON)},
			}, ""),
			wantErr: true, // Must reject forged sender identity
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zr, err := ParseAltZapReceipt(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAltZapReceipt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil {
				if err := tt.check(zr); err != nil {
					t.Errorf("Check failed: %v", err)
				}
			}
		})
	}
}

func TestNewAltZapReceipt(t *testing.T) {
	// Mock nip57.DecodeBolt11
	originalDecode := nip57.DecodeBolt11
	defer func() { nip57.DecodeBolt11 = originalDecode }()

	nip57.DecodeBolt11 = func(bolt11 string) (*nip57.Invoice, error) {
		if bolt11 == "bad_invoice" {
			return nil, fmt.Errorf("decode failed")
		}
		return &nip57.Invoice{
			AmountMloki: 123456,
		}, nil
	}

	tests := []struct {
		name       string
		bolt11     string
		desc       string
		wantErr    bool
		wantAmount string
	}{
		{
			name:       "Valid Receipt",
			bolt11:     "lnfc1...",
			desc:       "{}",
			wantErr:    false,
			wantAmount: "123456",
		},
		{
			name:       "Invalid nip57.Invoice",
			bolt11:     "bad_invoice",
			desc:       "{}",
			wantErr:    true,
			wantAmount: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var preimage = "1122"
			got, err := NewAltZapReceipt(AltZapReceiptParams{
				Chain:           "flokicoin",
				ProviderPubkey:  "provider",
				RecipientPubkey: "recipient",
				SenderPubkey:    "sender",
				Bolt11:          tt.bolt11,
				Description:     tt.desc,
				Preimage:        &preimage,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAltZapReceipt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Check for amount tag
				amountFound := false
				for _, tag := range got.Tags {
					if len(tag) >= 2 && tag[0] == "amount" {
						if tag[1] == tt.wantAmount {
							amountFound = true
						} else {
							t.Errorf("NewAltZapReceipt() amount = %v, want %v", tag[1], tt.wantAmount)
						}
					}
				}
				if !amountFound {
					t.Errorf("NewAltZapReceipt() missing amount tag")
				}
			}
		})
	}
}
