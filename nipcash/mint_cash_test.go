package nipcash

import (
	"testing"
	"time"
)

func TestMintCashParams_Request_HappyPath(t *testing.T) {
	p := MintCashParams{RequestID: testRID,
		Recipients: []Allocation{
			Send(Pubkey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 10_000_000),
			Send(attestedKey(t, "discord", "2004", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), 5_000_000),
		},
		Expiry: 24 * time.Hour,
	}
	req, err := p.Request()
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if len(req.Recipients) != 2 {
		t.Fatalf("Recipients: got %d, want 2", len(req.Recipients))
	}
	if req.Recipients[0].IdentityType != identityTypePubkey || req.Recipients[0].AmountMillis != 10_000_000 {
		t.Fatalf("recipient 0: %+v", req.Recipients[0])
	}
	if req.Recipients[1].IdentityType != identityTypeConnectionKey || req.Recipients[1].IAPubkey != "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		t.Fatalf("recipient 1: %+v", req.Recipients[1])
	}
	if req.Expiry != 86400 {
		t.Fatalf("Expiry: got %d, want 86400", req.Expiry)
	}
}

func TestMintCashParams_Request_ZeroExpiry(t *testing.T) {
	p := MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(Pubkey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 1000)}}
	req, err := p.Request()
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.Expiry != 0 {
		t.Fatalf("Expiry: got %d, want 0 (hub default)", req.Expiry)
	}
}

func TestMintCashParams_Request_SingleCashAllowed(t *testing.T) {
	p := MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(mustCashTarget(t), 3000)}}
	req, err := p.Request()
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.Recipients[0].IdentityType != identityTypeCash {
		t.Fatalf("got %s, want cash", req.Recipients[0].IdentityType)
	}
}

func TestMintCashParams_Request_MixedCashRejected(t *testing.T) {
	p := MintCashParams{RequestID: testRID, Recipients: []Allocation{
		Send(mustCashTarget(t), 1000),
		Send(Pubkey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 1000),
	}}
	if _, err := p.Request(); err != ErrMixedCashAllocation {
		t.Fatalf("got %v, want ErrMixedCashAllocation", err)
	}
}
