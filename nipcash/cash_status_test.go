package nipcash

import (
	"errors"
	"strings"
	"testing"
)

// A roster and a tombstone are told apart by ParseCashStatusResult; an empty or
// unknown answer is never read as spent.
func TestParseCashStatusResult_RosterOrTombstone(t *testing.T) {
	roster, err := ParseCashStatusResult([]byte(`{"recipients":[{"identity_type":"pubkey","identity_value":"` + strings.Repeat("a", 64) + `","amount_millis":1000}]}`))
	if err != nil || roster.Tombstone != nil || len(roster.Recipients) != 1 {
		t.Fatalf("roster: %+v %v", roster, err)
	}
	tomb, err := ParseCashStatusResult([]byte(`{"status":"spent","reason":"redeemed","retained_until":1758800000}`))
	if err != nil || tomb.Tombstone == nil || *tomb.Tombstone.RetainedUntil != 1758800000 {
		t.Fatalf("tombstone: %+v %v", tomb, err)
	}
	for _, raw := range []string{`{}`, `{"error":"spent"}`, `{"status":"something_new"}`} {
		r, err := ParseCashStatusResult([]byte(raw))
		if err == nil && r.Tombstone != nil {
			t.Errorf("%s read as spent", raw)
		}
	}
}

// T10-20: rows of an unknown type, or with uppercase values, are malformed;
// expires_at absent, null or 0 is never.
func TestParseCashStatusResult_Rows(t *testing.T) {
	hex := strings.Repeat("a", 64)
	for _, raw := range []string{
		`{"recipients":[{"identity_type":"bearer","identity_value":"` + hex + `","amount_millis":1}]}`,
		`{"recipients":[{"identity_type":"pubkey","identity_value":"` + strings.ToUpper(hex) + `","amount_millis":1}]}`,
		`{"recipients":[{"identity_type":"connection_key","identity_value":"` + hex + `","amount_millis":1}]}`,
	} {
		if _, err := ParseCashStatusResult([]byte(raw)); !errors.Is(err, ErrStatusMalformed) {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for _, exp := range []string{``, `,"expires_at":null`, `,"expires_at":0`} {
		r, err := ParseCashStatusResult([]byte(`{"recipients":[{"identity_type":"pubkey","identity_value":"` + hex +
			`","amount_millis":1,"claimed":true,"claimed_at":5,"redeem_fee_millis":1,"net_redeemable_millis":0,"min_transfer_millis":1000` + exp + `}]}`))
		if err != nil || !r.Recipients[0].ExpiresAt.Never() || *r.Recipients[0].ClaimedAt != 5 || r.Recipients[0].MinTransferMillis != 1000 {
			t.Errorf("expires_at %q: %+v %v", exp, r, err)
		}
	}
}
