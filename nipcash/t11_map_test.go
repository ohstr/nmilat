package nipcash

import "testing"

// T11-58 (the RedeemProgressOf half): a cash_status read after a redeem whose
// answer was lost: an unclaimed own row is released, a claimed one in flight, a
// tombstone done.
func TestT11_58_RedeemProgressOf(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  *RecipientStatus
		tomb *Tombstone
		want RedeemProgress
	}{
		{"unclaimed", &RecipientStatus{}, nil, RedeemReleased},
		{"claimed", &RecipientStatus{Claimed: true}, nil, RedeemInFlight},
		{"tombstone", nil, &Tombstone{Reason: ReasonRedeemed}, RedeemDone},
		{"tombstone wins over a row", &RecipientStatus{Claimed: true}, &Tombstone{Reason: ReasonRedeemed}, RedeemDone},
	} {
		if got := RedeemProgressOf(tc.row, tc.tomb); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
