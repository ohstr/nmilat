package nipcash

import "testing"

// NIP-CASH §Minting Cash: identity_type MUST be pubkey, connection_key or cash.
// Compared with literals, not the package's own constants, so renaming a wire
// value turns this red. The constructors are sealed, so no other type can be sent.
func TestMintCashParams_Request_IdentityTypeLiterals(t *testing.T) {
	for want, r := range map[string]Recipient{
		"pubkey":         Pubkey(randomKeyHex(t)),
		"connection_key": attestedKey(t, "discord", "u", randomKeyHex(t)),
		"cash":           mustCashTarget(t),
	} {
		req, err := MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(r, 1000)}}.Request()
		if err != nil {
			t.Fatalf("%s: %v", want, err)
		}
		if got := req.Recipients[0].IdentityType; got != want {
			t.Errorf("identity_type = %q, want %q", got, want)
		}
	}
}
