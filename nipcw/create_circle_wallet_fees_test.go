package nipcw

import "testing"

// NIP-CW §Response: every term of the issued wallet travels inside
// encrypted_details, fees_ppm included. Built from the wire text, so dropping the
// field from the parse (a past bug) turns this red.
func TestCreateCircleWalletParams_ParseResult_KeepsFeesPpm(t *testing.T) {
	memberPriv, memberPub := generateTestKeypair(t)
	hubPriv, hubPub := generateTestKeypair(t)
	details := `{"wallet_pubkey":"` + testWalletPubkey + `","relays":["wss://r"],"expires_at":1,"fees_ppm":2500,"budget_renewal":"never"}`
	p := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: newTestConnectionKey(t)}
	resp, err := p.ParseResult(hubPub, hubReply(t, hubPriv, memberPub, details))
	if err != nil {
		t.Fatal(err)
	}
	if resp.FeesPpm != 2500 {
		t.Fatalf("FeesPpm = %d, want 2500", resp.FeesPpm)
	}
}
