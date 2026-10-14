package nipcw

import (
	"encoding/json"
	"testing"
)

// NIP-CW §Response: every term of the issued wallet travels inside
// encrypted_details, fees_ppm included. Built from the wire text, so dropping the
// field from the parse (a past bug) turns this red.
func TestCreateCircleWalletParams_ParseResult_KeepsFeesPpm(t *testing.T) {
	memberPriv, memberPub := generateTestKeypair(t)
	hubPriv, hubPub := generateTestKeypair(t)
	details := `{"pairing_uri":"` + testPairingURI + `","wallet_pubkey":"w","expires_at":1,"fees_ppm":2500,"budget_renewal":"never"}`
	raw, err := json.Marshal(createCircleWalletResponseWire{EncryptedDetails: encryptForTest(t, hubPriv, memberPub, details)})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := CreateCircleWalletParams{Credential: BySigning(memberPriv)}.ParseResult(hubPub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp.FeesPpm != 2500 {
		t.Fatalf("FeesPpm = %d, want 2500", resp.FeesPpm)
	}
}
