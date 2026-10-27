package nipcash

import (
	"encoding/json"
	"strings"
	"testing"
)

// A Hub encodes a mint reply with cash_token and omits expires_at for a bill
// that never expires; a client reads absent, null and 0 alike as never.
func TestMintCashResult_HubEncoding(t *testing.T) {
	r := MintCashResult{WalletPubkey: strings.Repeat("ab", 32), CashToken: "satscash1x"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"wallet_pubkey":"`+strings.Repeat("ab", 32)+`","cash_token":"satscash1x","recipients":[]}` {
		t.Fatalf("encoded %s", got)
	}
	r.ExpiresAt = Expiry{At: 1800000000, Present: true}
	r.TokenTombstone, r.CashToken = &Tombstone{Status: StatusSpent, Reason: ReasonRedeemed}, ""
	b, _ = json.Marshal(r)
	if !strings.Contains(string(b), `"expires_at":1800000000`) || !strings.Contains(string(b), `"cash_token":{"status":"spent"`) {
		t.Fatalf("encoded %s", b)
	}
	var back MintCashResult
	if err := json.Unmarshal(b, &back); err != nil || back.TokenTombstone == nil || back.ExpiresAt.At != 1800000000 {
		t.Fatalf("round trip %+v %v", back, err)
	}
	for _, in := range []string{`{}`, `{"expires_at":null}`, `{"expires_at":0}`} {
		var s RecipientStatus
		if err := json.Unmarshal([]byte(in), &s); err != nil || !s.ExpiresAt.Never() {
			t.Errorf("%s: %+v %v", in, s.ExpiresAt, err)
		}
	}
	if b, _ := json.Marshal(RecipientStatus{}); strings.Contains(string(b), "expires_at") {
		t.Errorf("a never-expiring status row writes expires_at: %s", b)
	}
}
