package nipcw

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// NIP-CW §Identity Proof: the kind-23199 event's signer MUST equal the request's
// pubkey, its id MUST match its content, and it is kind 23199 (not NIP-CASH's
// 23198). A Hub fails closed on any of these, so a broken builder shows up only
// as refused joins; pinned here instead.
func TestCreateCircleWalletParams_Request_IdentityProof(t *testing.T) {
	memberPriv, memberPub := generateTestKeypair(t)
	_, hubPub := generateTestKeypair(t)
	req, err := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: newTestConnectionKey(t), MaxAmountMillis: 1000}.Request(hubPub)
	if err != nil {
		t.Fatal(err)
	}
	var ev nip01.Event
	if err := json.Unmarshal([]byte(req.IdentityEvent), &ev); err != nil {
		t.Fatalf("identity_event is not an event: %v", err)
	}
	if ev.Kind != 23199 {
		t.Errorf("kind = %d, want 23199", ev.Kind)
	}
	if ev.PubKey != req.Pubkey || req.Pubkey != memberPub {
		t.Errorf("signer %s, request pubkey %s, member %s: all must match", ev.PubKey, req.Pubkey, memberPub)
	}
	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		t.Errorf("identity_event does not verify (id or signature): %v", err)
	}
}
