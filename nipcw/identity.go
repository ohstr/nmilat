package nipcw

import (
	"encoding/json"
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Credential proves a member's own control of the pubkey requesting a
// Circle Wallet. Unlike NIP-CASH, NIP-CW has only one identity mode — a
// Circle Wallet member is always a raw Nostr pubkey (NIP-CW §Identity
// Proof) — so there is no BySecret/BySigningConnectionKey split here, just
// BySigning.
type Credential struct {
	privKeyHex string
}

// BySigning proves control of pubkey by signing a fresh kind-23199 identity
// proof internally — the caller supplies a key, never builds or signs an
// event themselves.
func BySigning(privKeyHex string) Credential {
	return Credential{privKeyHex: privKeyHex}
}

// pubkey derives the caller's own pubkey from the credential's private key
// — both the wire request's "pubkey" field and the proof's own signer.
func (c Credential) pubkey() (string, error) {
	return utils.GetPublicKey(c.privKeyHex)
}

// buildProof signs a kind-23199 identity proof bound to hubPubkey (the
// Circle Wallet Hub's own pubkey via the proof's d-tag — NIP-CW §Identity
// Proof: "binds proof to THIS Hub; no invoice to bind it to").
func (c Credential) buildProof(hubPubkey string) ([]byte, error) {
	ev, err := nip01.NewSignedEvent(KindCircleIdentityProof, "", c.privKeyHex, []string{"d", hubPubkey})
	if err != nil {
		return nil, fmt.Errorf("nipcw: sign identity proof: %w", err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("nipcw: marshal identity proof: %w", err)
	}
	return raw, nil
}
