package nipcw

import (
	"encoding/hex"
	"fmt"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Credential proves a member's own control of the pubkey requesting a
// Circle Wallet. A Circle Wallet member is always a raw Nostr pubkey (NIP-CW
// §Identity Proof), so there is only BySigning.
type Credential struct {
	privKeyHex string
}

// BySigning proves control of the key's pubkey by signing fresh kind-23199
// proofs internally; the caller never builds or signs an event themselves.
func BySigning(privKeyHex string) Credential {
	return Credential{privKeyHex: privKeyHex}
}

// pubkey derives the caller's own pubkey: the request's pubkey and the proof's
// signer.
func (c Credential) pubkey() (string, error) {
	return utils.GetPublicKey(c.privKeyHex)
}

// Pubkey is the pubkey this credential signs for (x-only hex).
func (c Credential) Pubkey() (string, error) { return c.pubkey() }

// signProof signs a kind-23199 event with the given tags at createdAt.
func (c Credential) signProof(createdAt int64, tags ...[]string) (*nip01.Event, error) {
	if createdAt < 0 {
		return nil, fmt.Errorf("nipcw: created_at %d is negative", createdAt)
	}
	ev := nip01.NewEvent(KindCircleIdentityProof, "", tags...)
	ev.CreatedAt = uint64(createdAt)
	if err := ev.Sign(c.privKeyHex); err != nil {
		return nil, fmt.Errorf("nipcw: sign kind-23199 event: %w", err)
	}
	return ev, nil
}

// isLowerHex64 reports 64 lowercase hex characters.
func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validXOnly reports 64 lowercase hex naming a point on the curve.
func validXOnly(s string) bool {
	if !isLowerHex64(s) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, err := schnorr.ParsePubKey(b)
	return err == nil
}

// tagValues returns the values of every tag named name, "" for a tag without one.
func tagValues(ev *nip01.Event, name string) []string {
	var out []string
	for _, t := range ev.Tags {
		if len(t) == 0 || t[0] != name {
			continue
		}
		v := ""
		if len(t) > 1 {
			v = t[1]
		}
		out = append(out, v)
	}
	return out
}

// oneTag returns the value of the only tag named name.
func oneTag(ev *nip01.Event, name string) (string, bool) {
	vs := tagValues(ev, name)
	if len(vs) != 1 {
		return "", false
	}
	return vs[0], true
}
