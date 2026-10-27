package nipCZ

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipIC"
)

func keypairFor(t *testing.T) (priv, pub string) { return cashtest.Keypair(t) }

// attestation is a 35522 by the IA at iaPriv for userID on platform.
func attestation(t *testing.T, iaPriv, user string, platform nipIC.WebIdentity, userID string) *nipIC.Attestation {
	t.Helper()
	key, err := nipIC.ConnectionKeyFromAttested(platform, userID)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := nipIC.NewAttestation(nipIC.AttestationParams{
		PrivateKey: iaPriv, ConnectionKey: key, UserPubkey: user, Platform: platform, AuthType: "oauth",
		Evidence: nipIC.Evidence{Version: 1, Platform: platform, AuthType: "oauth", UserID: userID, VerifiedAt: time.Now().Unix()},
	})
	if err != nil {
		t.Fatal(err)
	}
	att, err := nipIC.ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	return att
}
