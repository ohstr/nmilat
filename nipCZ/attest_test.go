package nipCZ

import (
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
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

// IdentityFromAttestation takes d only when it is the ConnectionKey of the
// attestation's platform and evidence user id, as nipcash does.
func TestIdentityFromAttestation_DIsTheUserIDsKey(t *testing.T) {
	iaPriv, _ := keypairFor(t)
	_, user := keypairFor(t)
	good := attestation(t, iaPriv, user, "github", "alice")
	if id, _, err := IdentityFromAttestation(good); err != nil || id.Value != string(good.ConnectionKey) {
		t.Fatalf("matching d: %+v %v", id, err)
	}
	other, _ := nipIC.ConnectionKeyFromAttested("github", "bob")
	ev := good.Copy()
	for _, tag := range ev.Tags {
		if tag[0] == nipIC.TagDTag {
			tag[1] = string(other)
		}
	}
	if err := ev.Sign(iaPriv); err != nil {
		t.Fatal(err)
	}
	rekeyed, err := nipIC.ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := IdentityFromAttestation(rekeyed); !errors.Is(err, nipcash.ErrAttestationKey) {
		t.Fatalf("d of another user id: %v", err)
	}
}
