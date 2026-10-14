package nipcash

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// NIP-CASH §Bill Proofs: every item's bill proof MUST be signed with the bill's
// own connection secret. The client e2e fake hub never verifies bill proofs, so
// without this a proof signed by any other key passed the whole suite.
func TestItem_BillProofIsSignedByTheConnectionSecret(t *testing.T) {
	_, pub := itemTestKeypair(t)
	b := ItemBinding{HubXOnly: pub, Nonce: strings.Repeat("11", 32), NotAfter: time.Now().Add(time.Minute).Unix()}
	secret := connSecretFor(pub)
	item, err := StatusItem("s1", pub, secret, CashStatusParams{Scope: ScopeMine}, BySecret("the-secret"), b)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := transport.CanonicalParamsHash(item.Params)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := transport.VerifyBillProof(item.BillProof, transport.ProofBinding{
		Target: pub, HubXOnly: pub, Method: item.Method, ParamsHash: hash, Nonce: b.Nonce, NotAfter: b.NotAfter,
	}, time.Now())
	if err != nil {
		t.Fatalf("VerifyBillProof: %v", err)
	}
	raw, err := hex.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := btcec.PrivKeyFromBytes(raw)
	if want := hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey())); signer != want {
		t.Errorf("bill proof signed by %s, want the connection secret's pubkey %s", signer, want)
	}
}
