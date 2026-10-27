package nipcw

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/utils"
)

func randomKeyHex(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func generateTestKeypair(t *testing.T) (privKeyHex, pubKeyHex string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privKeyHex = hex.EncodeToString(priv.Serialize())
	pubKeyHex, err = utils.GetPublicKey(privKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return privKeyHex, pubKeyHex
}

func newTestConnectionKey(t *testing.T) ConnectionKey {
	t.Helper()
	k, err := NewConnectionKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// testWalletPubkey is a well-formed wallet pubkey for details built by hand.
var testWalletPubkey = strings.Repeat("ab", 32)

// hubReply encrypts details (wire JSON) from fromPriv to the member and wraps
// them in the one-field result.
func hubReply(t *testing.T, fromPriv, memberPub, details string) []byte {
	t.Helper()
	key, err := conversationKey(fromPriv, memberPub)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := nip44.Encrypt(details, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(createCircleWalletResponseWire{EncryptedDetails: ct})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
