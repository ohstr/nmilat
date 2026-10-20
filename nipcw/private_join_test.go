package nipcw

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// NIP-CW §Private Join: the item targets the Hub, its item proof is signed by
// the requester, its bill proof by the Hub connection secret, and both bind
// d = Hub pubkey, h = node identity.
func TestCreateCircleWalletParams_Item(t *testing.T) {
	memberPriv, memberPub := generateTestKeypair(t)
	hubSecret, hubPub := generateTestKeypair(t)
	_, node := generateTestKeypair(t)
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b := nipcash.ItemBinding{HubXOnly: node, Nonce: nonce, NotAfter: now.Add(time.Minute).Unix()}

	p := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: newTestConnectionKey(t), MaxAmountMillis: 1000}
	item, err := p.Item("join", hubPub, hubSecret, b)
	if err != nil {
		t.Fatalf("Item: %v", err)
	}
	if item.Target != hubPub || item.Method != MethodCreateCircleWallet {
		t.Fatalf("item targets %q with %q, want the Hub with %q", item.Target, item.Method, MethodCreateCircleWallet)
	}

	var req CreateCircleWalletRequest
	if err := json.Unmarshal(item.Params, &req); err != nil {
		t.Fatal(err)
	}
	if req.Pubkey != memberPub || req.IdentityEvent == "" {
		t.Fatalf("params %+v: want the standard request with its identity proof", req)
	}

	hash, err := transport.CanonicalParamsHash(item.Params)
	if err != nil {
		t.Fatal(err)
	}
	want := transport.ProofBinding{
		Target: hubPub, HubXOnly: node, Method: MethodCreateCircleWallet,
		ParamsHash: hash, Nonce: nonce, NotAfter: b.NotAfter,
	}
	signer, err := transport.VerifyItemProof(item.Proof, want, now)
	if err != nil {
		t.Fatalf("item proof: %v", err)
	}
	if signer != memberPub {
		t.Fatalf("item proof signed by %s, want the requester %s", signer, memberPub)
	}
	billSigner, err := transport.VerifyBillProof(item.BillProof, want, now)
	if err != nil {
		t.Fatalf("bill proof: %v", err)
	}
	connPub, err := utils.GetPublicKey(hubSecret)
	if err != nil {
		t.Fatal(err)
	}
	if billSigner != connPub {
		t.Fatalf("bill proof signed by %s, want the Hub connection secret's key %s", billSigner, connPub)
	}
}

func TestCreateCircleWalletParams_Item_NeedsHubSecret(t *testing.T) {
	memberPriv, _ := generateTestKeypair(t)
	_, hubPub := generateTestKeypair(t)
	_, node := generateTestKeypair(t)
	p := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: newTestConnectionKey(t)}
	if _, err := p.Item("join", hubPub, "", nipcash.ItemBinding{HubXOnly: node, Nonce: "n"}); err == nil {
		t.Fatal("a join without the Hub connection secret has no bill proof and must be refused")
	}
}

// NIP-CW §Response: on either transport the details are encrypted from the Hub
// connection key. A private-join reply arrives via the inbox, so details
// encrypted from the inbox key, or from anyone else, must not be accepted.
func TestCreateCircleWalletParams_ParseResult_RejectsOtherSender(t *testing.T) {
	memberPriv, memberPub := generateTestKeypair(t)
	_, hubPub := generateTestKeypair(t)
	inboxPriv, _ := generateTestKeypair(t)

	raw := hubReply(t, inboxPriv, memberPub, `{"wallet_pubkey":"`+testWalletPubkey+`","relays":["wss://r"]}`)
	p := CreateCircleWalletParams{Credential: BySigning(memberPriv), Connection: newTestConnectionKey(t)}
	if _, err := p.ParseResult(hubPub, raw); err == nil {
		t.Fatal("details encrypted from a key other than the Hub connection key were accepted")
	}
}
