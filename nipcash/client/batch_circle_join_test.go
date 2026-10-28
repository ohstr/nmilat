package client

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

// TestCreateCircleWalletMany_EndToEnd: two joins in one envelope to a Hub that
// checks both proofs the way NIP-CW §Private Join says, admits one and refuses the
// other. The admitted join's details are encrypted from the Hub connection key and
// must decrypt; the refusal must keep its code.
func TestCreateCircleWalletMany_EndToEnd(t *testing.T) {
	hubWalletPriv, hubWalletPub := sessionKeypair(t)
	hubSecret, _ := sessionKeypair(t)
	hubSecretPub, err := utils.GetPublicKey(hubSecret)
	if err != nil {
		t.Fatal(err)
	}
	memberPriv, memberPub := sessionKeypair(t)
	strangerPriv, _ := sessionKeypair(t)

	var hub *fakeHub
	hub = newTestHub(t, func(item transport.Item) *transport.Result {
		var req nipcw.CreateCircleWalletRequest
		if err := json.Unmarshal(item.Params, &req); err != nil {
			return nil
		}
		hash, err := transport.CanonicalParamsHash(item.Params)
		if err != nil {
			return nil
		}
		env := hub.envelopes()
		want := transport.ProofBinding{
			Target: hubWalletPub, HubXOnly: hub.hubXOnly, Method: nipcw.MethodCreateCircleWallet,
			ParamsHash: hash, Nonce: env[len(env)-1].Nonce, NotAfter: env[len(env)-1].NotAfter,
		}
		if item.Target != hubWalletPub {
			return nil
		}
		if signer, err := transport.VerifyItemProof(item.Proof, want, time.Now()); err != nil || signer != req.Pubkey {
			return nil
		}
		if signer, err := transport.VerifyBillProof(item.BillProof, want, time.Now()); err != nil || signer != hubSecretPub {
			return nil
		}
		if req.Pubkey != memberPub {
			return &transport.Result{ID: item.ID, Error: &transport.ResultError{Code: nipcw.ErrRestricted}}
		}
		details := `{"wallet_pubkey":"` + strings.Repeat("ab", 32) + `","connection_pubkey":"` + req.ConnectionPubkey +
			`","relays":["wss://w"],"max_amount":1000,"max_receive":0,"expires_at":1,"fees_ppm":0,"dust_threshold_millis":0,"budget_renewal":"never"}`
		body, _ := json.Marshal(map[string]string{"encrypted_details": encryptFrom(t, hubWalletPriv, req.Pubkey, details)})
		return &transport.Result{ID: item.ID, ResultType: item.Method, Result: body}
	})
	relay := startFakeHub(t, hub)

	ctx, cancel := e2eContext(t)
	defer cancel()
	s, err := OpenBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("OpenBatchSession: %v", err)
	}

	hubConn, err := BillFromParts(hubWalletPub, hubSecret)
	if err != nil {
		t.Fatal(err)
	}
	join := func(id, priv string) BatchCircleJoin {
		key, err := nipcw.NewConnectionKey()
		if err != nil {
			t.Fatal(err)
		}
		j, err := nipcw.CreateCircleWalletParams{
			Credential: nipcw.BySigning(priv), Connection: key, MaxAmountMillis: 1000,
		}.Prepare(hubWalletPub, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return BatchCircleJoin{ID: id, Hub: hubConn, Join: j}
	}
	outcomes, err := s.CreateCircleWalletMany(ctx, []BatchCircleJoin{join("member", memberPriv), join("stranger", strangerPriv)})
	if err != nil {
		t.Fatalf("CreateCircleWalletMany: %v", err)
	}
	if len(outcomes) != 2 {
		t.Fatalf("got %d outcomes, want 2", len(outcomes))
	}
	if o := outcomes[0]; !o.Succeeded() || o.Result == nil || o.Result.WalletPubkey != strings.Repeat("ab", 32) || o.Result.MissingTerms != nil {
		t.Fatalf("member: state %v, result %+v, error %+v", o.State, o.Result, o.Error)
	}
	if o := outcomes[1]; o.State != OutcomeError || o.Error == nil || o.Error.Code != nipcw.ErrRestricted {
		t.Fatalf("stranger: state %v, error %+v; want %s", o.State, o.Error, nipcw.ErrRestricted)
	}
	if got := len(hub.envelopes()); got != 1 {
		t.Fatalf("hub received %d envelopes, want 1", got)
	}
}

// encryptFrom is NIP-44 from fromPriv to toPub, as a Hub encrypts encrypted_details.
func encryptFrom(t *testing.T, fromPriv, toPub, plaintext string) string {
	t.Helper()
	privBytes, err := hex.DecodeString(fromPriv)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(toPub)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := nip44.Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}
