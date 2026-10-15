package nipcw

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

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

// hubReply encrypts details (wire JSON) to the member as the Hub would, and
// wraps them in the one-field response.
func hubReply(t *testing.T, hubPriv, memberPub, details string) []byte {
	t.Helper()
	raw, err := json.Marshal(createCircleWalletResponseWire{EncryptedDetails: encryptForTest(t, hubPriv, memberPub, details)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCreateCircleWalletParams_Request(t *testing.T) {
	privKeyHex, pubKeyHex := generateTestKeypair(t)
	hubPubkey := randomKeyHex(t)
	conn := newTestConnectionKey(t)
	p := CreateCircleWalletParams{
		Credential:      BySigning(privKeyHex),
		Connection:      conn,
		MaxAmountMillis: 100_000,
		Expiry:          30 * 24 * time.Hour,
		BudgetRenewal:   "monthly",
	}
	req, err := p.Request(hubPubkey)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.Pubkey != pubKeyHex {
		t.Fatalf("Pubkey: got %s, want %s", req.Pubkey, pubKeyHex)
	}
	if req.ConnectionPubkey != conn.Pubkey() {
		t.Fatalf("ConnectionPubkey: got %s, want %s", req.ConnectionPubkey, conn.Pubkey())
	}
	if req.MaxAmount != 100_000 {
		t.Fatalf("MaxAmount: got %d", req.MaxAmount)
	}
	if req.Expiry != 30*24*3600 {
		t.Fatalf("Expiry: got %d", req.Expiry)
	}
	if req.BudgetRenewal != "monthly" {
		t.Fatalf("BudgetRenewal: got %s", req.BudgetRenewal)
	}

	// The secret never leaves: nowhere in the wire request.
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), conn.Secret()) {
		t.Fatal("the connection secret appears in the request")
	}

	// NIP-CW §Identity Proof: the proof binds the Hub (d) and the connection key
	// (connection), each exactly once.
	var ev struct {
		Tags [][]string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(req.IdentityEvent), &ev); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, tag := range ev.Tags {
		if len(tag) == 2 && (tag[0] == "d" && tag[1] == hubPubkey || tag[0] == "connection" && tag[1] == conn.Pubkey()) {
			counts[tag[0]]++
		}
	}
	if counts["d"] != 1 || counts["connection"] != 1 || len(ev.Tags) != 2 {
		t.Fatalf("tags = %v, want exactly one d=%s and one connection=%s", ev.Tags, hubPubkey, conn.Pubkey())
	}
}

// NIP-CW §Request: connection_pubkey is REQUIRED (no Hub-generated alternative)
// and MUST differ from pubkey.
func TestCreateCircleWalletParams_Request_ConnectionKeyRules(t *testing.T) {
	priv, _ := generateTestKeypair(t)
	hub := randomKeyHex(t)
	if _, err := (CreateCircleWalletParams{Credential: BySigning(priv)}).Request(hub); !errors.Is(err, ErrNoConnectionKey) {
		t.Errorf("no connection key: err = %v, want ErrNoConnectionKey", err)
	}
	same, err := ConnectionKeyFromSecret(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (CreateCircleWalletParams{Credential: BySigning(priv), Connection: same}).Request(hub); err == nil {
		t.Error("a connection key equal to the requester's key was accepted")
	}
}

func TestCreateCircleWalletParams_ParseResult_DecryptsDetails(t *testing.T) {
	memberPrivHex, memberPubHex := generateTestKeypair(t)
	hubPrivHex, hubPubHex := generateTestKeypair(t)
	conn := newTestConnectionKey(t)

	details := `{"wallet_pubkey":"` + testWalletPubkey + `","relays":["wss://r1.example","wss://r2.example"],` +
		`"expires_at":1234,"fees_ppm":0,"budget_renewal":"never"}`
	p := CreateCircleWalletParams{Credential: BySigning(memberPrivHex), Connection: conn, MaxAmountMillis: 1000}
	resp, err := p.ParseResult(hubPubHex, hubReply(t, hubPrivHex, memberPubHex, details))
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if resp.WalletPubkey != testWalletPubkey || resp.ExpiresAt != 1234 || resp.BudgetRenewal != "never" {
		t.Fatalf("resp: %+v", resp)
	}
	if len(resp.Relays) != 2 || resp.Relays[0] != "wss://r1.example" || resp.Relays[1] != "wss://r2.example" {
		t.Fatalf("Relays = %v, want both, in order", resp.Relays)
	}
	if !strings.Contains(resp.PairingURI, "secret="+conn.Secret()) {
		t.Fatalf("PairingURI %q does not carry the member's own secret", resp.PairingURI)
	}
	if resp.MaxAmountMillis != nil {
		t.Fatalf("MaxAmountMillis = %d for a Hub that did not send max_amount, want nil", *resp.MaxAmountMillis)
	}
}

// NIP-CW §Response: wallet_pubkey must be a key and relays must carry at least
// one usable entry, or the member has a wallet it cannot reach.
func TestCreateCircleWalletParams_ParseResult_RequiresWalletAndRelay(t *testing.T) {
	memberPrivHex, memberPubHex := generateTestKeypair(t)
	hubPrivHex, hubPubHex := generateTestKeypair(t)
	p := CreateCircleWalletParams{Credential: BySigning(memberPrivHex), Connection: newTestConnectionKey(t)}
	for name, details := range map[string]string{
		"no relays":       `{"wallet_pubkey":"` + testWalletPubkey + `"}`,
		"blank relays":    `{"wallet_pubkey":"` + testWalletPubkey + `","relays":[""," "]}`,
		"bad wallet":      `{"wallet_pubkey":"walletpubkey","relays":["wss://r"]}`,
		"old pairing_uri": `{"pairing_uri":"nostr+walletconnect://x?relay=wss://r&secret=abc"}`,
	} {
		if _, err := p.ParseResult(hubPubHex, hubReply(t, hubPrivHex, memberPubHex, details)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// NIP-CW §Response: max_amount is the cap as the Hub resolved it, which can differ
// from the request. Built from the wire text, so a dropped or renamed field shows.
func TestCreateCircleWalletParams_ParseResult_CarriesResolvedMaxAmount(t *testing.T) {
	memberPrivHex, memberPubHex := generateTestKeypair(t)
	hubPrivHex, hubPubHex := generateTestKeypair(t)
	details := `{"wallet_pubkey":"` + testWalletPubkey + `","relays":["wss://r"],"max_amount":99000,` +
		`"expires_at":1234,"fees_ppm":0,"budget_renewal":"monthly"}`
	p := CreateCircleWalletParams{Credential: BySigning(memberPrivHex), Connection: newTestConnectionKey(t), MaxAmountMillis: 100000}
	resp, err := p.ParseResult(hubPubHex, hubReply(t, hubPrivHex, memberPubHex, details))
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if resp.MaxAmountMillis == nil || *resp.MaxAmountMillis != 99000 {
		t.Fatalf("MaxAmountMillis = %v, want the Hub's resolved 99000", resp.MaxAmountMillis)
	}
}

// NIP-CW §Errors: the four refusal codes, spelled as the spec spells them.
func TestCreateCircleWalletRefusalCodes(t *testing.T) {
	for got, want := range map[string]string{
		ErrNotReady: "NOT_READY", ErrRestricted: "RESTRICTED",
		ErrWalletExists: "WALLET_EXISTS", ErrRateLimited: "RATE_LIMITED",
	} {
		if got != want {
			t.Errorf("code %q, want %q", got, want)
		}
	}
}

// TestCreateCircleWalletParams_ParseResult_NoDetailsIsAnError pins that a
// response with nothing to decrypt fails loudly. Returning a zero-valued
// CreateCircleWalletResponse would hand the caller a blank wallet pubkey and
// blank terms that read exactly like real ones.
func TestCreateCircleWalletParams_ParseResult_NoDetailsIsAnError(t *testing.T) {
	memberPrivHex, _ := generateTestKeypair(t)
	_, hubPubHex := generateTestKeypair(t)

	p := CreateCircleWalletParams{Credential: BySigning(memberPrivHex), Connection: newTestConnectionKey(t)}
	if _, err := p.ParseResult(hubPubHex, []byte(`{}`)); err == nil {
		t.Fatal("expected an error for a response with no encrypted_details")
	}
}

// TestCreateCircleWalletParams_ParseResult_CoMemberCannotDecrypt is the reason
// the details are nested at all: a circle join goes over the SHARED circlehub
// connection, so another member sees this exact response.
func TestCreateCircleWalletParams_ParseResult_CoMemberCannotDecrypt(t *testing.T) {
	_, memberPubHex := generateTestKeypair(t)
	coMemberPrivHex, _ := generateTestKeypair(t)
	hubPrivHex, hubPubHex := generateTestKeypair(t)

	raw := hubReply(t, hubPrivHex, memberPubHex, `{"wallet_pubkey":"`+testWalletPubkey+`","relays":["wss://r"]}`)
	coMember := CreateCircleWalletParams{Credential: BySigning(coMemberPrivHex), Connection: newTestConnectionKey(t)}
	if _, err := coMember.ParseResult(hubPubHex, raw); err == nil {
		t.Fatal("a co-member of the circle must not be able to decrypt another member's details")
	}
}

func encryptForTest(t *testing.T, fromPrivHex, toPubHex, plaintext string) string {
	t.Helper()
	privBytes, err := hex.DecodeString(fromPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(toPubHex)
	if err != nil {
		t.Fatal(err)
	}
	toPub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nip44.GenerateConversationKey(priv, toPub)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := nip44.Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}
