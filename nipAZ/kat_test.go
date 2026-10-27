package nipAZ_test

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/utils"
)

// K-AZ-1: a deterministic 9520 from key 01×32 to a github ConnectionKey with
// an ia (the x-only key of 02×32), on examplecoin, created_at 1720000000. The
// id was recomputed independently with python3 -I (pure-Python secp256k1 and
// bech32, NIP-01 serialisation) and is frozen here.
func TestKAZ1_DeterministicRequestID(t *testing.T) {
	const (
		wantSender = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
		wantIA     = "4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"
		wantCK     = "ffed85070e86f6ac651aa82b91310ca01895a7432bb0f8224fe74d7b21ab18c1"
		wantLnurl  = "lnurl1dp68gurn8ghj7urp0yhx27rpd4cxcefwvdhk6tmvde6hymrs9askc6trv5qmmmex"
		wantID     = "e0f32bed48057944056e7fb1d74c00569ecb2349882d0e2985f2ae480b71f4c5"
	)
	ia, err := utils.GetPublicKey(strings.Repeat("02", 32))
	if err != nil || ia != wantIA {
		t.Fatalf("ia pubkey %q %v", ia, err)
	}
	lnurl, err := utils.EncodeLNURL("https://pay.example.com/lnurlp/alice")
	if err != nil || lnurl != wantLnurl {
		t.Fatalf("lnurl %q %v", lnurl, err)
	}
	if githubCK != wantCK {
		t.Fatalf("ConnectionKey %q", githubCK)
	}
	ev, err := nipAZ.NewAltZapRequest(nipAZ.AltZapRequestParams{
		PrivateKey: strings.Repeat("01", 32), Chain: "examplecoin",
		Recipient: nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "github"), IA: ia,
		Lnurl: lnurl, AmountMloki: 21000, Relays: []string{"wss://relay.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ev.CreatedAt = 1720000000
	if err := ev.Sign(strings.Repeat("01", 32)); err != nil {
		t.Fatal(err)
	}
	if ev.PubKey != wantSender || ev.ID != wantID {
		t.Fatalf("pubkey %s id %s", ev.PubKey, ev.ID)
	}
	if err := nipAZ.ValidateAltZapRequestForRelay(ev); err != nil {
		t.Fatal(err)
	}
}
