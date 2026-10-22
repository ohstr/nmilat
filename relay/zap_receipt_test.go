package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/utils"
	"github.com/stretchr/testify/require"
)

// testKey is a deterministic private key and its pubkey.
type testKey struct{ priv, pub string }

func newTestKey(t testing.TB, n int) testKey {
	t.Helper()
	priv := fmt.Sprintf("%064x", 0x1000+n)
	pub, err := utils.GetPublicKey(priv)
	require.NoError(t, err)
	return testKey{priv, pub}
}

// testBolt11 builds an unsigned invoice carrying the payment and
// description hashes the receipt validators check. The node signature is
// zero: nothing here verifies it.
func testBolt11(t testing.TB, currency string, amountMloki int64, paymentHash, descriptionHash []byte) string {
	t.Helper()
	words := make([]byte, 7) // timestamp
	field := func(typ byte, payload []byte) {
		data, err := bech32.ConvertBits(payload, 8, 5, true)
		require.NoError(t, err)
		words = append(words, typ, byte(len(data)/32), byte(len(data)%32))
		words = append(words, data...)
	}
	field(1, paymentHash)
	field(23, descriptionHash)
	words = append(words, make([]byte, 104)...) // signature
	// One pico-unit is a tenth of a milli-unit.
	s, err := bech32.Encode(fmt.Sprintf("ln%s%dp", currency, amountMloki*10), words)
	require.NoError(t, err)
	return s
}

// zapSpec describes a zap receipt to build.
type zapSpec struct {
	Kind      int // 9735 (default) or 9521
	Sender    testKey
	Provider  testKey // signs the receipt: the recipient's LNURL server
	Recipient string  // pubkey; for 9521 ignored when Connection is set
	// Connection, for 9521, zaps a web identity (platform, external id)
	// that Resolved (an "r" pubkey) may link to a Nostr profile.
	Connection [2]string
	Resolved   string
	Amount     int64 // milli-units
	CreatedAt  uint64
	// Preimage makes the payment unique; equal preimages are the same payment.
	Preimage string
}

// zapReceipt builds a receipt that passes NIP-57/NIP-AZ validation.
func zapReceipt(t testing.TB, z zapSpec) *nip01.Event {
	t.Helper()
	if z.Preimage == "" {
		z.Preimage = fmt.Sprintf("%064x", z.CreatedAt^uint64(z.Amount)^uint64(len(z.Recipient)))
	}
	preimage, _ := hex.DecodeString(z.Preimage)
	paymentHash := sha256.Sum256(preimage)

	var receipt *nip01.Event
	switch z.Kind {
	case 0, nip57.KindZapReceipt:
		req := nip57.NewZapRequest(nip57.ZapRequestParams{
			Recipient: z.Recipient, Relays: []string{"wss://relay.example.com"},
			AmountMsat: z.Amount, Lnurl: "lnurl1dp68gurn8ghj7",
		})
		req.CreatedAt = z.CreatedAt
		require.NoError(t, req.Sign(z.Sender.priv))
		desc := string(mustJSON(t, req))
		descHash := sha256.Sum256([]byte(desc))
		receipt = nip57.NewZapReceipt(nip57.ZapReceiptParams{
			ProviderPubkey: z.Provider.pub, Recipient: z.Recipient, Description: desc,
			Bolt11: testBolt11(t, "bc", z.Amount, paymentHash[:], descHash[:]),
		})
		receipt.CreatedAt = z.CreatedAt
		require.NoError(t, receipt.Sign(z.Provider.priv))
	case nipAZ.KindAltZapReceipt:
		recipient := nipAZ.Pubkey(z.Recipient)
		if z.Connection[0] != "" {
			recipient = nipAZ.Connection(nipAZ.WebIdentity(z.Connection[0]), z.Connection[1])
		}
		req, err := nipAZ.NewAltZapRequest(nipAZ.AltZapRequestParams{
			PrivateKey: z.Sender.priv, Chain: "flokicoin", Recipient: recipient,
			Lnurl: "lnurl1dp68gurn8ghj7", AmountMloki: z.Amount, Relays: []string{"wss://relay.example.com"},
		})
		require.NoError(t, err)
		desc := string(mustJSON(t, req))
		receipt, err = nipAZ.NewAltZapReceipt(nipAZ.AltZapReceiptParams{
			PrivateKey: z.Provider.priv, Chain: "flokicoin", Recipient: recipient,
			Sender: nipAZ.Pubkey(z.Sender.pub), Description: desc, Preimage: &z.Preimage,
			Bolt11:                  testBolt11(t, "fc", z.Amount, paymentHash[:], mustHex(t, nipAZ.DescriptionHash(desc))),
			ResolvedRecipientPubkey: z.Resolved,
		})
		require.NoError(t, err)
		receipt.CreatedAt = z.CreatedAt
		require.NoError(t, receipt.Sign(z.Provider.priv))
	default:
		t.Fatalf("unsupported zap kind %d", z.Kind)
	}
	return receipt
}

func mustJSON(t testing.TB, ev *nip01.Event) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	return b
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestZapReceiptHelperValidates(t *testing.T) {
	sender, provider, recipient := newTestKey(t, 1), newTestKey(t, 2), newTestKey(t, 3)
	for _, kind := range []int{nip57.KindZapReceipt, nipAZ.KindAltZapReceipt} {
		ev := zapReceipt(t, zapSpec{Kind: kind, Sender: sender, Provider: provider, Recipient: recipient.pub, Amount: 21000, CreatedAt: 1_700_000_000})
		f, err := parseZapFact(ev)
		require.NoError(t, err)
		require.True(t, f.Valid, "kind %d", kind)
		require.Equal(t, recipient.pub, f.Receiver)
		require.Equal(t, sender.pub, f.Sender)
		require.Equal(t, provider.pub, f.Signer)
		require.Equal(t, uint64(21000), f.Amount)
		require.NotEmpty(t, f.PaymentHash)
	}
}
