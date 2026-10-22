package relay

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nip57/nip57test"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/stretchr/testify/require"
)

// testKey is a deterministic private key and its pubkey.
type testKey struct{ priv, pub string }

func newTestKey(t testing.TB, n int) testKey {
	t.Helper()
	k := nip57test.NewKey(n)
	return testKey{k.Priv, k.Pub}
}

func (k testKey) key() nip57test.Key { return nip57test.Key{Priv: k.priv, Pub: k.pub} }

// zapSpec describes a zap receipt to build; see nip57test.Spec.
type zapSpec struct {
	Kind       int
	Sender     testKey
	Provider   testKey
	Recipient  string
	Connection [2]string
	Resolved   string
	Amount     int64
	CreatedAt  uint64
	Preimage   string
	Currency   string
	Chain      nipAZ.Chain
}

// zapReceipt builds a receipt that passes NIP-57/NIP-AZ validation.
func zapReceipt(t testing.TB, z zapSpec) *nip01.Event {
	t.Helper()
	ev, err := nip57test.Receipt(nip57test.Spec{
		Kind: z.Kind, Sender: z.Sender.key(), Provider: z.Provider.key(), Recipient: z.Recipient,
		Connection: z.Connection, Resolved: z.Resolved, Amount: z.Amount, CreatedAt: z.CreatedAt,
		Preimage: z.Preimage, Currency: z.Currency, Chain: z.Chain,
	})
	require.NoError(t, err)
	return ev
}

func mustJSON(t testing.TB, ev *nip01.Event) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
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
