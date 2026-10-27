// Package nip57test builds valid zap receipts (NIP-57 kind 9735 and NIP-AZ
// kind 9521) from deterministic keys, for tests in nmilat and its embedders.
package nip57test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/utils"
)

// Key is a deterministic private key and its pubkey.
type Key struct{ Priv, Pub string }

// NewKey returns the n-th test key.
func NewKey(n int) Key {
	priv := fmt.Sprintf("%064x", 0x1000+n)
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		panic(err)
	}
	return Key{priv, pub}
}

// Bolt11 builds an invoice in currency ("bc", "fc", ...) carrying the payment
// and description hashes receipt validators check. The node signature is
// zero: nothing here verifies it.
func Bolt11(currency string, amountMloki int64, paymentHash, descriptionHash []byte) (string, error) {
	words := make([]byte, 7) // timestamp
	field := func(typ byte, payload []byte) error {
		data, err := bech32.ConvertBits(payload, 8, 5, true)
		if err != nil {
			return err
		}
		words = append(words, typ, byte(len(data)/32), byte(len(data)%32))
		words = append(words, data...)
		return nil
	}
	if err := field(1, paymentHash); err != nil {
		return "", err
	}
	if err := field(23, descriptionHash); err != nil {
		return "", err
	}
	words = append(words, make([]byte, 104)...) // signature
	// One pico-unit is a tenth of a milli-unit.
	return bech32.Encode(fmt.Sprintf("ln%s%dp", currency, amountMloki*10), words)
}

// Spec describes a zap receipt to build.
type Spec struct {
	Kind      int // 9735 (default) or 9521
	Sender    Key
	Provider  Key    // signs the receipt: the recipient's LNURL server
	Recipient string // pubkey; for 9521 ignored when Connection is set
	// Connection, for 9521, zaps a web identity (platform, external id)
	// that Resolved (an "r" pubkey) may link to a Nostr profile.
	Connection [2]string
	Resolved   string
	Amount     int64 // milli-units of the invoice's coin
	CreatedAt  uint64
	// Preimage makes the payment unique; equal preimages are the same payment.
	Preimage string
	// Currency is a 9735 invoice's prefix (default "bc").
	Currency string
	// Chain is a 9521's chain (default "flokicoin"); its invoice uses the
	// chain's first currency prefix.
	Chain nipAZ.Chain
}

// Receipt builds a receipt that passes NIP-57/NIP-AZ validation.
func Receipt(z Spec) (*nip01.Event, error) {
	if z.Preimage == "" {
		z.Preimage = fmt.Sprintf("%064x", z.CreatedAt^uint64(z.Amount)^uint64(len(z.Recipient)))
	}
	preimage, err := hex.DecodeString(z.Preimage)
	if err != nil {
		return nil, err
	}
	paymentHash := sha256.Sum256(preimage)

	switch z.Kind {
	case 0, nip57.KindZapReceipt:
		if z.Currency == "" {
			z.Currency = "bc"
		}
		req := nip57.NewZapRequest(nip57.ZapRequestParams{
			Recipient: z.Recipient, Relays: []string{"wss://relay.example.com"},
			AmountMsat: z.Amount, Lnurl: "lnurl1dp68gurn8ghj7",
		})
		req.CreatedAt = z.CreatedAt
		if err := req.Sign(z.Sender.Priv); err != nil {
			return nil, err
		}
		desc, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		descHash := sha256.Sum256(desc)
		bolt11, err := Bolt11(z.Currency, z.Amount, paymentHash[:], descHash[:])
		if err != nil {
			return nil, err
		}
		receipt := nip57.NewZapReceipt(nip57.ZapReceiptParams{
			ProviderPubkey: z.Provider.Pub, Recipient: z.Recipient, Description: string(desc), Bolt11: bolt11,
		})
		receipt.CreatedAt = z.CreatedAt
		return receipt, receipt.Sign(z.Provider.Priv)
	case nipAZ.KindAltZapReceipt:
		if z.Chain == "" {
			z.Chain = "flokicoin"
		}
		prefixes := nipAZ.InvoiceCurrencies[z.Chain]
		if len(prefixes) == 0 {
			return nil, fmt.Errorf("no invoice currency for chain %q", z.Chain)
		}
		recipient := nipAZ.Pubkey(z.Recipient)
		if z.Connection[0] != "" {
			// The fixtures name IA-attested accounts, so the key is the attested
			// user id hashed byte for byte, as a sender takes it from a 35522.
			key, err := nipIC.ConnectionKeyFromAttested(nipIC.WebIdentity(z.Connection[0]), z.Connection[1])
			if err != nil {
				return nil, err
			}
			recipient = nipAZ.ResolvedConnection(key, nipAZ.WebIdentity(z.Connection[0]))
		}
		req, err := nipAZ.NewAltZapRequest(nipAZ.AltZapRequestParams{
			PrivateKey: z.Sender.Priv, Chain: z.Chain, Recipient: recipient,
			Lnurl: "lnurl1dp68gurn8ghj7", AmountMloki: z.Amount, Relays: []string{"wss://relay.example.com"},
		})
		if err != nil {
			return nil, err
		}
		desc, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		descHash, err := hex.DecodeString(nipAZ.DescriptionHash(string(desc)))
		if err != nil {
			return nil, err
		}
		bolt11, err := Bolt11(prefixes[0], z.Amount, paymentHash[:], descHash)
		if err != nil {
			return nil, err
		}
		receipt, err := nipAZ.NewAltZapReceipt(nipAZ.AltZapReceiptParams{
			PrivateKey: z.Provider.Priv, Chain: z.Chain, Recipient: recipient,
			Sender: nipAZ.Pubkey(z.Sender.Pub), Description: string(desc), Preimage: &z.Preimage,
			Bolt11: bolt11, ResolvedRecipientPubkey: z.Resolved,
		})
		if err != nil {
			return nil, err
		}
		receipt.CreatedAt = z.CreatedAt
		return receipt, receipt.Sign(z.Provider.Priv)
	default:
		return nil, fmt.Errorf("unsupported zap kind %d", z.Kind)
	}
}
