package nipcash

import (
	"fmt"

	"github.com/ohstr/nmilat/internal/credcodec"
)

// CashHubConnectionHRP is the fixed bech32 prefix for a Cash Hub's own
// connection string (NIP-CASH §The Cash Hub Connection): the one its owner calls
// mint_cash over, as distinct from a bill's cash token.
const CashHubConnectionHRP = "cashhub"

// CashHubConnection is a decoded cashhub1... string.
//
// Pubkey (TLV 0) and HubIdentity (TLV 4) are 64 lowercase hex. Relays (TLV 1)
// are kept exactly as encoded, since the connection signature covers them as
// encoded. HasLabel tells an absent TLV 3 from an empty one. Signature (TLV 5)
// and Chain (TLV 6) complete the signature of §Connection Signatures.
//
// Decoding never verifies: call Verify. An unverified string still decodes, and
// a client tells its user the Hub is not confirmed.
type CashHubConnection struct {
	Pubkey      string
	Relays      []string
	Secret      string
	Label       string
	HasLabel    bool
	HubIdentity string
	Signature   []byte
	Chain       string
}

func (c CashHubConnection) conn() credcodec.Conn {
	return credcodec.Conn{Pubkey: c.Pubkey, Relays: c.Relays, Secret: c.Secret, Label: c.Label,
		HasLabel: c.HasLabel, HubIdentity: c.HubIdentity, Signature: c.Signature, Chain: c.Chain}
}

// Fields is what the connection signature covers.
func (c CashHubConnection) Fields() ConnFields {
	return ConnFields{HRP: CashHubConnectionHRP, Chain: c.Chain, Pubkey: c.Pubkey, HubIdentity: c.HubIdentity,
		Relays: c.Relays, Secret: c.Secret, Label: c.Label, HasLabel: c.HasLabel}
}

// Verify reports nil when the connection signature recovers to TLV 4 over the
// rebuilt text, else ErrConnUnverified.
func (c CashHubConnection) Verify() error { return VerifyConnection(c.Fields(), c.Signature) }

// EncodeCashHubConnection writes c as a cashhub1... string, entries in ascending
// type order. It refuses an unsigned connection (TLV 4 and 5 are required), a
// missing or malformed chain, an empty label with HasLabel, a non-ASCII or
// over-long relay hint and a connection with no usable hint. Blank hints are
// skipped; SignCashHubConnection signs over exactly the hints written.
func EncodeCashHubConnection(c CashHubConnection) (string, error) {
	s, err := credcodec.EncodeConn(CashHubConnectionHRP, c.conn())
	if err != nil {
		return "", fmt.Errorf("nipcash: %w", err)
	}
	return s, nil
}

// DecodeCashHubConnection parses a cashhub1... string, all lowercase or all
// uppercase. It refuses a missing TLV 0/2/4/5/6, a wrong-length 0/2/4/5, a
// malformed 6, a repeated single field, a string with no usable relay hint and a
// mixed-case string (ErrMixedCase); it ignores a type above 6.
func DecodeCashHubConnection(s string) (CashHubConnection, error) {
	c, err := credcodec.DecodeConn(s, CashHubConnectionHRP)
	if err != nil {
		return CashHubConnection{}, fmt.Errorf("nipcash: %w", err)
	}
	return CashHubConnection{Pubkey: c.Pubkey, Relays: c.Relays, Secret: c.Secret, Label: c.Label,
		HasLabel: c.HasLabel, HubIdentity: c.HubIdentity, Signature: c.Signature, Chain: c.Chain}, nil
}

// SignCashHubConnection signs c with its node signer and returns it with
// Signature set. Blank relay hints are dropped first, so the signature covers
// exactly the hints EncodeCashHubConnection will write. The signature must
// recover to both c.HubIdentity and expectedXOnly, or ErrSignerMismatch.
func SignCashHubConnection(c CashHubConnection, sign MintSigner, expectedXOnly string) (CashHubConnection, error) {
	c.Relays = credcodec.EmittedRelays(c.Relays)
	sig, err := SignConnection(c.Fields(), sign, expectedXOnly)
	if err != nil {
		return CashHubConnection{}, err
	}
	c.Signature = sig
	return c, nil
}
