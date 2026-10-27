package nipCO

import (
	"fmt"

	"github.com/ohstr/nmilat/internal/credcodec"
	"github.com/ohstr/nmilat/nipcash"
)

// OrderConnectionHRP is the bech32 prefix of an Order connection (NIP-CO §The
// Order Connection).
const OrderConnectionHRP = "cashorder"

// OrderConnection is a decoded cashorder1 string.
//
// Pubkey (TLV 0), Secret (TLV 2) and HubIdentity (TLV 4, x-only) are 64
// lowercase hex. Relays (TLV 1) are kept exactly as encoded, since the connection
// signature covers them as encoded. HasLabel tells an absent TLV 3 from an empty
// one. Signature (TLV 5, 65 bytes) and Chain (TLV 6) are NIP-CASH §Connection
// Signatures'.
//
// Decoding never verifies: call Verify. An unverified string still decodes, and a
// client tells its user the Hub is not confirmed. The secret is public by design
// and authorizes nothing but the bill proofs of an order and its lookups.
type OrderConnection struct {
	Pubkey      string
	Relays      []string
	Secret      string
	Label       string
	HasLabel    bool
	HubIdentity string
	Signature   []byte
	Chain       string
}

func (c OrderConnection) conn() credcodec.Conn {
	return credcodec.Conn{Pubkey: c.Pubkey, Relays: c.Relays, Secret: c.Secret, Label: c.Label,
		HasLabel: c.HasLabel, HubIdentity: c.HubIdentity, Signature: c.Signature, Chain: c.Chain}
}

// Fields is what the connection signature covers.
func (c OrderConnection) Fields() nipcash.ConnFields {
	return nipcash.ConnFields{HRP: OrderConnectionHRP, Chain: c.Chain, Pubkey: c.Pubkey, HubIdentity: c.HubIdentity,
		Relays: c.Relays, Secret: c.Secret, Label: c.Label, HasLabel: c.HasLabel}
}

// Verify reports nil when the connection signature recovers to TLV 4 over the
// rebuilt cash-order:v1 text, else an error wrapping nipcash.ErrConnUnverified.
func (c OrderConnection) Verify() error { return nipcash.VerifyConnection(c.Fields(), c.Signature) }

// checkRelays refuses zero relays and an empty, whitespace-only or non-ASCII
// one: an encoder never emits an empty relay (NIP-CO §Wire Format).
func checkRelays(relays []string) error {
	if len(relays) == 0 {
		return fmt.Errorf("%w: no relay", ErrOrderConnection)
	}
	for _, r := range relays {
		switch {
		case credcodec.IsBlankHint(r):
			return fmt.Errorf("%w: %w", ErrOrderConnection, credcodec.ErrBlankRelayHint)
		case !credcodec.IsASCII(r):
			return fmt.Errorf("%w: %w: %q", ErrOrderConnection, credcodec.ErrNonASCIIRelayHint, r)
		}
	}
	return nil
}

// EncodeOrderConnection writes c as a cashorder1 string, entries in ascending
// type order (0, 1..., 2, 3, 4, 5, 6). It refuses an unsigned connection (no TLV
// 4 or 5), a missing or malformed chain, an empty label with HasLabel, zero
// relays and an empty, whitespace-only, non-ASCII or over-long relay. The string
// has no length limit.
func EncodeOrderConnection(c OrderConnection) (string, error) {
	if err := checkRelays(c.Relays); err != nil {
		return "", err
	}
	s, err := credcodec.EncodeConn(OrderConnectionHRP, c.conn())
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrOrderConnection, err)
	}
	return s, nil
}

// DecodeOrderConnection parses a cashorder1 string, all lowercase or all
// uppercase. It refuses a missing TLV 0/2/4/5/6, a wrong-length 0/2/4/5, a
// malformed 6, a repeated single field, another HRP and a mixed-case string; it
// ignores an entry of an unknown type.
func DecodeOrderConnection(s string) (OrderConnection, error) {
	c, err := credcodec.DecodeConn(s, OrderConnectionHRP)
	if err != nil {
		return OrderConnection{}, fmt.Errorf("%w: %w", ErrOrderConnection, err)
	}
	return OrderConnection{Pubkey: c.Pubkey, Relays: c.Relays, Secret: c.Secret, Label: c.Label,
		HasLabel: c.HasLabel, HubIdentity: c.HubIdentity, Signature: c.Signature, Chain: c.Chain}, nil
}

// SignOrderConnection signs c with its node signer and returns it with Signature
// set. The signature must recover to both c.HubIdentity and expectedXOnly, or
// nipcash.ErrSignerMismatch and nothing is issued. Relays are signed exactly as
// given, so a blank one is refused here as EncodeOrderConnection refuses it.
func SignOrderConnection(c OrderConnection, sign nipcash.MintSigner, expectedXOnly string) (OrderConnection, error) {
	if err := checkRelays(c.Relays); err != nil {
		return OrderConnection{}, err
	}
	sig, err := nipcash.SignConnection(c.Fields(), sign, expectedXOnly)
	if err != nil {
		return OrderConnection{}, err
	}
	c.Signature = sig
	return c, nil
}
