package nipcw

import (
	"fmt"

	"github.com/ohstr/nmilat/internal/credcodec"
	"github.com/ohstr/nmilat/nipcash"
)

// CircleHubConnectionHRP is the fixed bech32 prefix for a Circle Wallet Hub's
// own connection string (NIP-CW §The Circle Wallet Hub Connection), the one
// members join over.
const CircleHubConnectionHRP = "circlehub"

// CircleHubConnection is a decoded circlehub1... string.
//
// Pubkey (TLV 0) is the Hub's own pubkey, the one a join proof's d tag binds;
// HubIdentity (TLV 4) is the node identity, circle_wallet.identity. Both are 64
// lowercase hex. Relays (TLV 1) are kept exactly as encoded, since the
// connection signature covers them as encoded. HasLabel tells an absent TLV 3
// from an empty one. Signature (TLV 5) and Chain (TLV 6) complete the signature
// of NIP-CASH §Connection Signatures, with the text label circle-hub:v1.
//
// Decoding never verifies: call Verify. An unverified string still decodes, and
// a client tells its user the Hub is not confirmed.
type CircleHubConnection struct {
	Pubkey      string
	Relays      []string
	Secret      string
	Label       string
	HasLabel    bool
	HubIdentity string
	Signature   []byte
	Chain       string
}

func (c CircleHubConnection) conn() credcodec.Conn {
	return credcodec.Conn{Pubkey: c.Pubkey, Relays: c.Relays, Secret: c.Secret, Label: c.Label,
		HasLabel: c.HasLabel, HubIdentity: c.HubIdentity, Signature: c.Signature, Chain: c.Chain}
}

// Fields is what the connection signature covers.
func (c CircleHubConnection) Fields() nipcash.ConnFields {
	return nipcash.ConnFields{HRP: CircleHubConnectionHRP, Chain: c.Chain, Pubkey: c.Pubkey, HubIdentity: c.HubIdentity,
		Relays: c.Relays, Secret: c.Secret, Label: c.Label, HasLabel: c.HasLabel}
}

// Verify reports nil when the connection signature recovers to TLV 4 over the
// rebuilt text, else nipcash.ErrConnUnverified.
func (c CircleHubConnection) Verify() error { return nipcash.VerifyConnection(c.Fields(), c.Signature) }

// EncodeCircleHubConnection writes c as a circlehub1... string, entries in
// ascending type order. It refuses an unsigned connection (TLV 4 and 5 are
// required), a missing or malformed chain, an empty label with HasLabel, a
// non-ASCII or over-long relay hint and a connection with no usable hint. Blank
// hints are skipped; SignCircleHubConnection signs over exactly the hints
// written.
func EncodeCircleHubConnection(c CircleHubConnection) (string, error) {
	s, err := credcodec.EncodeConn(CircleHubConnectionHRP, c.conn())
	if err != nil {
		return "", fmt.Errorf("nipcw: %w", err)
	}
	return s, nil
}

// DecodeCircleHubConnection parses a circlehub1... string, all lowercase or all
// uppercase. It refuses a missing TLV 0/2/4/5/6, a wrong-length 0/2/4/5, a
// malformed 6, a repeated single field, a string with no usable relay hint and a
// mixed-case string; it ignores a type above 6.
func DecodeCircleHubConnection(s string) (CircleHubConnection, error) {
	c, err := credcodec.DecodeConn(s, CircleHubConnectionHRP)
	if err != nil {
		return CircleHubConnection{}, fmt.Errorf("nipcw: %w", err)
	}
	return CircleHubConnection{Pubkey: c.Pubkey, Relays: c.Relays, Secret: c.Secret, Label: c.Label,
		HasLabel: c.HasLabel, HubIdentity: c.HubIdentity, Signature: c.Signature, Chain: c.Chain}, nil
}

// SignCircleHubConnection signs c with its node signer and returns it with
// Signature set. Blank relay hints are dropped first, so the signature covers
// exactly the hints EncodeCircleHubConnection will write. The signature must
// recover to both c.HubIdentity and expectedXOnly, or nipcash.ErrSignerMismatch.
func SignCircleHubConnection(c CircleHubConnection, sign nipcash.MintSigner, expectedXOnly string) (CircleHubConnection, error) {
	c.Relays = credcodec.EmittedRelays(c.Relays)
	sig, err := nipcash.SignConnection(c.Fields(), sign, expectedXOnly)
	if err != nil {
		return CircleHubConnection{}, err
	}
	c.Signature = sig
	return c, nil
}
