package nipcw

import (
	"fmt"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// JoinLookupParams looks a join up when its reply was lost (NIP-CW §Lost Join
// Reply): NIP-CASH's cash_lookup on the private transport, params
// {connection_pubkey, deadline}. Credential is the join's: its pubkey signs the
// item proof. ConnectionPubkey is the join's key, or the key a rotation moved
// the wallet to; Deadline is the join's (its proof's created_at + 300).
type JoinLookupParams struct {
	Credential       Credential
	ConnectionPubkey string
	Deadline         int64
}

// Item builds the lookup item: target the Circle Hub connection (hubPubkey),
// bill proof by hubSecret, item proof by the join's key.
func (p JoinLookupParams) Item(id, hubPubkey, hubSecret string, b nipcash.ItemBinding) (transport.Item, error) {
	return nipcash.CashLookupParams{
		Credential: nipcash.BySigning(p.Credential.privKeyHex),
		Request:    nipcash.CashLookupRequest{ConnectionPubkey: p.ConnectionPubkey, Deadline: p.Deadline},
	}.Item(id, hubPubkey, hubSecret, b)
}

// ParseResult checks a done lookup's result exactly as a join reply: decrypted
// from hubPubkey, naming p.ConnectionPubkey (after a rotation, the new key).
// CapsRaised is never set: the lookup does not know the requested caps.
func (p JoinLookupParams) ParseResult(hubPubkey string, data []byte) (*CreateCircleWalletResponse, error) {
	if !isLowerHex64(p.ConnectionPubkey) {
		return nil, fmt.Errorf("nipcw: connection_pubkey must be 64 lowercase hex")
	}
	return parseDetails(p.Credential, hubPubkey, p.ConnectionPubkey, data)
}
