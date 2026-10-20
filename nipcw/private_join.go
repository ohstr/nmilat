package nipcw

import (
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// Item builds a create_circle_wallet item for NIP-CASH's private transport
// (NIP-CW §Private Join). hubPubkey is the Hub connection's pubkey, which the
// item targets; hubSecret is that connection's secret, which signs the bill
// proof. b.HubXOnly is the node identity from the Hub's get_info.
//
// The params are the standard request unchanged, so its kind-23199 identity
// proof still binds to hubPubkey. The kind-23192 item proof is signed by the
// requester's own key, as the spec requires of a join.
//
// The reply is parsed with ParseResult(hubPubkey, ...), exactly as on the
// standard transport: the details are encrypted from the Hub connection key,
// never the inbox key.
func (p CreateCircleWalletParams) Item(id, hubPubkey, hubSecret string, b nipcash.ItemBinding) (transport.Item, error) {
	req, err := p.Request(hubPubkey)
	if err != nil {
		return transport.Item{}, err
	}
	return nipcash.BuildItem(id, hubPubkey, hubSecret, MethodCreateCircleWallet, req, nipcash.BySigning(p.Credential.privKeyHex), b)
}
