package nipcw

import (
	"encoding/json"
	"fmt"

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
	if id == "" {
		return transport.Item{}, fmt.Errorf("nipcw: item needs an id")
	}
	if hubSecret == "" {
		return transport.Item{}, fmt.Errorf("nipcw: a private join needs the Hub connection's secret to sign its bill proof")
	}
	req, err := p.Request(hubPubkey)
	if err != nil {
		return transport.Item{}, err
	}
	params, err := json.Marshal(req)
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcw: marshal item params: %w", err)
	}
	hash, err := transport.CanonicalParamsHash(params)
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcw: hash item params: %w", err)
	}
	binding := transport.ProofBinding{
		Target:     hubPubkey,
		HubXOnly:   b.HubXOnly,
		Method:     MethodCreateCircleWallet,
		ParamsHash: hash,
		Nonce:      b.Nonce,
		NotAfter:   b.NotAfter,
	}
	billProof, err := transport.BuildBillProof(hubSecret, binding)
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcw: build bill proof: %w", err)
	}
	proof, err := transport.BuildItemProof(p.Credential.privKeyHex, binding)
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcw: build item proof: %w", err)
	}
	return transport.Item{
		ID:        id,
		Target:    hubPubkey,
		Method:    MethodCreateCircleWallet,
		Params:    params,
		Proof:     proof,
		BillProof: billProof,
	}, nil
}
