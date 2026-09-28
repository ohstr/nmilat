package nipcash

import (
	"encoding/json"
	"fmt"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// ItemBinding is what every item in one envelope shares: the hub it is addressed
// to, and the envelope's own nonce and expiry.
//
// A caller does not build this by hand in normal use — the batch client derives it
// from the envelope it is assembling, which is what guarantees an item's proof binds
// to the envelope actually carrying it. It is exported for anyone driving the
// transport directly.
type ItemBinding struct {
	// HubXOnly is the hub's own identity key, NOT its inbox key. The proof commits
	// to the identity (so an item cannot be replayed at another hub), while the
	// envelope is encrypted to the inbox. Conflating them is the mistake the
	// announcement exists to prevent, so they are named distinctly here too.
	HubXOnly string
	Nonce    string
	NotAfter int64
}

// buildItem is the one place an item is assembled, and the reason the batch API
// cannot produce an incoherent envelope.
//
// Everything that could disagree is derived here from a single source rather than
// accepted from a caller: the params hash is computed from the params actually being
// sent, the proof is built over that hash and this binding, and the target is the
// one written into the item. There is no combination of arguments that yields an
// item whose proof does not match it.
//
// That matters more than it usually would. Every such mismatch is answered by a hub
// with OMISSION, which is deliberately information-free, so a caller who built one
// could never learn what was wrong (NIP-CASH §Responses). Making the mistake
// unrepresentable is worth more here than diagnosing it.
func buildItem(id, target, method string, wireParams any, cred Credential, b ItemBinding) (transport.Item, error) {
	if id == "" {
		return transport.Item{}, fmt.Errorf("nipcash: item needs an id")
	}
	if !transport.IsServableMethod(method) {
		return transport.Item{}, fmt.Errorf("nipcash: %q is not servable over the private transport", method)
	}

	params, err := json.Marshal(wireParams)
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcash: marshal item params: %w", err)
	}

	item := transport.Item{ID: id, Target: target, Method: method, Params: params}

	privKeyHex, cashSecret, err := cred.itemAuthorization()
	if err != nil {
		return transport.Item{}, err
	}
	if cashSecret != "" {
		// Cash-mode: no proof exists or is needed. The secret is already inside
		// wireParams — every params type puts it there via buildProof — so there is
		// nothing further to attach (NIP-CASH §Bearer Items).
		return item, nil
	}

	// Hashed from the marshalled bytes above, so the proof commits to exactly what
	// travels. Canonicalising rather than hashing raw is what keeps the binding
	// independent of any re-serialisation along the way.
	hash, err := transport.CanonicalParamsHash(params)
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcash: hash item params: %w", err)
	}
	proof, err := transport.BuildItemProof(privKeyHex, transport.ProofBinding{
		Target:     target,
		HubXOnly:   b.HubXOnly,
		Method:     method,
		ParamsHash: hash,
		Nonce:      b.Nonce,
		NotAfter:   b.NotAfter,
	})
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcash: build item proof: %w", err)
	}
	item.Proof = proof
	return item, nil
}

// Item builds a cash_redeem item for the private transport.
//
// The item's params are the same wire request this call sends on the standard
// transport, which is deliberate: the transport changes how a request travels, never
// what it says. One request shape, one server-side handler, one set of guarantees.
func (p CashRedeemParams) Item(id, target string, b ItemBinding) (transport.Item, error) {
	req, err := p.Request(target)
	if err != nil {
		return transport.Item{}, err
	}
	return buildItem(id, target, MethodCashRedeem, req, p.Credential, b)
}

// Item builds a cash_transfer item for the private transport.
func (p CashTransferParams) Item(id, target string, b ItemBinding) (transport.Item, error) {
	req, err := p.Request(target)
	if err != nil {
		return transport.Item{}, err
	}
	return buildItem(id, target, MethodCashTransfer, req, p.Credential, b)
}

// Item builds a cash_consolidate item for the private transport.
//
// target is the wallet the call is made AGAINST — the entry point — while the slices
// being merged are CashConsolidateParams.Sources, each carrying its own credential.
// The two are separate on purpose: NIP-CASH lets a caller consolidate sources it does
// not otherwise hold, so the entry point is not necessarily one of them.
//
// cred authorizes the call itself. Note a consolidate item can therefore carry
// several proofs: this item's own, plus one per source inside params, which is why
// transport.Item.VerificationCost counts them.
func (p CashConsolidateParams) Item(id, target string, cred Credential, b ItemBinding) (transport.Item, error) {
	req, err := p.Request()
	if err != nil {
		return transport.Item{}, err
	}
	return buildItem(id, target, MethodCashConsolidate, req, cred, b)
}

// StatusItem builds a cash_status item for the private transport.
//
// A bare function rather than a method, because cash_status has no params type: on
// the standard transport it is a call with no body, authorized by the connection it
// arrives on. The private transport has no per-bill connection, so the credential
// that was implicit there becomes explicit here.
func StatusItem(id, target string, cred Credential, b ItemBinding) (transport.Item, error) {
	// An empty object rather than nil: CanonicalParamsHash treats absent and empty
	// as one representation, and a hub's decoder expects a params field it can
	// unmarshal. Being explicit avoids depending on that equivalence.
	return buildItem(id, target, MethodCashStatus, struct{}{}, cred, b)
}
