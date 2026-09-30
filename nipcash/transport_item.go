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
func buildItem(id, target, connSecret, method string, wireParams any, cred Credential, b ItemBinding) (transport.Item, error) {
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

	// Hashed from the marshalled bytes above, so both proofs commit to exactly what
	// travels. Canonicalising rather than hashing raw is what keeps the binding
	// independent of any re-serialisation along the way.
	hash, err := transport.CanonicalParamsHash(params)
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcash: hash item params: %w", err)
	}
	binding := transport.ProofBinding{
		Target:     target,
		HubXOnly:   b.HubXOnly,
		Method:     method,
		ParamsHash: hash,
		Nonce:      b.Nonce,
		NotAfter:   b.NotAfter,
	}

	// The BILL proof, first and unconditional. Every item carries one, whatever the
	// bill's identity mode: it says the sender holds this bill's token, which is a
	// different claim from the slice proof below and the only one a hub can safely
	// act on when deciding whether to answer about the bill at all.
	if connSecret == "" {
		return transport.Item{}, fmt.Errorf("nipcash: item %q needs the bill's connection secret to prove possession", id)
	}
	billProof, err := transport.BuildBillProof(connSecret, binding)
	if err != nil {
		return transport.Item{}, fmt.Errorf("nipcash: build bill proof: %w", err)
	}
	item.BillProof = billProof

	privKeyHex, cashSecret, err := cred.itemAuthorization()
	if err != nil {
		return transport.Item{}, err
	}
	if cashSecret != "" {
		// Cash-mode: no SLICE proof exists or is needed. The secret is already inside
		// wireParams — every params type puts it there via buildProof — so there is
		// nothing further to attach (NIP-CASH §Bearer Items). The bill proof above
		// still applies.
		return item, nil
	}

	proof, err := transport.BuildItemProof(privKeyHex, binding)
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
func (p CashRedeemParams) Item(id, target, connSecret string, b ItemBinding) (transport.Item, error) {
	req, err := p.Request(target)
	if err != nil {
		return transport.Item{}, err
	}
	return buildItem(id, target, connSecret, MethodCashRedeem, req, p.Credential, b)
}

// Item builds a cash_transfer item for the private transport.
func (p CashTransferParams) Item(id, target, connSecret string, b ItemBinding) (transport.Item, error) {
	req, err := p.Request(target)
	if err != nil {
		return transport.Item{}, err
	}
	return buildItem(id, target, connSecret, MethodCashTransfer, req, p.Credential, b)
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
func (p CashConsolidateParams) Item(id, target, connSecret string, cred Credential, b ItemBinding) (transport.Item, error) {
	req, err := p.Request()
	if err != nil {
		return transport.Item{}, err
	}
	return buildItem(id, target, connSecret, MethodCashConsolidate, req, cred, b)
}

// StatusItem builds a cash_status item for the private transport.
//
// A bare function rather than a method on the params, because on the standard
// transport cash_status is authorized by the connection it arrives on. The private
// transport has no per-bill connection, so the credential that was implicit there
// becomes explicit here.
//
// Leaving p.Scope empty is the normal case and asks for this transport's own
// default, which is ScopeMine — the caller's own row, and nothing about their
// co-recipients. Say ScopeAll explicitly to get the shared roster.
func StatusItem(id, target, connSecret string, p CashStatusParams, cred Credential, b ItemBinding) (transport.Item, error) {
	if !IsValidCashStatusScope(p.Scope) {
		return transport.Item{}, fmt.Errorf("nipcash: cash_status scope %q must be %q, %q, or absent", p.Scope, ScopeAll, ScopeMine)
	}
	// Built through the credential, exactly as every other method's Request does, so
	// a cash-mode bill's secret reaches the params. buildItem returns early for a
	// cash-mode credential on the assumption that the secret is ALREADY in
	// wireParams; passing CashStatusParams straight through broke that assumption
	// silently, and produced an item with neither a proof nor a secret — malformed,
	// refused by the codec, and therefore never sent.
	_, _, _, _, cashSecret, err := cred.buildProof(proofBinding{WalletPubkey: target})
	if err != nil {
		return transport.Item{}, err
	}
	// The params value is passed even when empty: CanonicalParamsHash treats absent
	// and empty as one representation, and a hub's decoder expects a params field it
	// can unmarshal. Being explicit avoids depending on that equivalence.
	return buildItem(id, target, connSecret, MethodCashStatus, CashStatusRequest{Scope: p.Scope, CashSecret: cashSecret, AttestationEvent: p.AttestationEvent}, cred, b)
}
