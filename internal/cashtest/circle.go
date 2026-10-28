package cashtest

import (
	"encoding/json"
	"maps"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
)

// circleHub is the fake's Circle Wallet Hub connection, off unless WithCircleHub.
type circleHub struct {
	priv, xonly, secret string
	// wallet is get_info's circle_wallet block as raw keys, so a test can drop
	// one; chain is get_info's chain.
	wallet map[string]any
	chain  string
}

// CirclePrivateMethods are the methods the fake's Circle Hub connection lists in
// get_info private_methods (NIP-CW §Private Join).
var CirclePrivateMethods = []string{"cash_lookup", "create_circle_wallet"}

// WithCircleHub gives the fake a Circle Wallet Hub connection (allowlist policy)
// whose get_info carries DefaultCircleWallet. Its joins and join lookups arrive
// on the private transport like any item and are answered by Decide.
func WithCircleHub() Option {
	return func(h *FakeHub) { h.circle = &circleHub{} }
}

// DefaultCircleWallet is the circle_wallet block the fake reports: every
// "always" key, rotation served, accepting.
func DefaultCircleWallet(identity string) map[string]any {
	return map[string]any{
		"available_millis":      1000000,
		"max_exp_secs":          2592000,
		"fees_ppm":              0,
		"fee_reserve":           map[string]any{"ppm": 5000, "min_millis": 10000},
		"dust_threshold_millis": 1000,
		"circle_policy":         "allowlist",
		"identity":              identity,
		"rotation_delay_secs":   432000,
		"accepting":             true,
	}
}

func (h *FakeHub) initCircle() {
	if h.circle == nil {
		return
	}
	h.circle.priv, h.circle.xonly = Keypair(h.t)
	h.circle.secret, _ = Keypair(h.t)
	h.circle.wallet = DefaultCircleWallet(h.nodeXOnly)
	h.circle.chain = FakeChain
}

// CircleHubConnection is the Hub's circlehub1 string, signed by its node identity,
// or "" when the fake has no Circle Hub (the conformance join cases then skip).
func (h *FakeHub) CircleHubConnection() string {
	if h.circle == nil {
		return ""
	}
	s, err := nipcw.EncodeCircleHubConnection(h.SignedCircleHubConnection())
	if err != nil {
		h.t.Fatalf("cashtest: circle hub connection: %v", err)
	}
	return s
}

// SignedCircleHubConnection is the Circle Hub connection record, signed by the
// node identity (WithCircleHub only).
func (h *FakeHub) SignedCircleHubConnection() nipcw.CircleHubConnection {
	sign, err := nipcash.LocalChainSigner(h.NodePriv, FakeChain)
	if err != nil {
		h.t.Fatalf("cashtest: signer: %v", err)
	}
	c, err := nipcw.SignCircleHubConnection(nipcw.CircleHubConnection{
		Pubkey: h.circle.xonly, Secret: h.circle.secret, Relays: h.RelayURLs(),
		Label: "Fake Circle", HasLabel: true, HubIdentity: h.nodeXOnly, Chain: FakeChain,
	}, sign, h.nodeXOnly)
	if err != nil {
		h.t.Fatalf("cashtest: sign circle hub connection: %v", err)
	}
	return c
}

// CirclePubkey is the Circle Hub connection's pubkey (TLV 0), and CirclePriv its
// private key, which encrypts a join's details (nipcw.EncryptDetails).
func (h *FakeHub) CirclePubkey() string { return h.circle.xonly }

// CirclePriv is the Circle Hub connection key's private half.
func (h *FakeHub) CirclePriv() string { return h.circle.priv }

// CircleSecret is the Circle Hub connection's secret (TLV 2): a join's bill proof
// recovers to its pubkey.
func (h *FakeHub) CircleSecret() string { return h.circle.secret }

// SetCircleWallet replaces the circle_wallet block get_info reports; a test drops
// or changes keys in a copy of DefaultCircleWallet.
func (h *FakeHub) SetCircleWallet(block map[string]any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.circle.wallet = block
}

// SetCircleChain sets the chain the Circle Hub's get_info reports.
func (h *FakeHub) SetCircleChain(chain string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.circle.chain = chain
}

// circleInfo is the Circle Hub's get_info result. With a ledger serving the
// circle, available_millis is its live room.
func (h *FakeHub) circleInfo() json.RawMessage {
	var avail uint64
	served := false
	if h.ledger != nil {
		avail, served = h.ledger.circleAvailable()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	block := h.circle.wallet
	if served {
		block = maps.Clone(block)
		block["available_millis"] = avail
	}
	raw, err := json.Marshal(map[string]any{
		"methods": []string{"get_info"}, "private_methods": CirclePrivateMethods,
		"network": FakeNetwork, "chain": h.circle.chain, "circle_wallet": block,
	})
	if err != nil {
		h.t.Errorf("cashtest: circle get_info: %v", err)
	}
	return raw
}
