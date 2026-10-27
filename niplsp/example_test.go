package niplsp_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/niplsp"
	"github.com/ohstr/nmilat/utils"
)

// A publisher builds its announcement from its own LSPS answers and has its
// node sign it; a client checks it and, before buying, compares it with the
// live answers.
func Example() {
	// The LSP's own answers, as its LSPS handlers give them.
	protocols := []int{2}
	menu := json.RawMessage(`{"opening_fee_params_menu": [{"min_fee_msat": "2000000", "proportional": 4000,
		"valid_until": "2026-10-22T00:00:00.000Z", "min_lifetime": 4320, "max_client_to_self_delay": 2016,
		"min_payment_size_msat": "10000000", "max_payment_size_msat": "4000000000", "promise": "x"}]}`)

	fields, err := niplsp.FromLSPSInfo(protocols, nil, menu, nil, niplsp.Meta{
		NodeKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", // the node id
		Addrs:   []string{"203.0.113.7:9735"},
		Chain:   "bitcoin",
		Network: "mainnet",
		Display: niplsp.Display{Title: "Alice's Liquidity"},
	})
	if err != nil {
		panic(err)
	}
	ev, err := niplsp.NewAnnouncement(fields, 1792713600)
	if err != nil {
		panic(err)
	}

	// The node signs SHA-256 of the payload with its key (BIP-340). Here a
	// local key stands in for the node's signing RPC.
	priv, _ := utils.ParsePrivateKeyHex("0000000000000000000000000000000000000000000000000000000000000001")
	node := func(_ context.Context, payload []byte) ([]byte, error) {
		h := sha256.Sum256(payload)
		sig, err := schnorr.Sign(priv, h[:])
		if err != nil {
			return nil, err
		}
		return sig.Serialize(), nil
	}
	if err := niplsp.Sign(context.Background(), ev, node); err != nil {
		panic(err)
	}

	// A client.
	a, err := niplsp.ParseAnnouncement(ev, niplsp.CheckOptions{
		Chains: []string{"bitcoin"}, Networks: []string{"mainnet"}, Now: 1792713600,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(a.DisplayTitle(), a.NodeIDs()[0][:8])

	live, _ := niplsp.ParseLSPS2Menu(menu)
	live[0].MinFeeMillis = 3000000
	diff := niplsp.CheckLive(a, niplsp.Live{Protocols: []int{2}, LSPS2Menu: live})
	for _, f := range diff.Changed() {
		fmt.Println(f.Field, f.Announced, "->", f.Live, f.Verdict)
	}
	// Output:
	// Alice's Liquidity 0279be66
	// lsps2_fee[0].min_fee 2000000 -> 3000000 worse
}
