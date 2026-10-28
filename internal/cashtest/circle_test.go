package cashtest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// The fake's Circle Hub: off by default; with WithCircleHub a signed circlehub1
// string whose get_info carries the circle_wallet block (identity = TLV 4, every
// "always" key) and refuses a join on the standard transport.
func TestFakeHub_CircleHub(t *testing.T) {
	if s := cashtest.NewFakeHub(t).CircleHubConnection(); s != "" {
		t.Fatalf("a fake without a Circle Hub returned %q", s)
	}
	h := cashtest.NewFakeHub(t, cashtest.WithCircleHub())
	c, err := nipcw.DecodeCircleHubConnection(h.CircleHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(); err != nil || c.HubIdentity != h.NodeXOnly() || c.Pubkey != h.CirclePubkey() {
		t.Fatalf("connection %+v, verify %v", c, err)
	}
	nwc, err := relayclient.NewNWCClient(context.Background(), &nip47.PairingInfo{
		WalletPubkey: c.Pubkey, RelayURLs: c.Relays, Secret: c.Secret}, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatal(err)
	}
	defer nwc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info, err := nwc.GetInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cw := info.CircleWallet
	if cw == nil || cw.Identity != h.NodeXOnly() || len(cw.MissingAlways()) != 0 || cw.Accepting == nil || !*cw.Accepting || info.Chain != cashtest.FakeChain {
		t.Fatalf("circle_wallet %+v (missing %v)", cw, cw.MissingAlways())
	}
	block := cashtest.DefaultCircleWallet(h.NodeXOnly())
	delete(block, "fees_ppm")
	h.SetCircleWallet(block)
	if info, err = nwc.GetInfo(ctx); err != nil || len(info.CircleWallet.MissingAlways()) != 1 {
		t.Fatalf("dropped fees_ppm: %v %v", info, err)
	}
	resp, err := nwc.Call(ctx, nipcw.MethodCreateCircleWallet, map[string]any{})
	var we *relayclient.WalletError
	if !errors.As(err, &we) && (err != nil || resp.Error == nil || resp.Error.Code != "NOT_IMPLEMENTED") {
		t.Fatalf("standard-transport join: %+v %v", resp, err)
	}
}
