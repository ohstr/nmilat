package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// ErrDustNotConfirmed is a deletion the member did not confirm after being told
// that any dust left goes to the host. Nothing was sent.
var ErrDustNotConfirmed = errors.New("nipcw/client: the member did not confirm that dust goes to the host")

// DeleteWallet deletes the member's own Circle Wallet over its own connection
// (NIP-CW §Deleting a Circle Wallet): delete_circle_wallet with params {}.
// confirmDust tells the member that any dust left goes to the host (a client
// SHOULD pay out first) and returns whether to go on; nil or false sends
// nothing. A refusal (RESTRICTED while it holds more than dust or has a payment
// in flight, FROZEN, …) is a *relayclient.WalletError.
func DeleteWallet(ctx context.Context, w nipcw.WalletConnection, confirmDust func(ctx context.Context) bool) error {
	if confirmDust == nil || !confirmDust(ctx) {
		return ErrDustNotConfirmed
	}
	nwc, err := relayclient.NewNWCClient(ctx, &nip47.PairingInfo{
		WalletPubkey: w.WalletPubkey, RelayURLs: w.Relays, Secret: w.Secret,
	}, nip47.EncryptionNIP44V2)
	if err != nil {
		return err
	}
	defer nwc.Close()
	resp, err := nwc.Call(ctx, nipcw.MethodDeleteCircleWallet, struct{}{})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return &relayclient.WalletError{Method: nipcw.MethodDeleteCircleWallet, Code: resp.Error.Code, Message: resp.Error.Message}
	}
	if resp.ResultType != "" && resp.ResultType != nipcw.MethodDeleteCircleWallet {
		return fmt.Errorf("nipcw/client: delete_circle_wallet answered as %q", resp.ResultType)
	}
	return nil
}
