package client

import (
	"context"
	"errors"

	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// Freeze enforcement (NIP-CW §Freezing). This package sends no payouts itself:
// a member's wallet is a plain NIP-47 connection the caller drives. A caller
// keeps one WalletGuard per wallet, feeds it the wallet's notifications
// (Observe) and refusals (ObserveRefusal, or Do does it), and sends every request
// signed by the wallet key through Do, or checks Check first. Once the wallet is
// frozen, its funds move again only after the member's unfreeze was applied
// (Unfrozen) or with the key a completed rotation installs (rotation_completed):
// never by retrying with the frozen key.

var (
	// ErrWalletFrozen is a request with a frozen wallet's key: the Hub would
	// refuse it with FROZEN. Nothing was sent.
	ErrWalletFrozen = errors.New("nipcw/client: the wallet is frozen; its funds move again only after an unfreeze or with the key a completed rotation installs")
	// ErrStaleKey is a request with a key that is not the wallet's current key,
	// such as the one a completed rotation replaced. Nothing was sent.
	ErrStaleKey = errors.New("nipcw/client: this is not the wallet's current key")
)

// Check reports whether a request signed by key may be sent: ErrStaleKey for a
// key other than the wallet's current one, ErrWalletFrozen while the wallet is
// frozen, nil otherwise. A pending rotation does not stop it: a request by the
// current key cancels the rotation (unless the wallet is frozen), which the
// caller weighs with PendingRotation.
func (g *WalletGuard) Check(key string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case key != g.key:
		return ErrStaleKey
	case g.frozen:
		return ErrWalletFrozen
	}
	return nil
}

// ObserveRefusal applies a refusal of a request signed by key: FROZEN freezes
// the wallet when key is its current key. A refusal of a key a rotation already
// replaced says nothing about the new key.
func (g *WalletGuard) ObserveRefusal(key, code string) {
	if code != nipcw.ErrFrozen {
		return
	}
	g.mu.Lock()
	if key == g.key {
		g.frozen = true
	}
	g.mu.Unlock()
}

// Do sends one request signed by key through call, guarded: Check first, and
// call is not made when it fails; afterwards a FROZEN refusal in call's error
// (a *relayclient.WalletError) freezes the wallet. call's error is returned as
// is.
func (g *WalletGuard) Do(ctx context.Context, key string, call func(ctx context.Context) error) error {
	if err := g.Check(key); err != nil {
		return err
	}
	err := call(ctx)
	var we *relayclient.WalletError
	if errors.As(err, &we) {
		g.ObserveRefusal(key, we.Code)
	}
	return err
}
