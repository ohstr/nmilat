package client

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// WP-12 Freeze: after wallet_frozen or a FROZEN refusal, funds move again only
// after unfreeze or with the key a completed rotation installs, never by
// retrying with the frozen key.
func TestWalletGuard_FreezeEnforced(t *testing.T) {
	const old, newKey = "aa", "bb"
	ctx := context.Background()
	calls := 0
	pay := func(code string) func(context.Context) error {
		return func(context.Context) error {
			calls++
			if code != "" {
				return &relayclient.WalletError{Method: "pay_invoice", Code: code, Message: "test"}
			}
			return nil
		}
	}

	g := NewWalletGuard(old)
	if err := g.Do(ctx, old, pay("")); err != nil || calls != 1 {
		t.Fatalf("an unfrozen wallet pays: %v, %d calls", err, calls)
	}

	// A FROZEN refusal freezes it; the retry with the frozen key is never sent.
	var we *relayclient.WalletError
	if err := g.Do(ctx, old, pay(nipcw.ErrFrozen)); !errors.As(err, &we) || calls != 2 {
		t.Fatalf("the refusal is returned as is: %v", err)
	}
	if err := g.Do(ctx, old, pay("")); !errors.Is(err, ErrWalletFrozen) || calls != 2 {
		t.Fatalf("retry with the frozen key: %v, %d calls; want ErrWalletFrozen and nothing sent", err, calls)
	}
	if err := g.Check(old); !errors.Is(err, ErrWalletFrozen) {
		t.Fatalf("Check = %v", err)
	}

	// unfreeze lifts it.
	g.Unfrozen()
	if err := g.Do(ctx, old, pay("")); err != nil || calls != 3 {
		t.Fatalf("after unfreeze: %v, %d calls", err, calls)
	}

	// wallet_frozen, then a completed rotation: the new key pays, the old never.
	g.Observe(RotationEvent{Type: nip47.NotificationWalletFrozen})
	if err := g.Check(old); !errors.Is(err, ErrWalletFrozen) {
		t.Fatalf("wallet_frozen: Check = %v", err)
	}
	g.Observe(RotationEvent{Type: nip47.NotificationRotationCompleted, ConnectionPubkey: newKey})
	if err := g.Do(ctx, old, pay("")); !errors.Is(err, ErrStaleKey) || calls != 3 {
		t.Fatalf("the replaced key: %v, %d calls; want ErrStaleKey and nothing sent", err, calls)
	}
	if err := g.Do(ctx, newKey, pay("")); err != nil || calls != 4 {
		t.Fatalf("the rotated key: %v, %d calls", err, calls)
	}

	// A FROZEN refusal of the replaced key says nothing about the new one.
	g.ObserveRefusal(old, nipcw.ErrFrozen)
	if err := g.Check(newKey); err != nil {
		t.Fatalf("a stale key's refusal froze the new key: %v", err)
	}
	g.ObserveRefusal(newKey, nipcw.ErrRestricted)
	if err := g.Check(newKey); err != nil {
		t.Fatalf("another code froze the wallet: %v", err)
	}
	g.ObserveRefusal(newKey, nipcw.ErrFrozen)
	if err := g.Check(newKey); !errors.Is(err, ErrWalletFrozen) {
		t.Fatalf("FROZEN on the current key: %v", err)
	}
}
