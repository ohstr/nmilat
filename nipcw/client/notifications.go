package client

import (
	"encoding/json"
	"sync"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
)

// RotationEvent is a parsed rotation or freeze notification (NIP-CW §Recovering a
// Lost Connection). Type is one of nip47's NotificationRotationPending,
// NotificationRotationCancelled, NotificationRotationCompleted and
// NotificationWalletFrozen; ConnectionPubkey is the new key (empty on a freeze),
// CompletesAt set on a pending rotation only.
type RotationEvent struct {
	Type             string
	ConnectionPubkey string
	CompletesAt      int64
}

// ParseRotationNotification reads n as a rotation or freeze notification; false
// for any other type or a payload without its fields. While a rotation is
// pending, a request by the old key cancels it, so a caller pauses its
// background requests.
func ParseRotationNotification(n *nip47.Notification) (RotationEvent, bool) {
	if n == nil {
		return RotationEvent{}, false
	}
	switch n.NotificationType {
	case nip47.NotificationRotationPending:
		var p nip47.RotationPending
		if json.Unmarshal(n.Notification, &p) != nil || p.ConnectionPubkey == "" || p.CompletesAt <= 0 {
			return RotationEvent{}, false
		}
		return RotationEvent{Type: n.NotificationType, ConnectionPubkey: p.ConnectionPubkey, CompletesAt: p.CompletesAt}, true
	case nip47.NotificationRotationCancelled, nip47.NotificationRotationCompleted:
		var p nip47.RotationChanged
		if json.Unmarshal(n.Notification, &p) != nil || p.ConnectionPubkey == "" {
			return RotationEvent{}, false
		}
		return RotationEvent{Type: n.NotificationType, ConnectionPubkey: p.ConnectionPubkey}, true
	case nip47.NotificationWalletFrozen:
		var p map[string]json.RawMessage
		if len(n.Notification) > 0 && json.Unmarshal(n.Notification, &p) != nil {
			return RotationEvent{}, false
		}
		return RotationEvent{Type: n.NotificationType}, true
	}
	return RotationEvent{}, false
}

// WalletGuard tracks one member wallet's freeze and rotation state, so a client
// sends nothing a Hub would refuse or that would cancel a rotation. After
// wallet_frozen or a FROZEN refusal the wallet is frozen: no payout with its
// current key until Unfrozen (the member's unfreeze applied) or a completed
// rotation installs a new key. The zero value is not usable; use NewWalletGuard.
type WalletGuard struct {
	mu      sync.Mutex
	key     string
	frozen  bool
	pending *RotationEvent
}

// NewWalletGuard guards the wallet whose current connection key is currentKey.
func NewWalletGuard(currentKey string) *WalletGuard { return &WalletGuard{key: currentKey} }

// Observe applies a notification the wallet's current key received.
func (g *WalletGuard) Observe(ev RotationEvent) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch ev.Type {
	case nip47.NotificationWalletFrozen:
		g.frozen = true
	case nip47.NotificationRotationPending:
		e := ev
		g.pending = &e
	case nip47.NotificationRotationCancelled:
		g.pending = nil
	case nip47.NotificationRotationCompleted:
		g.key, g.frozen, g.pending = ev.ConnectionPubkey, false, nil
	}
}

// ObserveCode applies a refusal: FROZEN freezes the wallet.
func (g *WalletGuard) ObserveCode(code string) {
	if code == nipcw.ErrFrozen {
		g.mu.Lock()
		g.frozen = true
		g.mu.Unlock()
	}
}

// Unfrozen records that the member's unfreeze was applied.
func (g *WalletGuard) Unfrozen() {
	g.mu.Lock()
	g.frozen = false
	g.mu.Unlock()
}

// MayPay reports whether a payout signed by key may be sent: key is the
// wallet's current key and the wallet is not frozen.
func (g *WalletGuard) MayPay(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return key == g.key && !g.frozen
}

// PendingRotation returns the pending rotation, if any: while it is pending, the
// caller pauses background requests, which would cancel it.
func (g *WalletGuard) PendingRotation() (RotationEvent, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending == nil {
		return RotationEvent{}, false
	}
	return *g.pending, true
}

// Key is the wallet's current connection key.
func (g *WalletGuard) Key() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.key
}
