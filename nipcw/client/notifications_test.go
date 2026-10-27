package client

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
)

func note(typ, body string) *nip47.Notification {
	return &nip47.Notification{NotificationType: typ, Notification: json.RawMessage(body)}
}

// T12-15 (S-CW-106, 113): the notifications parse; after wallet_frozen no payout
// goes with that key until an unfreeze or a completed rotation.
func TestRotationNotifications(t *testing.T) {
	old, newKey := "aa", "bb"
	pending, ok := ParseRotationNotification(note(nip47.NotificationRotationPending, `{"connection_pubkey":"bb","completes_at":1720432000}`))
	if !ok || pending.CompletesAt != 1720000000+432000 || pending.ConnectionPubkey != newKey {
		t.Fatalf("pending: %+v %v", pending, ok)
	}
	frozen, ok := ParseRotationNotification(note(nip47.NotificationWalletFrozen, `{}`))
	if !ok || frozen.Type != nip47.NotificationWalletFrozen {
		t.Fatalf("frozen: %+v %v", frozen, ok)
	}
	for _, n := range []*nip47.Notification{
		nil,
		note(nip47.NotificationRotationPending, `{"connection_pubkey":"bb"}`),
		note(nip47.NotificationRotationCompleted, `{}`),
		note(nip47.NotificationPaymentReceived, `{}`),
	} {
		if _, ok := ParseRotationNotification(n); ok {
			t.Errorf("parsed %+v", n)
		}
	}

	g := NewWalletGuard(old)
	g.Observe(pending)
	if p, ok := g.PendingRotation(); !ok || p.CompletesAt != 1720432000 || !g.MayPay(old) {
		t.Fatal("a pending rotation pauses nothing but is reported")
	}
	cancelled, _ := ParseRotationNotification(note(nip47.NotificationRotationCancelled, `{"connection_pubkey":"bb"}`))
	g.Observe(cancelled)
	if _, ok := g.PendingRotation(); ok {
		t.Fatal("cancelled rotation still pending")
	}
	g.Observe(frozen)
	if g.MayPay(old) {
		t.Fatal("a frozen wallet may pay with its key")
	}
	g.Unfrozen()
	if !g.MayPay(old) {
		t.Fatal("an unfrozen wallet may pay again")
	}
	g.ObserveCode(nipcw.ErrFrozen)
	if g.MayPay(old) {
		t.Fatal("FROZEN freezes the wallet")
	}
	completed, _ := ParseRotationNotification(note(nip47.NotificationRotationCompleted, `{"connection_pubkey":"bb"}`))
	g.Observe(completed)
	if g.MayPay(old) || !g.MayPay(newKey) || g.Key() != newKey {
		t.Fatal("a completed rotation moves payouts to the new key and ends the freeze")
	}
}
