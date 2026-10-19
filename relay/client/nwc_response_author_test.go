package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
)

// testAttackerPrivKey is anyone watching the relay: not the wallet.
const testAttackerPrivKey = "1111111111111111111111111111111111111111111111111111111111111111"

// forgedPayInvoiceResponse is a reply to reqEvent signed by privKey, encrypted
// to the app under privKey's own key, so it decrypts fine for the app.
func forgedPayInvoiceResponse(t *testing.T, privKey string, reqEvent *nip01.Event, preimage string) *nip01.Event {
	t.Helper()
	ev, err := nip47.NewResponseEvent(privKey, reqEvent.PubKey, nip47.MethodPayInvoice,
		nip47.PayInvoiceResult{Preimage: preimage}, reqEvent, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return ev
}

func payInvoiceWithin(t *testing.T, pairing *nip47.PairingInfo, timeout time.Duration) (*nip47.PayInvoiceResult, error) {
	t.Helper()
	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
}

// A reply from another key that arrives first is dropped, and the wallet's own
// reply after it is the one returned.
func TestNWCClient_IgnoresAResponseFromAnotherKey(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		return []*nip01.Event{
			forgedPayInvoiceResponse(t, testAttackerPrivKey, reqEvent, "forged"),
			signedPayInvoiceResponse(t, reqEvent, "deadbeef"),
		}
	})
	result, err := payInvoiceWithin(t, pairing, 5*time.Second)
	if err != nil {
		t.Fatalf("PayInvoice() error = %v", err)
	}
	if result.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want the wallet's %q", result.Preimage, "deadbeef")
	}
}

// With only a reply from another key, the call times out: it never returns the
// forged result.
func TestNWCClient_NeverReturnsAForgedResponse(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		return []*nip01.Event{forgedPayInvoiceResponse(t, testAttackerPrivKey, reqEvent, "forged")}
	})
	result, err := payInvoiceWithin(t, pairing, 300*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("PayInvoice() = %+v, %v; want context.DeadlineExceeded", result, err)
	}
}

// A reply that names the wallet's pubkey but carries a bad signature is dropped.
func TestNWCClient_IgnoresAResponseWithABadSignature(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		ev := signedPayInvoiceResponse(t, reqEvent, "forged")
		sig := []byte(ev.Sig)
		sig[0] ^= 1
		ev.Sig = string(sig)
		return []*nip01.Event{ev}
	})
	result, err := payInvoiceWithin(t, pairing, 300*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("PayInvoice() = %+v, %v; want context.DeadlineExceeded", result, err)
	}
}
