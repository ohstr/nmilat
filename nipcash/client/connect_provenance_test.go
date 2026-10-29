package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
)

// NIP-CASH §Mint Provenance: a bill's provenance is verified against the Hub the caller expects before any of its
// relays is dialled, so a tampered copy never learns the caller's address. Connect dials nothing at all; a verified
// bill's relays are dialled when a bill method runs.
func TestConnect_VerifiesProvenanceBeforeDialling(t *testing.T) {
	hub := cashtest.NewFakeHub(t)
	l := hub.ServeWithdrawals(t, nil)
	priv, pub := sessionKeypair(t)
	tok := l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: 1000})

	var dialled atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { dialled.Add(1) }))
	t.Cleanup(attacker.Close)
	decoded, err := nipcash.Decode(tok)
	if err != nil {
		t.Fatal(err)
	}
	rehinted := decoded
	rehinted.RelayURLs = []string{"ws" + strings.TrimPrefix(attacker.URL, "http")}
	tampered, err := nipcash.Encode(rehinted)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := e2eContext(t)
	defer cancel()

	expect := WithExpectedMinter(hub.NodeXOnly())
	for name, s := range map[string]string{"relay hints replaced": tampered, "the same, with a cash secret": tampered + "#" + strings.Repeat("ab", 32)} {
		if _, err := Connect(ctx, s, expect); !errors.Is(err, ErrBillUnverified) {
			t.Errorf("%s: %v, want ErrBillUnverified", name, err)
		}
	}
	if _, err := Connect(ctx, tok, WithExpectedMinter(strings.Repeat("07", 32))); !errors.Is(err, ErrBillUnverified) {
		t.Errorf("another expected Hub: %v", err)
	}
	zeroSig := decoded
	zeroSig.MintSignature = make([]byte, 65)
	zs, err := nipcash.Encode(zeroSig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Connect(ctx, zs); !errors.Is(err, ErrBillUnverified) {
		t.Errorf("a signature that recovers no key: %v", err)
	}
	// With no expected Hub, Connect still dials nothing: the tampered copy is bound to the key it recovers only
	// once a bill method runs.
	if c, err := Connect(ctx, tampered); err != nil {
		t.Errorf("a recoverable signature with no expected Hub: %v", err)
	} else {
		c.Close()
	}
	zap := decoded
	zap.Scheme = nipcash.SchemeZapV1
	zapS, err := nipcash.Encode(zap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Connect(ctx, zapS); !errors.Is(err, ErrZapContextRequired) {
		t.Errorf("a zap bill without its context: %v", err)
	}
	if n := dialled.Load(); n != 0 {
		t.Fatalf("the tampered bill's relay was dialled %d times", n)
	}

	compressed, ok := nipcash.VerifyProvenance(decoded)
	if !ok || len(compressed) != 66 {
		t.Fatalf("minter %q", compressed)
	}
	if _, err := Connect(ctx, tok, WithExpectedMinter(compressed)); err != nil {
		t.Errorf("the bill as minted, its Hub given compressed: %v", err)
	}
	c, err := Connect(ctx, tok, expect)
	if err != nil {
		t.Fatalf("the bill as minted: %v", err)
	}
	defer c.Close()
	if _, err := c.CashStatus(ctx, nipcash.BySigning(priv), ""); err != nil {
		t.Fatalf("CashStatus on the bill as minted: %v", err)
	}
}
