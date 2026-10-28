package cashtest_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip13"
	"github.com/ohstr/nmilat/nipcash/transport"
)

func powEvent(t *testing.T, kind int, exp int64, difficulty int) *nip01.Event {
	t.Helper()
	priv, pub := cashtest.Keypair(t)
	ev := nip01.NewEvent(kind, "x")
	ev.PubKey = pub
	if exp != 0 {
		ev.Tags = append(ev.Tags, []string{"expiration", strconv.FormatInt(exp, 10)})
	}
	if difficulty > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := ev.Mine(ctx, difficulty); err != nil {
			t.Fatal(err)
		}
	}
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ev
}

// K-POW-4 (CASH-POW-04): the PoW relay double enforces the minimum, the
// expiration window to the second and id dedup, on kind 23190 only, and
// advertises the minimum in NIP-11.
func TestPowRelay_KPow4(t *testing.T) {
	r := cashtest.NewRelay(t)
	r.SetMinPow(6)
	const T = int64(1_900_000_000)
	r.SetPowClock(func() time.Time { return time.Unix(T, 0) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if n, err := transport.RelayPowMinimum(ctx, r.URL()); err != nil || n != 6 {
		t.Fatalf("NIP-11 minimum %d (%v), want 6", n, err)
	}

	req := transport.KindPrivateRequest
	if ok, msg := r.Publish(powEvent(t, req, T+60, 0)); ok || msg != "pow: difficulty 6 required" {
		t.Errorf("unmined: %v %q", ok, msg)
	}
	if ev := powEvent(t, req, T+60, 6); func() bool { d, _ := nip13.Difficulty(ev.ID); return d < 6 }() {
		t.Fatal("mining fell short")
	}
	for name, exp := range map[string]int64{"absent": 0, "past": T - 1, "T+86401": T + 86401} {
		if ok, _ := r.Publish(powEvent(t, req, exp, 6)); ok {
			t.Errorf("expiration %s accepted", name)
		}
	}
	for name, exp := range map[string]int64{"T": T, "T+86400": T + 86400} {
		if ok, msg := r.Publish(powEvent(t, req, exp, 6)); !ok {
			t.Errorf("expiration %s refused: %s", name, msg)
		}
	}
	ev := powEvent(t, req, T+60, 6)
	if ok, msg := r.Publish(ev); !ok {
		t.Fatal(msg)
	}
	if ok, _ := r.Publish(ev); ok {
		t.Error("a repeated id was accepted before its expiration")
	}
	r.SetPowClock(func() time.Time { return time.Unix(T+61, 0) })
	if ok, _ := r.Publish(ev); ok {
		t.Error("an expired event was accepted")
	}

	// Other kinds are untouched, and 0 turns enforcement off.
	if ok, msg := r.Publish(powEvent(t, transport.KindPrivateResponse, 0, 0)); !ok {
		t.Errorf("kind 23191 refused: %s", msg)
	}
	r.SetMinPow(0)
	if ok, msg := r.Publish(powEvent(t, req, 0, 0)); !ok {
		t.Errorf("enforcement off, refused: %s", msg)
	}
}
