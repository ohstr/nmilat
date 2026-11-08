package transport

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// testGrant returns a connection secret (+ its x-only pubkey), a delegate
// pubkey, and valid GrantParams delegating cash_status to that delegate.
func testGrant(t *testing.T) (connSecret, connXOnly, delegate string, g GrantParams) {
	t.Helper()
	connSecret, connXOnly = testKeypair(t)
	_, delegate = testKeypair(t)
	_, target := testKeypair(t)
	_, hub := testKeypair(t)
	g = GrantParams{
		Delegate:  delegate,
		Target:    target,
		HubXOnly:  hub,
		Method:    "cash_status",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	return connSecret, connXOnly, delegate, g
}

func grantBinding(g GrantParams) GrantBinding {
	return GrantBinding{Target: g.Target, HubXOnly: g.HubXOnly, Method: g.Method}
}

func TestGrant_RoundTrip(t *testing.T) {
	connSecret, connXOnly, delegate, g := testGrant(t)
	g.MaxAmount = 50000
	g.SingleUse = true
	raw, err := BuildGrant(connSecret, g)
	if err != nil {
		t.Fatalf("BuildGrant: %v", err)
	}
	info, err := VerifyGrant(raw, grantBinding(g), time.Now())
	if err != nil {
		t.Fatalf("VerifyGrant: %v", err)
	}
	if info.ConnKey != connXOnly {
		t.Errorf("ConnKey = %q, want the connection key %q", info.ConnKey, connXOnly)
	}
	if info.Delegate != delegate {
		t.Errorf("Delegate = %q, want %q", info.Delegate, delegate)
	}
	if info.MaxAmount != 50000 {
		t.Errorf("MaxAmount = %d, want 50000", info.MaxAmount)
	}
	if !info.SingleUse {
		t.Error("SingleUse = false, want true")
	}
	if info.ExpiresAt != g.ExpiresAt {
		t.Errorf("ExpiresAt = %d, want %d", info.ExpiresAt, g.ExpiresAt)
	}
	if info.ID == "" {
		t.Error("ID is empty; needed for single-use tracking")
	}
}

func TestGrant_DefaultsAreUnboundedReusable(t *testing.T) {
	connSecret, _, _, g := testGrant(t) // no MaxAmount, no SingleUse
	raw, err := BuildGrant(connSecret, g)
	if err != nil {
		t.Fatal(err)
	}
	info, err := VerifyGrant(raw, grantBinding(g), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxAmount != 0 {
		t.Errorf("MaxAmount = %d, want 0 (no cap)", info.MaxAmount)
	}
	if info.SingleUse {
		t.Error("SingleUse = true, want false (reusable by default)")
	}
}

func TestGrant_BindingMismatches(t *testing.T) {
	cases := map[string]struct {
		mutate func(*GrantBinding)
		want   error
	}{
		"different bill":   {func(b *GrantBinding) { _, b.Target = testKeypair(t) }, ErrGrantWrongTarget},
		"different hub":    {func(b *GrantBinding) { _, b.HubXOnly = testKeypair(t) }, ErrGrantWrongHub},
		"different method": {func(b *GrantBinding) { b.Method = "cash_redeem" }, ErrGrantWrongMethod},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			connSecret, _, _, g := testGrant(t)
			raw, err := BuildGrant(connSecret, g)
			if err != nil {
				t.Fatal(err)
			}
			b := grantBinding(g)
			tc.mutate(&b)
			if _, err := VerifyGrant(raw, b, time.Now()); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGrant_Expired(t *testing.T) {
	connSecret, _, _, g := testGrant(t)
	g.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	raw, err := BuildGrant(connSecret, g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGrant(raw, grantBinding(g), time.Now()); !errors.Is(err, ErrGrantExpired) {
		t.Errorf("err = %v, want ErrGrantExpired", err)
	}
}

func TestGrant_FromFuture(t *testing.T) {
	connSecret, _, _, g := testGrant(t)
	raw, err := BuildGrant(connSecret, g)
	if err != nil {
		t.Fatal(err)
	}
	// Verify with a clock well before the grant was created: its created_at is
	// then in the future relative to "now".
	past := time.Now().Add(-10 * time.Minute)
	if _, err := VerifyGrant(raw, grantBinding(g), past); !errors.Is(err, ErrGrantFromFuture) {
		t.Errorf("err = %v, want ErrGrantFromFuture", err)
	}
}

func TestGrant_TamperedSignatureFails(t *testing.T) {
	connSecret, _, _, g := testGrant(t)
	raw, err := BuildGrant(connSecret, g)
	if err != nil {
		t.Fatal(err)
	}
	var ev nip01.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	s := []byte(ev.Sig)
	if s[0] == '0' {
		s[0] = '1'
	} else {
		s[0] = '0'
	}
	ev.Sig = string(s)
	tampered, _ := json.Marshal(ev)
	if _, err := VerifyGrant(tampered, grantBinding(g), time.Now()); !errors.Is(err, ErrGrantSignature) {
		t.Errorf("err = %v, want ErrGrantSignature", err)
	}
}

// TestGrant_BillProofIsNotAGrant: a kind-23193 bill proof must NOT verify as a
// grant. The kind separation is load-bearing — the same reason a slice proof
// must not verify as a bill proof.
func TestGrant_BillProofIsNotAGrant(t *testing.T) {
	connSecret, b := testBinding(t)
	billProof, err := BuildBillProof(connSecret, b)
	if err != nil {
		t.Fatal(err)
	}
	want := GrantBinding{Target: b.Target, HubXOnly: b.HubXOnly, Method: b.Method}
	if _, err := VerifyGrant(billProof, want, time.Now()); !errors.Is(err, ErrGrantMalformed) {
		t.Errorf("err = %v, want ErrGrantMalformed (a bill proof is not a grant)", err)
	}
}

func TestGrant_BuildRequiresCoreFields(t *testing.T) {
	connSecret, _, _, base := testGrant(t)
	for name, mutate := range map[string]func(*GrantParams){
		"no delegate": func(g *GrantParams) { g.Delegate = "" },
		"no target":   func(g *GrantParams) { g.Target = "" },
		"no hub":      func(g *GrantParams) { g.HubXOnly = "" },
		"no method":   func(g *GrantParams) { g.Method = "" },
		"no expiry":   func(g *GrantParams) { g.ExpiresAt = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			g := base
			mutate(&g)
			if _, err := BuildGrant(connSecret, g); !errors.Is(err, ErrGrantMalformed) {
				t.Errorf("err = %v, want ErrGrantMalformed", err)
			}
		})
	}
}
