package client

import "testing"

// Info returns the get_info read at Connect, which passed the online check.
func TestClientInfo(t *testing.T) {
	hub := newCircle(t)
	ctx, cancel := testContext(t)
	defer cancel()
	cl := connect(t, ctx, hub)
	gi := cl.Info()
	if gi == nil || gi.CircleWallet == nil || gi.Chain == "" {
		t.Fatalf("Info() = %+v", gi)
	}
	gi.Chain = "changed"
	if cl.Info().Chain == "changed" {
		t.Error("Info() shares the client's copy")
	}
}
