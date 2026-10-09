package bunker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip46"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// Every NIP-46 signer can answer a relay's NIP-42 challenge.
var (
	_ relayclient.Signer = (*Client)(nil)
	_ relayclient.Signer = (*nip46.LocalKey)(nil)
)

// Handle answers a request with no relay at all.
func TestHandleWithoutRelay(t *testing.T) {
	k, _ := nip46.NewLocalKey(userPriv)
	var got []Decision
	srv, err := NewServer(ServerConfig{Key: k, Relays: []string{"wss://unused.example"},
		Policy:     PolicyFunc(func(context.Context, *Call) error { return nil }),
		OnDecision: func(d Decision) { got = append(got, d) }})
	if err != nil {
		t.Fatal(err)
	}
	app, _ := nip46.NewLocalKey(peerPriv)
	ask := func(method string, params ...string) *nip46.ResponseEvent {
		t.Helper()
		ev, _, err := nip46.NewRequestEvent(app.PrivKeyHex(), srv.TransportPubKey(), method, params, nip46.EncryptionNIP04)
		if err != nil {
			t.Fatal(err)
		}
		_ = ev.Sign(app.PrivKeyHex())
		req, err := nip46.ParseRequestEvent(ev, k.PrivKeyHex())
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Handle(context.Background(), req, nip46.EncryptionNIP04)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := nip46.ParseResponseEvent(resp, app.PrivKeyHex())
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}

	if r := ask(nip46.MethodConnect, srv.TransportPubKey(), "chosen"); r.Error == "" {
		t.Error("connect accepted with no armed secret")
	}
	srv.ArmSecret("chosen", time.Minute)
	if r := ask(nip46.MethodConnect, srv.TransportPubKey(), "chosen"); r.Result != "ack" {
		t.Errorf("connect with armed secret = %+v", r)
	}
	r := ask(nip46.MethodSignEvent, `{"kind":1,"content":"x","tags":[],"created_at":1700000000}`)
	if r.Error != "" || got[len(got)-1].Result != r.Result || !strings.Contains(r.Result, `"sig"`) {
		t.Errorf("sign = %+v, decision result %q", r, got[len(got)-1].Result)
	}
	srv.ArmSecret("other", time.Minute)
	srv.ArmSecret("", 0)
	if r := ask(nip46.MethodConnect, srv.TransportPubKey(), "other"); r.Error == "" {
		t.Error("disarmed secret accepted")
	}
}

// Without relays a server still answers through Handle, but can't Run.
func TestServerWithoutRelays(t *testing.T) {
	k, _ := nip46.NewLocalKey(userPriv)
	srv, err := NewServer(ServerConfig{Key: k, Policy: PolicyFunc(func(context.Context, *Call) error { return nil })})
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.switchRelaysJSON(); got != "null" {
		t.Errorf("switch_relays = %s, want null", got)
	}
	if err := srv.Run(context.Background()); err == nil {
		t.Error("Run without relays succeeded")
	}
}
