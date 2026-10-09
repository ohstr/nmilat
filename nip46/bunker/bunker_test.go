package bunker

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/relay"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

const (
	userPriv  = "0000000000000000000000000000000000000000000000000000000000000003"
	transPriv = "0000000000000000000000000000000000000000000000000000000000000007"
	peerPriv  = "0000000000000000000000000000000000000000000000000000000000000005"
)

// startRelay serves an in-process nmilat relay and returns its ws:// URL.
func startRelay(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "bunker-relay-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	rl, err := relay.New(f.Name(), &nip11.Metadata{Name: "test", Limitation: nip11.Limitation{MaxMessageLength: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rl)
	t.Cleanup(func() {
		srv.Close()
		_ = rl.Close()
	})
	return "ws://" + srv.Listener.Addr().String()
}

type harness struct {
	srv   *Server
	relay string
	mu    sync.Mutex
	calls []Decision
}

func (h *harness) decisions() []Decision {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Decision(nil), h.calls...)
}

// startServer runs a bunker on a fresh relay until the test ends. Key
// defaults to userPriv, Policy to allowing everything.
func startServer(t *testing.T, cfg ServerConfig) *harness {
	t.Helper()
	h := &harness{relay: startRelay(t)}
	if cfg.Key == nil {
		k, err := nip46.NewLocalKey(userPriv)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Key = k
	}
	if cfg.Policy == nil {
		cfg.Policy = PolicyFunc(func(context.Context, *Call) error { return nil })
	}
	if cfg.Relays == nil {
		cfg.Relays = []string{h.relay}
	}
	cfg.OnDecision = func(d Decision) {
		h.mu.Lock()
		h.calls = append(h.calls, d)
		h.mu.Unlock()
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitConnected(t, srv.RelayStatuses)
	return h
}

func waitConnected(t *testing.T, statuses func() []RelayStatus) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := statuses()
		if len(st) > 0 && st[0].Connected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay never connected: %+v", statuses())
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func dial(t *testing.T, h *harness, opts ClientOptions) *Client {
	t.Helper()
	uri, err := h.srv.NewBunkerURI(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(ctx5(t), uri, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func note(content string, tags ...[]string) *nip01.Event {
	if tags == nil {
		tags = [][]string{}
	}
	return &nip01.Event{Kind: 1, Content: content, Tags: tags, CreatedAt: 1700000000}
}

func TestURIRoundTrip(t *testing.T) {
	k, _ := nip46.NewLocalKey(userPriv)
	u := &URI{SignerPubKey: k.PubKey(), Relays: []string{"wss://a.example", "wss://b.example/x"}, Secret: "s3"}
	got, err := ParseURI(u.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.SignerPubKey != u.SignerPubKey || got.Secret != "s3" || strings.Join(got.Relays, ",") != strings.Join(u.Relays, ",") {
		t.Errorf("round trip = %+v", got)
	}
	got, err = ParseURI("bunker://" + strings.ToUpper(k.PubKey()) + "?relay=relay.example&relay=https://nope")
	if err != nil || got.Relays[0] != "wss://relay.example" || len(got.Relays) != 1 || got.Secret != "" {
		t.Errorf("schemeless relay = %+v, %v", got, err)
	}
	for _, bad := range []string{
		"nostrconnect://" + k.PubKey() + "?relay=wss://r",
		"bunker://nothex?relay=wss://r",
		"bunker://" + k.PubKey(),
		"bunker://" + k.PubKey() + "?relay=http://r",
	} {
		if _, err := ParseURI(bad); err == nil {
			t.Errorf("ParseURI(%q) succeeded", bad)
		}
	}
}

func TestNewServerValidates(t *testing.T) {
	k, _ := nip46.NewLocalKey(userPriv)
	allow := PolicyFunc(func(context.Context, *Call) error { return nil })
	cases := map[string]ServerConfig{
		"no key":      {Policy: allow, Relays: []string{"wss://r"}},
		"no policy":   {Key: k, Relays: []string{"wss://r"}},
		"bad relay":   {Key: k, Policy: allow, Relays: []string{"http://r"}},
		"shadow":      {Key: k, Policy: allow, Relays: []string{"wss://r"}, Methods: map[string]Handler{nip46.MethodPing: nil}},
		"remote key":  {Key: remoteKey{k}, Policy: allow, Relays: []string{"wss://r"}},
		"bad transpt": {Key: k, Policy: allow, Relays: []string{"wss://r"}, TransportKey: "zz"},
	}
	for name, cfg := range cases {
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("%s: NewServer succeeded", name)
		}
	}
}

// remoteKey hides that it's a LocalKey, like a key held elsewhere.
type remoteKey struct{ *nip46.LocalKey }

func TestDialSignRoundTrip(t *testing.T) {
	var seen []*Call
	var mu sync.Mutex
	h := startServer(t, ServerConfig{Policy: PolicyFunc(func(_ context.Context, c *Call) error {
		mu.Lock()
		seen = append(seen, c)
		mu.Unlock()
		return nil
	})})
	c := dial(t, h, ClientOptions{Perms: "sign_event:1", Metadata: &nip46.Metadata{Name: "test app"}})

	if c.PubKey() != h.srv.PubKey() || c.SignerPubKey() != h.srv.TransportPubKey() {
		t.Fatalf("pubkeys: client %s/%s server %s/%s", c.PubKey(), c.SignerPubKey(), h.srv.PubKey(), h.srv.TransportPubKey())
	}
	ev := note("hello", []string{"t", "x"})
	if err := c.Sign(ctx5(t), ev); err != nil {
		t.Fatal(err)
	}
	if err := ev.Verify(); err != nil || ev.PubKey != h.srv.PubKey() {
		t.Fatalf("signed event %+v: %v", ev, err)
	}
	if err := c.Ping(ctx5(t)); err != nil {
		t.Error(err)
	}

	mu.Lock()
	defer mu.Unlock()
	connect := seen[0]
	if connect.Method != nip46.MethodConnect || connect.Secret == "" || connect.Perms != "sign_event:1" ||
		connect.Metadata.Name != "test app" || connect.Client != c.Session().clientPubKey() {
		t.Errorf("connect call = %+v", connect)
	}
	var sign *Call
	for _, s := range seen {
		if s.Method == nip46.MethodSignEvent {
			sign = s
		}
	}
	if sign == nil || sign.Event.ID != ev.ID || sign.Encryption != nip46.EncryptionNIP44V2 {
		t.Errorf("sign call = %+v", sign)
	}
}

func (s Session) clientPubKey() string {
	k, _ := nip46.NewLocalKey(s.ClientKey)
	return k.PubKey()
}

func TestSecretIsSingleUseAndExpires(t *testing.T) {
	h := startServer(t, ServerConfig{})
	uri, _ := h.srv.NewBunkerURI(time.Minute)
	c, err := Dial(ctx5(t), uri, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if _, err := Dial(ctx5(t), uri, ClientOptions{}); !errors.Is(err, nip46.ErrDenied) {
		t.Errorf("reused secret: %v", err)
	}

	expired, _ := h.srv.NewBunkerURI(-time.Second)
	if _, err := Dial(ctx5(t), expired, ClientOptions{}); !errors.Is(err, nip46.ErrDenied) {
		t.Errorf("expired secret: %v", err)
	}

	cancelled, _ := h.srv.NewBunkerURI(time.Minute)
	h.srv.CancelPairing()
	if _, err := Dial(ctx5(t), cancelled, ClientOptions{}); !errors.Is(err, nip46.ErrDenied) {
		t.Errorf("cancelled secret: %v", err)
	}
	// A refused connect never reached the policy.
	for _, d := range h.decisions() {
		if d.Call.Method == nip46.MethodConnect && d.Allowed() && d.Call.Secret != "" && d.Call.Client != c.Session().clientPubKey() {
			t.Errorf("unexpected allowed connect: %+v", d.Call)
		}
	}
}

func TestPolicyDenialsAndGuard(t *testing.T) {
	h := startServer(t, ServerConfig{Policy: PolicyFunc(func(_ context.Context, c *Call) error {
		c.Rule = "notes-only"
		if c.Event != nil && c.Event.Kind != 1 {
			return nip46.Denyf("kind %d not allowed", c.Event.Kind)
		}
		if c.Method == "boom" {
			return errors.New("backend down")
		}
		return nil
	}), Methods: map[string]Handler{"boom": func(context.Context, *Call) (string, error) { return "", nil }}})
	c := dial(t, h, ClientOptions{})
	ctx := ctx5(t)

	ev := note("x")
	ev.Kind = 4
	err := c.Sign(ctx, ev)
	var e *nip46.Error
	if !errors.Is(err, nip46.ErrDenied) || !errors.As(err, &e) || e.Reason != "kind 4 not allowed" {
		t.Errorf("kind 4: %v", err)
	}
	nsec, _ := nip19.EncodePrivateKey(userPriv)
	if err := c.Sign(ctx, note("leak "+nsec)); !errors.Is(err, nip46.ErrDenied) {
		t.Errorf("guard: %v", err)
	}
	if _, err := c.Call(ctx, "boom"); !errors.Is(err, nip46.ErrDenied) || !strings.Contains(err.Error(), "backend down") {
		t.Errorf("plain policy error: %v", err)
	}
	if _, err := c.Call(ctx, "nope"); !errors.Is(err, nip46.ErrInvalid) {
		t.Errorf("unknown method: %v", err)
	}
	if _, err := c.Call(ctx, nip46.MethodSignEvent, "{bad"); !errors.Is(err, nip46.ErrInvalid) {
		t.Errorf("bad event: %v", err)
	}
	if err := c.Sign(ctx, note("fine")); err != nil {
		t.Errorf("allowed after denials: %v", err)
	}
	var denied int
	for _, d := range h.decisions() {
		if !d.Allowed() {
			denied++
		}
	}
	if denied != 5 {
		t.Errorf("denied decisions = %d, want 5", denied)
	}
}

func TestResumeWithoutSecret(t *testing.T) {
	h := startServer(t, ServerConfig{})
	c := dial(t, h, ClientOptions{})
	sess := c.Session()
	_ = c.Close()

	r, err := Resume(ctx5(t), sess, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if r.Session().ClientKey != sess.ClientKey || r.PubKey() != sess.UserPubKey {
		t.Errorf("resumed session %+v, want %+v", r.Session(), sess)
	}
	if err := r.Sign(ctx5(t), note("again")); err != nil {
		t.Fatal(err)
	}

	sess.UserPubKey = strings.Repeat("a", 64)
	if _, err := Resume(ctx5(t), sess, ClientOptions{}); err == nil {
		t.Error("Resume accepted a session for another user")
	}
}

func TestNostrconnectPairing(t *testing.T) {
	h := startServer(t, ServerConfig{})
	p, err := NewPairing([]string{h.relay}, ClientOptions{Perms: "sign_event:1", Metadata: &nip46.Metadata{Name: "scanner"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	waitConnected(t, p.c.RelayStatuses)

	schema, err := h.srv.AcceptNostrconnect(ctx5(t), p.URI())
	if err != nil {
		t.Fatal(err)
	}
	if schema.Metadata.Name != "scanner" || schema.Perms != "sign_event:1" {
		t.Errorf("schema = %+v", schema)
	}
	c, err := p.Wait(ctx5(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.SignerPubKey() != h.srv.TransportPubKey() || c.PubKey() != h.srv.PubKey() {
		t.Errorf("paired with %s as %s", c.SignerPubKey(), c.PubKey())
	}
	if err := c.Sign(ctx5(t), note("scanned")); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptNostrconnectOnForeignRelay(t *testing.T) {
	h := startServer(t, ServerConfig{})
	other := startRelay(t)
	p, err := NewPairing([]string{other}, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	waitConnected(t, p.c.RelayStatuses)
	if _, err := h.srv.AcceptNostrconnect(ctx5(t), p.URI()); err != nil {
		t.Fatal(err)
	}
	c, err := p.Wait(ctx5(t))
	if err != nil {
		t.Fatal(err)
	}
	// The server keeps listening on the app's relay.
	if err := c.Sign(ctx5(t), note("foreign")); err != nil {
		t.Fatal(err)
	}
	dead, _ := url.Parse("ws://127.0.0.1:1")
	q := url.Values{"relay": {dead.String()}, "secret": {"s"}}
	k, _ := nip46.NewLocalKey(peerPriv)
	if _, err := h.srv.AcceptNostrconnect(ctx5(t), "nostrconnect://"+k.PubKey()+"?"+q.Encode()); !errors.Is(err, ErrNoRelay) {
		t.Errorf("unreachable relay: %v", err)
	}
}

func TestCryptoAndTransportKey(t *testing.T) {
	h := startServer(t, ServerConfig{TransportKey: transPriv})
	if h.srv.TransportPubKey() == h.srv.PubKey() {
		t.Fatal("transport key not used")
	}
	for _, enc := range []string{nip46.EncryptionNIP44V2, nip46.EncryptionNIP04} {
		c := dial(t, h, ClientOptions{Encryption: enc})
		uri, _ := ParseURI((&URI{SignerPubKey: c.SignerPubKey(), Relays: []string{h.relay}}).String())
		if uri.SignerPubKey != h.srv.TransportPubKey() {
			t.Fatalf("URI names %s", uri.SignerPubKey)
		}
		peer, _ := nip46.NewLocalKey(peerPriv)
		for _, scheme := range []string{nip46.EncryptionNIP04, nip46.EncryptionNIP44V2} {
			ct, err := c.Encrypt(ctx5(t), scheme, peer.PubKey(), "hi")
			if err != nil {
				t.Fatalf("%s/%s encrypt: %v", enc, scheme, err)
			}
			pt, err := peer.Decrypt(ctx5(t), scheme, c.PubKey(), ct)
			if err != nil || pt != "hi" {
				t.Fatalf("%s/%s peer decrypt: %q %v", enc, scheme, pt, err)
			}
			back, _ := peer.Encrypt(ctx5(t), scheme, c.PubKey(), "re")
			if pt, err := c.Decrypt(ctx5(t), scheme, peer.PubKey(), back); err != nil || pt != "re" {
				t.Fatalf("%s/%s decrypt: %q %v", enc, scheme, pt, err)
			}
		}
		nsec, _ := nip19.EncodePrivateKey(transPriv)
		if _, err := c.Encrypt(ctx5(t), nip46.EncryptionNIP44V2, peer.PubKey(), nsec); !errors.Is(err, nip46.ErrDenied) {
			t.Errorf("transport key not guarded: %v", err)
		}
	}
}

// A request whose NIP-44 content carries no encryption tag still gets an
// answer, encrypted the way it actually arrived.
func TestServerFallsBackOnMistaggedEncryption(t *testing.T) {
	h := startServer(t, ServerConfig{})
	appKey, _ := nip46.NewLocalKey(peerPriv)
	ev, id, err := nip46.NewRequestEvent(appKey.PrivKeyHex(), h.srv.TransportPubKey(), nip46.MethodPing, nil, nip46.EncryptionNIP44V2)
	if err != nil {
		t.Fatal(err)
	}
	ev.Tags = [][]string{{"p", h.srv.TransportPubKey()}}
	if err := ev.Sign(appKey.PrivKeyHex()); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(h.relay)
	conn, err := relayclient.Connect(ctx5(t), u)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	subID := "resp"
	conn.SubscribeWithID(subID, nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{nip46.KindRequest}, Tags: map[string][]string{"p": {appKey.PubKey()}},
	}))
	events := conn.Events(subID)
	time.Sleep(100 * time.Millisecond)
	conn.Send(ev)
	select {
	case got := <-events:
		resp, err := nip46.ParseResponseEventAs(got.Event, appKey.PrivKeyHex(), nip46.EncryptionNIP44V2)
		if err != nil || resp.RequestID != id || resp.Result != "pong" {
			t.Fatalf("response %+v, %v", resp, err)
		}
	case <-ctx5(t).Done():
		t.Fatal("no response")
	}
}

func TestClientCallLifecycle(t *testing.T) {
	block := make(chan struct{})
	h := startServer(t, ServerConfig{Policy: PolicyFunc(func(ctx context.Context, c *Call) error {
		if c.Method == "slow" {
			<-block
		}
		return nil
	}), Methods: map[string]Handler{"slow": func(context.Context, *Call) (string, error) { return "late", nil }}})
	t.Cleanup(func() { close(block) })
	c := dial(t, h, ClientOptions{})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.Call(ctx, "slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("deadline: %v", err)
	}
	// Still usable: requests are matched by id.
	if err := c.Ping(ctx5(t)); err != nil {
		t.Errorf("ping after timeout: %v", err)
	}
	_ = c.Close()
	if err := c.Ping(ctx5(t)); !errors.Is(err, ErrClosed) {
		t.Errorf("after Close: %v", err)
	}
}
