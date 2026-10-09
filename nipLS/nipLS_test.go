package nipLS

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/utils"
)

const (
	testPriv  = "0000000000000000000000000000000000000000000000000000000000000003"
	otherPriv = "0000000000000000000000000000000000000000000000000000000000000005"
)

// sockDir returns a short temp dir: unix socket paths are capped at ~108 bytes.
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "nipls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

type harness struct {
	srv  *Server
	path string
	mu   sync.Mutex
	log  []Decision
}

func (h *harness) decisions() []Decision {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Decision(nil), h.log...)
}

// start serves cfg on a fresh socket until the test ends. Key and Policy
// default to testPriv and AllowAll.
func start(t *testing.T, cfg ServerConfig) *harness {
	t.Helper()
	if cfg.Key == nil {
		k, err := NewLocalKey(testPriv)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Key = k
	}
	if cfg.Policy == nil {
		cfg.Policy = AllowAll
	}
	h := &harness{path: filepath.Join(sockDir(t), "s.sock")}
	cfg.OnDecision = func(d Decision) {
		h.mu.Lock()
		h.log = append(h.log, d)
		h.mu.Unlock()
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	l, err := Listen(h.path, ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return h
}

func dial(t *testing.T, h *harness) *Client {
	t.Helper()
	c, err := Dial(context.Background(), FormatURI(h.path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func draft(kind int, content string, tags ...[]string) *nip01.Event {
	if tags == nil {
		tags = [][]string{}
	}
	return &nip01.Event{Kind: kind, Content: content, Tags: tags, CreatedAt: 1700000000}
}

func TestParseURI(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"bunker+unix:///run/s.sock", "/run/s.sock", true},
		{"unix:///run/s.sock", "/run/s.sock", true},
		{"/run/./s.sock", "/run/s.sock", true},
		{"bunker+unix://run/s.sock", "", false},
		{"bunker+unix:///run/s.sock?x=1", "", false},
		{"bunker://abc?relay=wss://r", "", false},
		{"relative.sock", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := ParseURI(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("ParseURI(%q) = %q, %v; want %q ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
	if !IsURI("unix:///x") || !IsURI("bunker+unix:///x") || IsURI("bunker://x") || IsURI("/x") {
		t.Error("IsURI misclassified")
	}
	if got := FormatURI("/run//s.sock"); got != "bunker+unix:///run/s.sock" {
		t.Errorf("FormatURI = %q", got)
	}
}

func TestNewLocalKeyAcceptsHexAndNsec(t *testing.T) {
	pub, _ := utils.GetPublicKey(testPriv)
	nsec, _ := nip19.EncodePrivateKey(testPriv)
	for _, in := range []string{testPriv, strings.ToUpper(testPriv), nsec, " " + nsec + "\n"} {
		k, err := NewLocalKey(in)
		if err != nil {
			t.Fatalf("NewLocalKey(%q): %v", in, err)
		}
		if k.PubKey() != pub {
			t.Errorf("pubkey = %s, want %s", k.PubKey(), pub)
		}
	}
	for _, bad := range []string{"", "zz", "nsec1bad"} {
		if _, err := NewLocalKey(bad); err == nil {
			t.Errorf("NewLocalKey(%q) succeeded", bad)
		}
	}
}

func TestNewServerValidates(t *testing.T) {
	k, _ := NewLocalKey(testPriv)
	if _, err := NewServer(ServerConfig{Policy: AllowAll}); err == nil {
		t.Error("missing Key accepted")
	}
	if _, err := NewServer(ServerConfig{Key: k}); err == nil {
		t.Error("missing Policy accepted")
	}
	_, err := NewServer(ServerConfig{Key: k, Policy: AllowAll, Methods: map[string]Handler{
		nip46.MethodSignEvent: func(context.Context, *Request) (string, error) { return "", nil },
	}})
	if err == nil {
		t.Error("custom method shadowing sign_event accepted")
	}
}

func TestSignRoundTrip(t *testing.T) {
	h := start(t, ServerConfig{})
	c := dial(t, h)
	if c.PubKey() != h.srv.PubKey() {
		t.Fatalf("client pubkey %s != server %s", c.PubKey(), h.srv.PubKey())
	}
	ev := draft(1, "hello", []string{"t", "x"})
	if err := c.Sign(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if err := ev.Verify(); err != nil {
		t.Fatalf("signed event does not verify: %v", err)
	}
	if ev.PubKey != c.PubKey() || ev.Content != "hello" {
		t.Errorf("unexpected signed event %+v", ev)
	}
	d := h.decisions()
	if len(d) != 1 || !d[0].Allowed() || d[0].Request.Event.ID != ev.ID {
		t.Errorf("decisions = %+v", d)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("ping: %v", err)
	}
}

func TestPolicyDenyAndInvalid(t *testing.T) {
	policy := PolicyFunc(func(_ context.Context, r *Request) error {
		r.Rule = "only-kind-1"
		switch {
		case r.Method != nip46.MethodSignEvent:
			return nil
		case r.Event.Kind == 1:
			return nil
		case r.Event.Kind == 2:
			return Invalid("kind 2 is malformed here")
		case r.Event.Kind == 3:
			return errors.New("backend down")
		}
		return Denyf("kind %d not allowed", r.Event.Kind)
	})
	h := start(t, ServerConfig{Policy: policy})
	c := dial(t, h)
	ctx := context.Background()

	err := c.Sign(ctx, draft(4, "x"))
	var e *Error
	if !errors.Is(err, ErrDenied) || !errors.As(err, &e) || e.Reason != "kind 4 not allowed" {
		t.Errorf("kind 4: %v", err)
	}
	if err := c.Sign(ctx, draft(2, "x")); !errors.Is(err, ErrInvalid) {
		t.Errorf("kind 2: want ErrInvalid, got %v", err)
	}
	if err := c.Sign(ctx, draft(3, "x")); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "backend down") {
		t.Errorf("kind 3: want plain error as denial, got %v", err)
	}
	// A refusal leaves the connection usable.
	if err := c.Sign(ctx, draft(1, "ok")); err != nil {
		t.Errorf("kind 1 after denials: %v", err)
	}
	d := h.decisions()
	if len(d) != 4 || d[0].Allowed() || d[0].Request.Rule != "only-kind-1" || !d[3].Allowed() {
		t.Errorf("decisions = %+v", d)
	}
}

func TestPolicySeesCopy(t *testing.T) {
	policy := PolicyFunc(func(_ context.Context, r *Request) error {
		r.Event.Content = "tampered"
		r.Event.Tags = append(r.Event.Tags, []string{"p", "x"})
		return nil
	})
	h := start(t, ServerConfig{Policy: policy})
	c := dial(t, h)
	ev := draft(1, "original")
	if err := c.Sign(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if ev.Content != "original" || len(ev.Tags) != 0 {
		t.Errorf("policy edits leaked into the signed event: %+v", ev)
	}
}

func TestSignRefusals(t *testing.T) {
	nsec, _ := nip19.EncodePrivateKey(testPriv)
	h := start(t, ServerConfig{Guard: []string{"ncryptsec1secretblob"}})
	c := dial(t, h)
	ctx := context.Background()
	otherPub, _ := utils.GetPublicKey(otherPriv)

	cases := []struct {
		name string
		ev   *nip01.Event
		want error
	}{
		{"hex key in content", draft(1, "leak "+testPriv), ErrDenied},
		{"nsec in a tag", draft(1, "x", []string{"t", strings.ToUpper(nsec)}), ErrDenied},
		{"extra guard string", draft(1, "x ncryptsec1SECRETBLOB"), ErrDenied},
	}
	for _, tc := range cases {
		if err := c.Sign(ctx, tc.ev); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}

	// Raw calls for what Client.Sign would never send.
	foreign, _ := json.Marshal(&nip01.Event{Kind: 1, PubKey: otherPub, Tags: [][]string{}})
	if _, err := c.Call(ctx, nip46.MethodSignEvent, string(foreign)); !errors.Is(err, ErrDenied) {
		t.Errorf("foreign pubkey: %v", err)
	}
	if _, err := c.Call(ctx, nip46.MethodSignEvent); !errors.Is(err, ErrInvalid) {
		t.Errorf("no params: %v", err)
	}
	if _, err := c.Call(ctx, nip46.MethodSignEvent, "{not json"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad event JSON: %v", err)
	}
	ev, _ := json.Marshal(draft(1, "x"))
	if _, err := c.Call(ctx, nip46.MethodSignEvent, string(ev), "{}"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad attestations: %v", err)
	}
	if _, err := c.Call(ctx, "no_such_method"); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown method: %v", err)
	}
}

func TestAttestationsReachPolicy(t *testing.T) {
	approver, _ := NewLocalKey(otherPriv)
	var got []*nip01.Event
	policy := PolicyFunc(func(_ context.Context, r *Request) error {
		got = r.Attestations
		if len(r.Attestations) == 0 {
			return Deny("needs approval")
		}
		return nil
	})
	h := start(t, ServerConfig{Policy: policy})
	c := dial(t, h)
	ctx := context.Background()

	if err := c.Sign(ctx, draft(1, "x")); !errors.Is(err, ErrDenied) {
		t.Fatalf("without attestation: %v", err)
	}
	att := draft(1, "approve")
	if err := approver.Sign(ctx, att); err != nil {
		t.Fatal(err)
	}
	if err := c.SignWithAttestations(ctx, draft(1, "x"), []*nip01.Event{att}); err != nil {
		t.Fatalf("with attestation: %v", err)
	}
	if len(got) != 1 || got[0].ID != att.ID {
		t.Errorf("policy saw attestations %+v", got)
	}
}

func TestCryptoRoundTrip(t *testing.T) {
	var methods []string
	policy := PolicyFunc(func(_ context.Context, r *Request) error {
		methods = append(methods, r.Method)
		if r.Plaintext == "forbidden" {
			return Deny("no")
		}
		return nil
	})
	h := start(t, ServerConfig{Policy: policy})
	c := dial(t, h)
	ctx := context.Background()
	peer, _ := NewLocalKey(otherPriv)
	npub, _ := nip19.EncodePublicKey(peer.PubKey())

	for _, scheme := range []string{nip46.EncryptionNIP04, nip46.EncryptionNIP44V2} {
		ct, err := c.Encrypt(ctx, scheme, peer.PubKey(), "hi "+scheme)
		if err != nil {
			t.Fatalf("%s encrypt: %v", scheme, err)
		}
		pt, err := peer.Decrypt(ctx, scheme, c.PubKey(), ct)
		if err != nil || pt != "hi "+scheme {
			t.Fatalf("%s: peer decrypted %q, %v", scheme, pt, err)
		}
		back, _ := peer.Encrypt(ctx, scheme, c.PubKey(), "reply")
		// The counterpart may be given as an npub.
		pt, err = c.Decrypt(ctx, scheme, npub, back)
		if err != nil || pt != "reply" {
			t.Fatalf("%s decrypt: %q, %v", scheme, pt, err)
		}
	}
	if _, err := c.Encrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), "forbidden"); !errors.Is(err, ErrDenied) {
		t.Errorf("policy denial: %v", err)
	}
	if _, err := c.Encrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), "my key "+testPriv); !errors.Is(err, ErrDenied) {
		t.Errorf("guard on plaintext: %v", err)
	}
	if _, err := c.Encrypt(ctx, "rot13", peer.PubKey(), "x"); !errors.Is(err, nip46.ErrUnsupportedEncryption) {
		t.Errorf("unknown scheme: %v", err)
	}
	if _, err := c.Call(ctx, nip46.MethodNIP44Encrypt, "not-a-key", "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad counterpart: %v", err)
	}
	// 4 round trips + the policy denial; the guard refuses before the policy.
	if len(methods) != 5 {
		t.Errorf("policy saw %v", methods)
	}
}

func TestSessionMethodsAndCustom(t *testing.T) {
	h := start(t, ServerConfig{Methods: map[string]Handler{
		"signer_status": func(_ context.Context, r *Request) (string, error) {
			if len(r.Params) > 0 && r.Params[0] == "fail" {
				return "", Deny("custom refusal")
			}
			return `{"ok":true}`, nil
		},
	}})
	c := dial(t, h)
	ctx := context.Background()
	want := map[string]string{
		nip46.MethodConnect: "ack", nip46.MethodLogout: "ack", nip46.MethodPing: "pong",
		nip46.MethodGetRelays: "{}", nip46.MethodSwitchRelays: "null", "signer_status": `{"ok":true}`,
	}
	for m, w := range want {
		if got, err := c.Call(ctx, m); err != nil || got != w {
			t.Errorf("%s = %q, %v; want %q", m, got, err, w)
		}
	}
	if _, err := c.Call(ctx, "signer_status", "fail"); !errors.Is(err, ErrDenied) {
		t.Errorf("custom denial: %v", err)
	}
	if n := len(h.decisions()); n != 0 {
		t.Errorf("session/custom methods produced %d decisions", n)
	}
}

func TestMalformedLine(t *testing.T) {
	h := start(t, ServerConfig{})
	conn, err := net.Dial("unix", h.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("\n{oops\n" + `{"id":"7","method":"ping","params":[]}` + "\n"))
	sc := bufio.NewScanner(conn)
	var lines []nip46.Response
	for len(lines) < 2 && sc.Scan() {
		var r nip46.Response
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, r)
	}
	if len(lines) != 2 || !strings.HasPrefix(lines[0].Error, ErrPrefixInvalid) || lines[1].RequestID != "7" || lines[1].Result != "pong" {
		t.Errorf("responses = %+v", lines)
	}
}

func TestPeerAllowList(t *testing.T) {
	if !PeerCredSupported {
		t.Skip("SO_PEERCRED not supported here")
	}
	me := os.Getuid()

	h := start(t, ServerConfig{AllowUIDs: []int{me}})
	dial(t, h)

	h = start(t, ServerConfig{AllowUIDs: []int{me + 1}, AllowGIDs: []int{os.Getgid() + 1}})
	if _, err := Dial(context.Background(), h.path); err == nil {
		t.Fatal("disallowed uid connected")
	}
	d := h.decisions()
	if len(d) != 1 || d[0].Allowed() || d[0].Request.Method != "" || d[0].Request.Peer.UID == nil || *d[0].Request.Peer.UID != me {
		t.Errorf("decisions = %+v", d)
	}
}

func TestListenSafety(t *testing.T) {
	dir := sockDir(t)

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(file, ListenOptions{}); err == nil {
		t.Error("bound over a regular file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(link, ListenOptions{}); err == nil {
		t.Error("bound over a symlink")
	}

	path := filepath.Join(dir, "s.sock")
	l, err := Listen(path, ListenOptions{Mode: 0o660})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Errorf("mode = %v, %v", info.Mode().Perm(), err)
	}
	go func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}(l)
	if _, err := Listen(path, ListenOptions{}); !errors.Is(err, ErrAlreadyListening) {
		t.Errorf("second Listen on a live socket: %v", err)
	}
	_ = l.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket file left after Close: %v", err)
	}

	// A stale socket file (no listener) is replaced.
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ul.SetUnlinkOnClose(false)
	_ = ul.Close()
	l, err = Listen(path, ListenOptions{})
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	_ = l.Close()
}

func TestListenAndServeURI(t *testing.T) {
	k, _ := NewLocalKey(testPriv)
	srv, err := NewServer(ServerConfig{Key: k, Policy: AllowAll})
	if err != nil {
		t.Fatal(err)
	}
	uri := FormatURI(filepath.Join(sockDir(t), "s.sock"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx, uri, ListenOptions{}) }()

	var c *Client
	for i := 0; i < 100; i++ {
		if c, err = Dial(ctx, uri); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Error(err)
	}
	_ = c.Close()
	cancel()
	if err := <-done; err != nil {
		t.Errorf("ListenAndServe: %v", err)
	}
	if err := srv.ListenAndServe(context.Background(), "relative.sock", ListenOptions{}); err == nil {
		t.Error("relative path accepted")
	}
}

// A Server can front another signer: *Client is a Key.
func TestServerFrontsClient(t *testing.T) {
	upstream := start(t, ServerConfig{})
	up := dial(t, upstream)

	proxy := start(t, ServerConfig{Key: up, Policy: PolicyFunc(func(_ context.Context, r *Request) error {
		if r.Event != nil && r.Event.Kind != 1 {
			return Deny("proxy allows kind 1 only")
		}
		return nil
	})})
	c := dial(t, proxy)
	if c.PubKey() != up.PubKey() {
		t.Fatalf("proxy pubkey %s != upstream %s", c.PubKey(), up.PubKey())
	}
	ev := draft(1, "via proxy")
	if err := c.Sign(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if err := c.Sign(context.Background(), draft(7, "x")); !errors.Is(err, ErrDenied) {
		t.Errorf("proxy policy: %v", err)
	}
	if len(upstream.decisions()) != 1 {
		t.Errorf("upstream saw %d requests, want 1", len(upstream.decisions()))
	}
}

func TestClientBreaksAfterCancel(t *testing.T) {
	block := make(chan struct{})
	h := start(t, ServerConfig{Policy: PolicyFunc(func(ctx context.Context, _ *Request) error {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return nil
	})})
	t.Cleanup(func() { close(block) })
	c := dial(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Sign(ctx, draft(1, "x")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
	if err := c.Ping(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("call after a broken one: %v", err)
	}
}

func TestClientRejectsSwappedEvent(t *testing.T) {
	// A server that signs something else than asked.
	path := filepath.Join(sockDir(t), "s.sock")
	l, err := Listen(path, ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	k, _ := NewLocalKey(testPriv)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		sc := bufio.NewScanner(conn)
		enc := json.NewEncoder(conn)
		for sc.Scan() {
			var req nip46.Request
			_ = json.Unmarshal(sc.Bytes(), &req)
			resp := nip46.Response{RequestID: req.RequestID, Result: k.PubKey()}
			if req.Method == nip46.MethodSignEvent {
				ev := draft(1, "something else")
				_ = k.Sign(context.Background(), ev)
				b, _ := json.Marshal(ev)
				resp.Result = string(b)
			}
			_ = enc.Encode(resp)
		}
	}()
	c, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Sign(context.Background(), draft(1, "asked for this")); err == nil || !strings.Contains(err.Error(), "different event") {
		t.Errorf("swapped event accepted: %v", err)
	}
}
