package nipLS

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/utils"
)

// rawConn is a client that writes bytes as given and reads response lines.
type rawConn struct {
	t    *testing.T
	conn net.Conn
	sc   *bufio.Scanner
}

func rawDial(t *testing.T, h *harness) *rawConn {
	t.Helper()
	conn, err := net.Dial("unix", h.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), MaxMessageSize+1)
	return &rawConn{t: t, conn: conn, sc: sc}
}

func (r *rawConn) write(b []byte) {
	r.t.Helper()
	if _, err := r.conn.Write(b); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawConn) read() nip46.Response {
	r.t.Helper()
	if !r.sc.Scan() {
		r.t.Fatalf("no response: %v", r.sc.Err())
	}
	if n := len(r.sc.Bytes()); n > MaxMessageSize {
		r.t.Fatalf("signer sent a %d-byte line", n)
	}
	var resp nip46.Response
	if err := json.Unmarshal(r.sc.Bytes(), &resp); err != nil {
		r.t.Fatalf("response %q: %v", r.sc.Bytes(), err)
	}
	return resp
}

func (r *rawConn) ping(id string) {
	r.t.Helper()
	r.write([]byte(`{"id":"` + id + `","method":"ping","params":[]}` + "\n"))
	if resp := r.read(); resp.RequestID != id || resp.Result != "pong" {
		r.t.Fatalf("ping %s answered %+v", id, resp)
	}
}

// T16-01 (S-LS-01, 02).
func TestSpecParseURISpellings(t *testing.T) {
	for _, ok := range []string{"bunker+unix:///run/s.sock", "unix:///run/s.sock", "/run/s.sock"} {
		if got, err := ParseURI(ok); err != nil || got != "/run/s.sock" {
			t.Errorf("ParseURI(%q) = %q, %v", ok, got, err)
		}
	}
	for _, bad := range []string{"run/s.sock", "bunker+unix://run/s.sock", "bunker+unix:///run/s.sock?secret=x",
		"bunker+unix:///run/s.sock#a", "/run/s.sock?secret=x", "unix:///run/s.sock#a"} {
		if _, err := ParseURI(bad); err == nil {
			t.Errorf("ParseURI(%q) accepted", bad)
		}
	}
}

// T16-04 (S-LS-06), T16-05 (S-LS-07).
func TestSpecNonObjectAndBlankLines(t *testing.T) {
	h := start(t, ServerConfig{})
	r := rawDial(t, h)
	for _, bad := range []string{"hello", "[]", `"x"`, `{"id":"1","method":"ping"`} {
		r.write([]byte(bad + "\n"))
		if resp := r.read(); resp.RequestID != "" || !strings.HasPrefix(resp.Error, ErrPrefixInvalid) {
			t.Errorf("%s answered %+v", bad, resp)
		}
	}
	r.write([]byte("\n  \n\r\n"))
	r.ping("after-blank")
	// Exactly one response to the ping: the next answer is for "next".
	r.ping("next")
}

// T16-06 (S-LS-08).
func TestSpecPipelined(t *testing.T) {
	h := start(t, ServerConfig{})
	r := rawDial(t, h)
	r.write([]byte(`{"id":"a","method":"ping","params":[]}` + "\n" + `{"id":"b","method":"get_public_key","params":[]}` + "\n"))
	if a := r.read(); a.RequestID != "a" || a.Result != "pong" {
		t.Errorf("first = %+v", a)
	}
	if b := r.read(); b.RequestID != "b" || b.Result != h.srv.PubKey() {
		t.Errorf("second = %+v", b)
	}
}

// T16-07 (S-LS-09): an abandoned request breaks the connection; a new
// Dial works.
func TestSpecAbandonedReconnect(t *testing.T) {
	var slow atomic.Bool
	slow.Store(true)
	h := start(t, ServerConfig{Policy: PolicyFunc(func(ctx context.Context, _ *Request) error {
		if slow.Load() {
			select {
			case <-time.After(300 * time.Millisecond):
			case <-ctx.Done():
			}
		}
		return nil
	})})
	c := dial(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := c.Sign(ctx, draft(1, "x")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("broken connection reused")
	}
	slow.Store(false)
	c2 := dial(t, h)
	if err := c2.Sign(context.Background(), draft(1, "y")); err != nil {
		t.Fatalf("after reconnect: %v", err)
	}
}

// T16-08 (S-LS-10), T16-09 (S-LS-11).
func TestSpecMethodTable(t *testing.T) {
	h := start(t, ServerConfig{})
	c := dial(t, h)
	ctx := context.Background()
	if _, err := c.Call(ctx, "export_key"); !errors.Is(err, ErrInvalid) {
		t.Errorf("export_key: %v", err)
	}
	want := []struct{ m, r string }{
		{nip46.MethodConnect, "ack"}, {nip46.MethodLogout, "ack"}, {nip46.MethodPing, "pong"},
		{nip46.MethodGetPublicKey, h.srv.PubKey()}, {nip46.MethodGetRelays, "{}"}, {nip46.MethodSwitchRelays, "null"},
	}
	for _, w := range want {
		if got, err := c.Call(ctx, w.m); err != nil || got != w.r {
			t.Errorf("%s = %q, %v; want %q", w.m, got, err, w.r)
		}
	}
}

// T16-10 (S-LS-12).
func TestSpecEventPubkey(t *testing.T) {
	h := start(t, ServerConfig{})
	c := dial(t, h)
	ctx := context.Background()
	otherPub, _ := utils.GetPublicKey(otherPriv)
	foreign, _ := json.Marshal(&nip01.Event{Kind: 1, PubKey: otherPub, Tags: [][]string{}})
	if got, err := c.Call(ctx, nip46.MethodSignEvent, string(foreign)); err == nil || got != "" {
		t.Errorf("foreign pubkey signed: %q, %v", got, err)
	}
	bare, _ := json.Marshal(map[string]any{"kind": 1, "content": "x", "tags": [][]string{}, "created_at": 1700000000})
	res, err := c.Call(ctx, nip46.MethodSignEvent, string(bare))
	if err != nil {
		t.Fatal(err)
	}
	var ev nip01.Event
	if err := json.Unmarshal([]byte(res), &ev); err != nil || ev.Verify() != nil || ev.PubKey != h.srv.PubKey() {
		t.Errorf("no-pubkey event signed as %q: %v", ev.PubKey, err)
	}
}

// T16-11 (S-LS-13): the signer's own key in any guarded encoding is
// refused under AllowAll.
func TestSpecOwnKeyRefused(t *testing.T) {
	nsec, _ := nip19.EncodePrivateKey(testPriv)
	const ncs = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p"
	h := start(t, ServerConfig{Guard: []string{ncs}})
	c := dial(t, h)
	ctx := context.Background()
	peer, _ := utils.GetPublicKey(otherPriv)
	for _, secret := range []string{testPriv, nsec, ncs} {
		if err := c.Sign(ctx, draft(1, "k "+secret)); !errors.Is(err, ErrDenied) {
			t.Errorf("in content %.12s: %v", secret, err)
		}
		if err := c.Sign(ctx, draft(1, "x", []string{"t", secret})); !errors.Is(err, ErrDenied) {
			t.Errorf("in a tag %.12s: %v", secret, err)
		}
		if _, err := c.Encrypt(ctx, nip46.EncryptionNIP44V2, peer, "k "+secret); !errors.Is(err, ErrDenied) {
			t.Errorf("in a plaintext %.12s: %v", secret, err)
		}
	}
}

// T16-12 (S-LS-14), T16-17 (S-LS-22, 23).
func TestSpecDefaultDeny(t *testing.T) {
	k, _ := NewLocalKey(testPriv)
	if _, err := NewServer(ServerConfig{Key: k}); err == nil {
		t.Error("NewServer without a Policy succeeded")
	}
	h := start(t, ServerConfig{Policy: DenyAll})
	c := dial(t, h)
	ctx := context.Background()
	if err := c.Sign(ctx, draft(1, "x")); !errors.Is(err, ErrDenied) {
		t.Errorf("DenyAll signed kind 1: %v", err)
	}
	peer, _ := utils.GetPublicKey(otherPriv)
	if _, err := c.Encrypt(ctx, nip46.EncryptionNIP44V2, peer, "x"); !errors.Is(err, ErrDenied) {
		t.Errorf("DenyAll encrypted: %v", err)
	}
	// Connecting grants only what the policy allows; ping still answers.
	if err := c.Ping(ctx); err != nil {
		t.Error(err)
	}
	l, err := Listen(filepath.Join(sockDir(t), "n.sock"), ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if l.Addr().Network() != "unix" {
		t.Errorf("Listen bound %s", l.Addr().Network())
	}
}

// T16-13 (S-LS-15).
func TestSpecErrorClasses(t *testing.T) {
	h := start(t, ServerConfig{Methods: map[string]Handler{
		"signer_fail": func(_ context.Context, r *Request) (string, error) {
			switch r.Params[0] {
			case "deny":
				return "", Deny("no")
			case "invalid":
				return "", Invalid("bad")
			}
			return "", errors.New("disk on fire")
		},
	}})
	c := dial(t, h)
	ctx := context.Background()
	if _, err := c.Call(ctx, "signer_fail", "deny"); !errors.Is(err, ErrDenied) || errors.Is(err, ErrInvalid) {
		t.Errorf("denied: %v", err)
	}
	if _, err := c.Call(ctx, "signer_fail", "invalid"); !errors.Is(err, ErrInvalid) || errors.Is(err, ErrDenied) {
		t.Errorf("invalid: %v", err)
	}
	_, err := c.Call(ctx, "signer_fail", "other")
	var e *Error
	if !errors.As(err, &e) || e.Code != nil || e.Reason != "disk on fire" {
		t.Errorf("other: %v", err)
	}
	// None of them breaks the connection.
	if err := c.Ping(ctx); err != nil {
		t.Error(err)
	}
}

// approvalPolicy allows a sign_event only with an attestation reading
// "approve <signer-computed id>", each attestation spent once.
func approvalPolicy() Policy {
	spent := map[string]bool{}
	return PolicyFunc(func(_ context.Context, r *Request) error {
		if r.Method != nip46.MethodSignEvent {
			return nil
		}
		for _, a := range r.Attestations {
			if a.Content == "approve "+r.Event.ID && !spent[a.ID] {
				spent[a.ID] = true
				return nil
			}
		}
		return Deny("needs approval")
	})
}

func approval(t *testing.T, id string) *nip01.Event {
	t.Helper()
	approver, _ := NewLocalKey(otherPriv)
	att := draft(1, "approve "+id)
	att.CreatedAt = uint64(time.Now().UnixNano())
	if err := approver.Sign(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	return att
}

// T16-14 (S-LS-16, 17).
func TestSpecApprovalID(t *testing.T) {
	h := start(t, ServerConfig{Policy: approvalPolicy()})
	c := dial(t, h)
	ctx := context.Background()

	// An id computed under any other pubkey is not what the signer
	// computes.
	ev := draft(1, "pay")
	otherPub, _ := utils.GetPublicKey(otherPriv)
	if err := PrepareTarget(ev, otherPub); err != nil {
		t.Fatal(err)
	}
	wrongID := ev.ID
	if err := c.SignWithAttestations(ctx, draft(1, "pay"), []*nip01.Event{approval(t, wrongID)}); !errors.Is(err, ErrDenied) {
		t.Fatalf("approval of the wrong id: %v", err)
	}
	target := draft(1, "pay")
	if err := PrepareTarget(target, c.PubKey()); err != nil {
		t.Fatal(err)
	}
	if err := c.SignWithAttestations(ctx, draft(1, "pay"), []*nip01.Event{approval(t, target.ID)}); err != nil {
		t.Fatalf("approval of the signer-computed id: %v", err)
	}

	// params[1] "" means none; an object is invalid.
	evJSON, _ := json.Marshal(draft(1, "pay"))
	if _, err := c.Call(ctx, nip46.MethodSignEvent, string(evJSON), ""); !errors.Is(err, ErrDenied) {
		t.Errorf(`params[1] "": %v`, err)
	}
	if _, err := c.Call(ctx, nip46.MethodSignEvent, string(evJSON), "{}"); !errors.Is(err, ErrInvalid) {
		t.Errorf("params[1] object: %v", err)
	}
}

// T16-15 (S-LS-18): check, spend and sign are atomic.
func TestSpecSpendOnce(t *testing.T) {
	h := start(t, ServerConfig{Policy: approvalPolicy()})
	target := draft(1, "once")
	if err := PrepareTarget(target, h.srv.PubKey()); err != nil {
		t.Fatal(err)
	}
	att := approval(t, target.ID)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		c := dial(t, h)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.SignWithAttestations(context.Background(), draft(1, "once"), []*nip01.Event{att}) == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Errorf("one approval signed %d times", ok.Load())
	}

	// Quota 3, four concurrent requests: three signatures.
	var quota = 3
	hq := start(t, ServerConfig{Policy: PolicyFunc(func(_ context.Context, r *Request) error {
		if quota == 0 {
			return Deny("quota spent")
		}
		quota--
		return nil
	})})
	ok.Store(0)
	for i := 0; i < 4; i++ {
		c := dial(t, hq)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if c.Sign(context.Background(), draft(1, "q"+strconv.Itoa(i))) == nil {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if ok.Load() != 3 {
		t.Errorf("quota 3 signed %d", ok.Load())
	}
}

// T16-16 (S-LS-19..21): the default mode is 0600; the rest is covered by
// TestListenSafety and TestPeerAllowList.
func TestSpecSocketMode(t *testing.T) {
	path := filepath.Join(sockDir(t), "m.sock")
	l, err := Listen(path, ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Errorf("mode = %v, %v", info.Mode(), err)
	}
}

// fakeSigner serves a fresh socket as k, answering sign_event with
// answer, and counts the sign_event requests it reads.
func fakeSigner(t *testing.T, k *LocalKey, answer func(req nip46.Request) nip46.Response) (string, *atomic.Int32) {
	t.Helper()
	path := filepath.Join(sockDir(t), "f.sock")
	l, err := Listen(path, ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var signs atomic.Int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				sc := bufio.NewScanner(conn)
				enc := json.NewEncoder(conn)
				for sc.Scan() {
					var req nip46.Request
					_ = json.Unmarshal(sc.Bytes(), &req)
					resp := nip46.Response{RequestID: req.RequestID, Result: k.PubKey()}
					if req.Method == nip46.MethodSignEvent {
						signs.Add(1)
						resp = answer(req)
						resp.RequestID = req.RequestID
					}
					_ = enc.Encode(resp)
				}
			}()
		}
	}()
	return path, &signs
}

// T16-18 (S-LS-24).
func TestSpecTamperedResult(t *testing.T) {
	k, _ := NewLocalKey(testPriv)
	other, _ := NewLocalKey(otherPriv)
	cases := map[string]func(ev *nip01.Event){
		"tags":       func(ev *nip01.Event) { ev.Tags = [][]string{{"t", "y"}}; _ = k.Sign(context.Background(), ev) },
		"content":    func(ev *nip01.Event) { ev.Content = "other"; _ = k.Sign(context.Background(), ev) },
		"kind":       func(ev *nip01.Event) { ev.Kind = 7; _ = k.Sign(context.Background(), ev) },
		"created_at": func(ev *nip01.Event) { ev.CreatedAt++; _ = k.Sign(context.Background(), ev) },
		"pubkey":     func(ev *nip01.Event) { _ = other.Sign(context.Background(), ev) },
		"sig": func(ev *nip01.Event) {
			_ = k.Sign(context.Background(), ev)
			b := []byte(ev.Sig)
			if b[0] == '0' {
				b[0] = '1'
			} else {
				b[0] = '0'
			}
			ev.Sig = string(b)
		},
	}
	for name, tamper := range cases {
		path, _ := fakeSigner(t, k, func(req nip46.Request) nip46.Response {
			var ev nip01.Event
			_ = json.Unmarshal([]byte(req.Params[0]), &ev)
			tamper(&ev)
			b, _ := json.Marshal(&ev)
			return nip46.Response{Result: string(b)}
		})
		c, err := Dial(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		ev := draft(1, "asked", []string{"t", "x"})
		if err := c.Sign(context.Background(), ev); err == nil {
			t.Errorf("tampered %s accepted", name)
		}
		if ev.Sig != "" {
			t.Errorf("tampered %s written into the event", name)
		}
		_ = c.Close()
	}
}

// T16-20 (LS-METH-02, LS-ERR-01).
func TestSpecCustomMethodsAndNoRetry(t *testing.T) {
	h := start(t, ServerConfig{Methods: map[string]Handler{
		"signer_status": func(context.Context, *Request) (string, error) { return "ok", nil },
	}})
	if got, err := dial(t, h).Call(context.Background(), "signer_status"); err != nil || got != "ok" {
		t.Errorf("signer_status = %q, %v", got, err)
	}
	k, _ := NewLocalKey(testPriv)
	for _, name := range []string{nip46.MethodSignEvent, nip46.MethodPing} {
		_, err := NewServer(ServerConfig{Key: k, Policy: AllowAll, Methods: map[string]Handler{
			name: func(context.Context, *Request) (string, error) { return "", nil },
		}})
		if err == nil {
			t.Errorf("custom %s accepted", name)
		}
	}

	path, signs := fakeSigner(t, k, func(nip46.Request) nip46.Response {
		return nip46.Response{Error: ErrPrefixDenied + "not today"}
	})
	c, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Sign(context.Background(), draft(1, "x")); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied answer: %v", err)
	}
	if n := signs.Load(); n != 1 {
		t.Errorf("%d sign_event requests written, want 1", n)
	}
}
