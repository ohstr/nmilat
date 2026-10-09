package nipLS

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
)

// Handler answers a custom method. Its result string goes back as the
// response's "result"; an error goes back as "error" (see Error for how
// Deny and Invalid are encoded). Custom methods are not policy-gated.
type Handler func(ctx context.Context, req *Request) (string, error)

// ServerConfig configures a Server.
type ServerConfig struct {
	// Key signs and encrypts. Required.
	Key Key
	// Policy gates sign_event, nip04_* and nip44_*. Required: use AllowAll
	// to sign everything a connected peer asks for.
	Policy Policy

	// Guard lists further encodings of the key to refuse in output, such
	// as the ncryptsec it was loaded from. A *LocalKey's hex and nsec are
	// always guarded.
	Guard []string

	// AllowUIDs and AllowGIDs, when either is non-empty, accept only peers
	// whose SO_PEERCRED uid or primary gid is listed. Linux only.
	AllowUIDs []int
	AllowGIDs []int

	// Methods adds methods beyond NIP-46's, e.g. a status call. A name may
	// not shadow a built-in method.
	Methods map[string]Handler

	// OnDecision, if set, is called for every policy-gated request and
	// every refused connection. Calls are serialized.
	OnDecision func(Decision)

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Server answers NIP-LS requests on a unix socket.
type Server struct {
	cfg      ServerConfig
	pub      string
	guard    *guard
	allowUID map[int]bool
	allowGID map[int]bool
	connSeq  atomic.Uint64

	// signMu serializes authorize -> sign so a policy can spend one-time
	// state safely.
	signMu     sync.Mutex
	decisionMu sync.Mutex
}

var builtinMethods = map[string]bool{
	nip46.MethodConnect: true, nip46.MethodSignEvent: true, nip46.MethodPing: true,
	nip46.MethodGetPublicKey: true, nip46.MethodGetRelays: true, nip46.MethodSwitchRelays: true,
	nip46.MethodLogout: true, nip46.MethodNIP04Encrypt: true, nip46.MethodNIP04Decrypt: true,
	nip46.MethodNIP44Encrypt: true, nip46.MethodNIP44Decrypt: true,
}

// NewServer validates cfg and prepares a server. It does not listen.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Key == nil {
		return nil, errors.New("nipLS: ServerConfig.Key is required")
	}
	if cfg.Policy == nil {
		return nil, errors.New("nipLS: ServerConfig.Policy is required (use nipLS.AllowAll to sign everything)")
	}
	if (len(cfg.AllowUIDs) > 0 || len(cfg.AllowGIDs) > 0) && !PeerCredSupported {
		return nil, ErrPeerCredUnsupported
	}
	for name := range cfg.Methods {
		if builtinMethods[name] {
			return nil, fmt.Errorf("nipLS: custom method %q shadows a built-in", name)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pub := strings.ToLower(cfg.Key.PubKey())
	if _, err := ParsePubKey(pub); err != nil {
		return nil, fmt.Errorf("nipLS: key has an invalid pubkey: %w", err)
	}

	secrets := append([]string(nil), cfg.Guard...)
	if lk, ok := cfg.Key.(*LocalKey); ok {
		secrets = append(secrets, keySecrets(lk.PrivKeyHex())...)
	}
	return &Server{
		cfg:      cfg,
		pub:      pub,
		guard:    newGuard(secrets...),
		allowUID: intSet(cfg.AllowUIDs),
		allowGID: intSet(cfg.AllowGIDs),
	}, nil
}

func intSet(xs []int) map[int]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[int]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// PubKey is the signer's pubkey, lowercase hex.
func (s *Server) PubKey() string { return s.pub }

// ListenAndServe binds path (a socket path or bunker+unix:// URI) with
// Listen and serves on it until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, path string, opts ListenOptions) error {
	p, err := ParseURI(path)
	if err != nil {
		return err
	}
	l, err := Listen(p, opts)
	if err != nil {
		return err
	}
	return s.Serve(ctx, l)
}

// Serve accepts connections on l until ctx is done, then closes l and
// waits for open connections to finish.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.ServeConn(ctx, conn)
		}()
	}
}

// ServeConn answers requests on one connection until it closes or ctx is
// done, then closes it.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	peer := peerCredOf(conn)
	peer.Conn = s.connSeq.Add(1)
	if !s.peerAllowed(peer) {
		_ = s.decide(&Request{Peer: peer}, Deny("peer uid/gid not allowed"))
		return
	}

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), MaxMessageSize)
	enc := json.NewEncoder(conn)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var wreq nip46.Request
		var resp nip46.Response
		if err := json.Unmarshal(line, &wreq); err != nil {
			resp.Error = ErrPrefixInvalid + "malformed request JSON"
		} else {
			req := &Request{ID: wreq.RequestID, Method: wreq.Method, Params: wreq.Params, Peer: peer}
			resp.RequestID = wreq.RequestID
			result, err := s.handle(ctx, req)
			if err != nil {
				resp.Error = nip46.WireError(err)
			} else {
				resp.Result = result
			}
		}
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) peerAllowed(p Peer) bool {
	if s.allowUID == nil && s.allowGID == nil {
		return true
	}
	if p.UID != nil && s.allowUID[*p.UID] {
		return true
	}
	if p.GID != nil && s.allowGID[*p.GID] {
		return true
	}
	return false
}

// handle answers one request. Session methods are no-ops: the socket's
// permissions are the session.
func (s *Server) handle(ctx context.Context, req *Request) (string, error) {
	switch req.Method {
	case nip46.MethodPing:
		return "pong", nil
	case nip46.MethodGetPublicKey:
		return s.pub, nil
	case nip46.MethodConnect, nip46.MethodLogout:
		return "ack", nil
	case nip46.MethodGetRelays:
		return "{}", nil
	case nip46.MethodSwitchRelays:
		return "null", nil
	case nip46.MethodSignEvent:
		return s.handleSign(ctx, req)
	case nip46.MethodNIP04Encrypt, nip46.MethodNIP04Decrypt, nip46.MethodNIP44Encrypt, nip46.MethodNIP44Decrypt:
		return s.handleCrypto(ctx, req)
	}
	if h, ok := s.cfg.Methods[req.Method]; ok {
		return h(ctx, req)
	}
	return "", Invalid("unsupported method: " + req.Method)
}

func (s *Server) handleSign(ctx context.Context, req *Request) (string, error) {
	if len(req.Params) < 1 {
		return "", s.decide(req, Invalid("sign_event requires an event param"))
	}
	var ev nip01.Event
	if err := json.Unmarshal([]byte(req.Params[0]), &ev); err != nil {
		return "", s.decide(req, Invalid("malformed event JSON"))
	}
	req.Event = &ev
	if len(req.Params) > 1 && strings.TrimSpace(req.Params[1]) != "" {
		if err := json.Unmarshal([]byte(req.Params[1]), &req.Attestations); err != nil {
			return "", s.decide(req, Invalid("attestations param must be a JSON array of events"))
		}
	}
	if ev.PubKey != "" && !strings.EqualFold(ev.PubKey, s.pub) {
		return "", s.decide(req, Deny("event pubkey does not match the signer"))
	}
	if err := PrepareTarget(&ev, s.pub); err != nil {
		return "", s.decide(req, Invalid(err.Error()))
	}
	if s.guard.containsEvent(&ev) {
		return "", s.decide(req, Deny("event contains the signer's key"))
	}
	req.Event = ev.Copy()

	s.signMu.Lock()
	defer s.signMu.Unlock()
	if err := s.cfg.Policy.Authorize(ctx, req); err != nil {
		return "", s.decide(req, nip46.AsRefusal(err))
	}
	want := ev.ID
	if err := s.cfg.Key.Sign(ctx, &ev); err != nil {
		return "", s.decide(req, fmt.Errorf("sign failed: %w", err))
	}
	if ev.ID != want {
		return "", s.decide(req, errors.New("sign failed: key signed a different event"))
	}
	out, err := json.Marshal(&ev)
	if err != nil {
		return "", s.decide(req, errors.New("encode failed"))
	}
	_ = s.decide(req, nil)
	return string(out), nil
}

func (s *Server) handleCrypto(ctx context.Context, req *Request) (string, error) {
	if len(req.Params) < 2 {
		return "", s.decide(req, Invalid("expected [pubkey, text] params"))
	}
	counterpart, err := ParsePubKey(req.Params[0])
	if err != nil {
		return "", s.decide(req, Invalid("invalid counterpart pubkey"))
	}
	req.Counterpart = counterpart

	scheme := nip46.EncryptionNIP44V2
	if req.Method == nip46.MethodNIP04Encrypt || req.Method == nip46.MethodNIP04Decrypt {
		scheme = nip46.EncryptionNIP04
	}
	encrypting := req.Method == nip46.MethodNIP04Encrypt || req.Method == nip46.MethodNIP44Encrypt
	if encrypting {
		req.Plaintext = req.Params[1]
		if s.guard.contains(req.Plaintext) {
			return "", s.decide(req, Deny("plaintext contains the signer's key"))
		}
	} else {
		req.Ciphertext = req.Params[1]
	}
	if err := s.cfg.Policy.Authorize(ctx, req); err != nil {
		return "", s.decide(req, nip46.AsRefusal(err))
	}
	var result string
	if encrypting {
		result, err = s.cfg.Key.Encrypt(ctx, scheme, counterpart, req.Plaintext)
	} else {
		result, err = s.cfg.Key.Decrypt(ctx, scheme, counterpart, req.Ciphertext)
	}
	if err != nil {
		return "", s.decide(req, fmt.Errorf("%s failed: %w", req.Method, err))
	}
	_ = s.decide(req, nil)
	return result, nil
}

// decide reports the outcome to OnDecision and returns err.
func (s *Server) decide(req *Request, err error) error {
	if s.cfg.OnDecision != nil {
		s.decisionMu.Lock()
		s.cfg.OnDecision(Decision{Time: s.cfg.Now(), Request: req, Err: err})
		s.decisionMu.Unlock()
	}
	return err
}

// PrepareTarget sets ev's pubkey to signerPub, clears any signature, and
// computes the id the signature (and any attestation) binds to.
func PrepareTarget(ev *nip01.Event, signerPub string) error {
	return nip46.PrepareTarget(ev, signerPub)
}

// ErrAlreadyListening means another server holds the socket.
var ErrAlreadyListening = errors.New("nipLS: a signer is already listening on this socket")

// ListenOptions configures Listen.
type ListenOptions struct {
	// Mode is the socket file's permission bits; 0 means 0600.
	Mode os.FileMode
	// UID and GID, when set, chown the socket.
	UID, GID *int
}

// Listen binds a unix socket at path. It refuses to replace a symlink, a
// non-socket file or a live socket, and removes a stale one. The parent
// directory is left alone: it is often a volume shared with clients. The
// socket file is removed when the listener closes.
func Listen(path string, opts ListenOptions) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return nil, fmt.Errorf("nipLS: refusing to bind over a symlink at %s", path)
		case info.Mode()&os.ModeSocket == 0:
			return nil, fmt.Errorf("nipLS: %s exists and is not a socket", path)
		case socketIsLive(path):
			return nil, fmt.Errorf("%w (%s)", ErrAlreadyListening, path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("nipLS: removing stale socket %s: %w", path, err)
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	mode := opts.Mode
	if mode == 0 {
		mode = 0o600
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = l.Close()
		return nil, err
	}
	if opts.UID != nil || opts.GID != nil {
		uid, gid := -1, -1
		if opts.UID != nil {
			uid = *opts.UID
		}
		if opts.GID != nil {
			gid = *opts.GID
		}
		if err := os.Chown(path, uid, gid); err != nil {
			_ = l.Close()
			return nil, err
		}
	}
	return l, nil
}

func socketIsLive(path string) bool {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
