package bunker

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/utils"
)

// ServerConfig configures a Server.
type ServerConfig struct {
	// Key signs and encrypts as the user. Required.
	Key nip46.Key
	// TransportKey is the private key (hex) the NIP-46 conversation itself
	// runs under: what the bunker:// URI names and requests are encrypted
	// to. Empty means Key's own, which requires Key to be a
	// *nip46.LocalKey.
	TransportKey string
	// Relays the server listens on. Required by Run; Handle needs none.
	Relays []string
	// Policy decides every request. Required.
	Policy Policy

	// Guard lists further strings to refuse in output, such as the
	// ncryptsec a key was loaded from. A *nip46.LocalKey and the transport
	// key are always guarded.
	Guard []string

	// Methods adds methods beyond NIP-46's. A name may not shadow a
	// built-in method.
	Methods map[string]Handler

	// OnDecision, if set, is called once per request with its outcome.
	// Calls are serialized.
	OnDecision func(Decision)
	// Logf receives operational messages (relay connects, dropped events).
	// It never receives decrypted content or key material.
	Logf func(format string, args ...any)

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Server is a NIP-46 remote signer listening on relays.
type Server struct {
	cfg          ServerConfig
	userPub      string
	transportKey string
	transportPub string
	relays       []string
	guard        *nip46.KeyGuard
	pool         *pool

	mu        sync.Mutex
	secret    string
	secretExp time.Time
	life      context.Context

	decisionMu sync.Mutex
}

var builtinMethods = map[string]bool{
	nip46.MethodConnect: true, nip46.MethodSignEvent: true, nip46.MethodPing: true,
	nip46.MethodGetPublicKey: true, nip46.MethodGetRelays: true, nip46.MethodSwitchRelays: true,
	nip46.MethodLogout: true, nip46.MethodNIP04Encrypt: true, nip46.MethodNIP04Decrypt: true,
	nip46.MethodNIP44Encrypt: true, nip46.MethodNIP44Decrypt: true,
}

// NewServer validates cfg and prepares a server. Call Run to start it.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Key == nil {
		return nil, errors.New("bunker: ServerConfig.Key is required")
	}
	if cfg.Policy == nil {
		return nil, errors.New("bunker: ServerConfig.Policy is required")
	}
	for name := range cfg.Methods {
		if builtinMethods[name] {
			return nil, fmt.Errorf("bunker: custom method %q shadows a built-in", name)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	userPub, err := nip46.ParsePubKey(cfg.Key.PubKey())
	if err != nil {
		return nil, fmt.Errorf("bunker: key has an invalid pubkey: %w", err)
	}

	var guarded []string
	lk, isLocal := cfg.Key.(*nip46.LocalKey)
	if isLocal {
		guarded = append(guarded, lk.PrivKeyHex())
	}
	transport := cfg.TransportKey
	if transport == "" {
		if !isLocal {
			return nil, errors.New("bunker: ServerConfig.TransportKey is required unless Key is a *nip46.LocalKey")
		}
		transport = lk.PrivKeyHex()
	} else {
		tk, err := nip46.NewLocalKey(transport)
		if err != nil {
			return nil, fmt.Errorf("bunker: invalid TransportKey: %w", err)
		}
		transport = tk.PrivKeyHex()
		guarded = append(guarded, transport)
	}
	transportPub, err := utils.GetPublicKey(transport)
	if err != nil {
		return nil, fmt.Errorf("bunker: invalid transport key: %w", err)
	}

	var relays []string
	for _, r := range cfg.Relays {
		n, err := normalizeRelay(r)
		if err != nil {
			return nil, fmt.Errorf("bunker: relay %q: %w", r, err)
		}
		relays = append(relays, n)
	}

	s := &Server{
		cfg:          cfg,
		userPub:      userPub,
		transportKey: transport,
		transportPub: transportPub,
		relays:       relays,
		guard:        nip46.NewKeyGuard(guarded, cfg.Guard...),
	}
	filter := nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{nip46.KindRequest},
		Tags:  map[string][]string{"p": {transportPub}},
	})
	s.pool = newPool(filter, s.handleEvent, cfg.Logf)
	return s, nil
}

// PubKey is the user pubkey the server signs as.
func (s *Server) PubKey() string { return s.userPub }

// TransportPubKey is the pubkey apps talk to; bunker:// URIs name it.
func (s *Server) TransportPubKey() string { return s.transportPub }

// Relays are the relays the server listens on.
func (s *Server) Relays() []string { return append([]string(nil), s.relays...) }

// RelayStatuses reports each relay's connection state.
func (s *Server) RelayStatuses() []RelayStatus { return s.pool.statuses() }

// Run connects to the relays and serves requests until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	if len(s.relays) == 0 {
		return errors.New("bunker: no relays configured")
	}
	s.mu.Lock()
	if s.life != nil {
		s.mu.Unlock()
		return errors.New("bunker: server already running")
	}
	s.life = ctx
	s.mu.Unlock()

	for _, r := range s.relays {
		if err := s.pool.add(ctx, r); err != nil {
			s.cfg.Logf("skipping relay %s: %v", r, err)
		}
	}
	<-ctx.Done()
	s.pool.wait()
	return nil
}

// NewBunkerURI arms a fresh single-use secret, valid for ttl, and returns
// the bunker:// URI an app pastes to pair. Arming a new one replaces any
// previous secret.
func (s *Server) NewBunkerURI(ttl time.Duration) (string, error) {
	secret, err := NewSecret()
	if err != nil {
		return "", err
	}
	s.ArmSecret(secret, ttl)
	return (&URI{SignerPubKey: s.transportPub, Relays: s.relays, Secret: secret}).String(), nil
}

// ArmSecret makes secret the one a connect must present, for ttl, single
// use. It replaces any previous secret; "" disarms. NewBunkerURI arms a
// random one; use this when the secret comes from elsewhere.
func (s *Server) ArmSecret(secret string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if secret == "" {
		s.secret, s.secretExp = "", time.Time{}
		return
	}
	s.secret, s.secretExp = secret, s.cfg.Now().Add(ttl)
}

// CancelPairing disarms the current bunker:// secret, if any.
func (s *Server) CancelPairing() {
	s.mu.Lock()
	s.secret, s.secretExp = "", time.Time{}
	s.mu.Unlock()
}

// takeSecret consumes the armed secret if given matches it.
func (s *Server) takeSecret(given string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret == "" || given == "" {
		return false
	}
	if s.cfg.Now().After(s.secretExp) {
		s.secret = ""
		return false
	}
	if subtle.ConstantTimeCompare([]byte(given), []byte(s.secret)) != 1 {
		return false
	}
	s.secret = ""
	return true
}

// AcceptNostrconnect answers an app's nostrconnect:// URI: it sends the
// connect response carrying the URI's secret on every relay the URI names
// and keeps listening there. The app then knows the signer. Accepting is
// the operator's decision, so the policy is not asked; record the app as
// paired before calling if the policy needs to know. Run must be running.
func (s *Server) AcceptNostrconnect(ctx context.Context, uri string) (*nip46.NostrconnectSchema, error) {
	schema, err := nip46.ParseNostrconnect(uri)
	if err != nil {
		return nil, fmt.Errorf("bunker: %w", err)
	}
	return schema, s.AcceptNostrconnectSchema(ctx, schema)
}

// AcceptNostrconnectSchema is AcceptNostrconnect for an already-parsed URI.
func (s *Server) AcceptNostrconnectSchema(ctx context.Context, schema *nip46.NostrconnectSchema) error {
	s.mu.Lock()
	life := s.life
	s.mu.Unlock()
	if life == nil {
		return errors.New("bunker: server is not running")
	}
	// The secret doubles as the response id: there is no request to answer.
	ev, err := nip46.NewResponseEvent(s.transportKey, schema.ClientPublickey, schema.Secret, schema.Secret, nip46.EncryptionNIP44V2)
	if err != nil {
		return fmt.Errorf("bunker: %w", err)
	}
	if err := ev.Sign(s.transportKey); err != nil {
		return fmt.Errorf("bunker: %w", err)
	}
	relays := make([]string, 0, len(schema.Relays))
	for _, r := range schema.Relays {
		relays = append(relays, r.String())
	}
	sent, tried := s.pool.sendTo(ctx, life, relays, ev)
	if sent == 0 {
		return fmt.Errorf("%w (tried %s)", ErrNoRelay, strings.Join(tried, ", "))
	}
	return nil
}

// handleEvent verifies, decrypts and answers one request event.
func (s *Server) handleEvent(conn *relayclient.Connection, ev *nip01.Event) {
	if err := ev.Verify(); err != nil {
		s.cfg.Logf("dropped unverifiable event %s", short(ev.ID))
		return
	}
	encryption := nip46.TaggedEncryption(ev)
	req, err := nip46.ParseRequestEventAs(ev, s.transportKey, encryption)
	if err != nil {
		encryption = nip46.OtherEncryption(encryption)
		if req, err = nip46.ParseRequestEventAs(ev, s.transportKey, encryption); err != nil {
			s.cfg.Logf("dropped unparseable request from %s", short(ev.PubKey))
			return
		}
	}
	// Requests and responses share the kind; a response has no method.
	if req.Method == "" {
		return
	}

	resp, err := s.Handle(s.lifeCtx(), req, encryption)
	if err != nil {
		s.cfg.Logf("could not build a response to %s", req.RequestID)
		return
	}
	if !conn.Send(resp) {
		s.cfg.Logf("relay %s: closed before the response to %s went out", conn.Relay(), req.RequestID)
	}
}

// Handle answers one already-decrypted request without any relay: it runs
// the method (and the policy), reports the decision, and returns the
// signed response event, encrypted with encryption. The error is only for
// a response that could not be built. Useful for tests and for carrying
// requests over another transport.
func (s *Server) Handle(ctx context.Context, req *nip46.RequestEvent, encryption string) (*nip01.Event, error) {
	call := &Call{ID: req.RequestID, Method: req.Method, Params: req.Params, Client: strings.ToLower(req.PubKey), Encryption: encryption}
	result, err := s.dispatch(ctx, call)
	s.decide(call, result, err)

	var resp *nip01.Event
	if err != nil {
		resp, err = nip46.NewErrorResponseEvent(s.transportKey, call.Client, call.ID, nip46.WireError(err), encryption)
	} else {
		resp, err = nip46.NewResponseEvent(s.transportKey, call.Client, call.ID, result, encryption)
	}
	if err != nil {
		return nil, err
	}
	if err := resp.Sign(s.transportKey); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) lifeCtx() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.life == nil {
		return context.Background()
	}
	return s.life
}

func (s *Server) dispatch(ctx context.Context, call *Call) (string, error) {
	switch call.Method {
	case nip46.MethodConnect:
		// params: [signer-pubkey, secret, perms, client-metadata]
		if len(call.Params) > 1 {
			call.Secret = call.Params[1]
		}
		if len(call.Params) > 2 {
			call.Perms = call.Params[2]
		}
		call.Metadata = parseMetadata(call.Params)
		if !s.takeSecret(call.Secret) {
			return "", nip46.Deny("no matching pairing in progress")
		}
		return s.authorized(ctx, call, func() (string, error) { return "ack", nil })
	case nip46.MethodPing:
		return s.authorized(ctx, call, func() (string, error) { return "pong", nil })
	case nip46.MethodGetPublicKey:
		return s.authorized(ctx, call, func() (string, error) { return s.userPub, nil })
	case nip46.MethodGetRelays:
		return s.authorized(ctx, call, func() (string, error) { return s.relaysJSON(), nil })
	case nip46.MethodSwitchRelays:
		return s.authorized(ctx, call, func() (string, error) { return s.switchRelaysJSON(), nil })
	case nip46.MethodLogout:
		return s.authorized(ctx, call, func() (string, error) { return "ack", nil })
	case nip46.MethodSignEvent:
		return s.sign(ctx, call)
	case nip46.MethodNIP04Encrypt, nip46.MethodNIP04Decrypt, nip46.MethodNIP44Encrypt, nip46.MethodNIP44Decrypt:
		return s.crypto(ctx, call)
	}
	if h, ok := s.cfg.Methods[call.Method]; ok {
		return s.authorized(ctx, call, func() (string, error) { return h(ctx, call) })
	}
	return "", nip46.Invalid("unsupported method: " + call.Method)
}

// authorized runs the policy, then do.
func (s *Server) authorized(ctx context.Context, call *Call, do func() (string, error)) (string, error) {
	if err := s.cfg.Policy.Authorize(ctx, call); err != nil {
		return "", nip46.AsRefusal(err)
	}
	return do()
}

func (s *Server) sign(ctx context.Context, call *Call) (string, error) {
	if len(call.Params) < 1 {
		return "", nip46.Invalid("sign_event requires an event param")
	}
	var ev nip01.Event
	if err := json.Unmarshal([]byte(call.Params[0]), &ev); err != nil {
		return "", nip46.Invalid("malformed event JSON")
	}
	if ev.PubKey != "" && !strings.EqualFold(ev.PubKey, s.userPub) {
		return "", nip46.Deny("event pubkey does not match the signer")
	}
	if err := nip46.PrepareTarget(&ev, s.userPub); err != nil {
		return "", nip46.Invalid(err.Error())
	}
	call.Event = ev.Copy()
	if s.guard.ContainsEvent(&ev) {
		return "", nip46.Deny("event contains the signer's key")
	}
	return s.authorized(ctx, call, func() (string, error) {
		want := ev.ID
		if err := s.cfg.Key.Sign(ctx, &ev); err != nil {
			return "", fmt.Errorf("sign failed: %w", err)
		}
		if ev.ID != want {
			return "", errors.New("sign failed: key signed a different event")
		}
		out, err := json.Marshal(&ev)
		if err != nil {
			return "", errors.New("encode failed")
		}
		return string(out), nil
	})
}

func (s *Server) crypto(ctx context.Context, call *Call) (string, error) {
	if len(call.Params) < 2 {
		return "", nip46.Invalid("expected [pubkey, text] params")
	}
	counterpart, err := nip46.ParsePubKey(call.Params[0])
	if err != nil {
		return "", nip46.Invalid("invalid counterpart pubkey")
	}
	call.Counterpart = counterpart
	scheme := nip46.EncryptionNIP44V2
	if call.Method == nip46.MethodNIP04Encrypt || call.Method == nip46.MethodNIP04Decrypt {
		scheme = nip46.EncryptionNIP04
	}
	encrypting := call.Method == nip46.MethodNIP04Encrypt || call.Method == nip46.MethodNIP44Encrypt
	if encrypting {
		call.Plaintext = call.Params[1]
		if s.guard.Contains(call.Plaintext) {
			return "", nip46.Deny("plaintext contains the signer's key")
		}
	} else {
		call.Ciphertext = call.Params[1]
	}
	return s.authorized(ctx, call, func() (string, error) {
		var out string
		var err error
		if encrypting {
			out, err = s.cfg.Key.Encrypt(ctx, scheme, counterpart, call.Plaintext)
		} else {
			out, err = s.cfg.Key.Decrypt(ctx, scheme, counterpart, call.Ciphertext)
		}
		if err != nil {
			return "", fmt.Errorf("%s failed: %w", call.Method, err)
		}
		return out, nil
	})
}

func (s *Server) decide(call *Call, result string, err error) {
	if s.cfg.OnDecision == nil {
		return
	}
	d := Decision{Time: s.cfg.Now(), Call: call, Err: err}
	if err == nil {
		d.Result = result
	}
	s.decisionMu.Lock()
	defer s.decisionMu.Unlock()
	s.cfg.OnDecision(d)
}

// relaysJSON is get_relays' result: each relay read/write.
func (s *Server) relaysJSON() string {
	m := make(map[string]map[string]bool, len(s.relays))
	for _, r := range s.relays {
		m[r] = map[string]bool{"read": true, "write": true}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// switchRelaysJSON is switch_relays' result: the relays the app should
// use, as an array, or null (no change) when there are none.
func (s *Server) switchRelaysJSON() string {
	if len(s.relays) == 0 {
		return "null"
	}
	b, err := json.Marshal(s.relays)
	if err != nil {
		return "null"
	}
	return string(b)
}

// parseMetadata reads connect's params[3]. Absent or malformed yields an
// empty value: a display hint isn't worth failing a pairing over.
func parseMetadata(params []string) *nip46.Metadata {
	meta := &nip46.Metadata{}
	if len(params) < 4 || params[3] == "" {
		return meta
	}
	if err := json.Unmarshal([]byte(params[3]), meta); err != nil {
		return &nip46.Metadata{}
	}
	return meta
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}
