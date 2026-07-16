package relay

import (
	"compress/flate"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/nip77"
	"github.com/ohstr/nmilat/nipOA"
	"github.com/ohstr/nmilat/search"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
	"github.com/rs/zerolog"
)

const (
	wsReadBuffer       = 1024
	wsWriteBuffer      = 1024
	wsDefaultReadLimit = 1_101_005
)

var (
	wsDefaultAllowedOrigins = []string{"*"}
	wsBufferPool            = new(sync.Pool)
	ErrSessionClosed        = errors.New("session closed")
	ErrRateLimited          = errors.New("rate-limited: too many concurrent tasks")
)

type sessionContextKey struct{}

// MembershipStatus records a single authenticated identity's NIP-43
// standing on a connection.
type MembershipStatus uint8

const (
	// MembershipNone means the pubkey authenticated (NIP-42) but holds no
	// NIP-43 membership -- the common case on a relay that hasn't enabled
	// membership enforcement, or for a non-member on one that has.
	MembershipNone MembershipStatus = iota
	// MembershipActive means the pubkey is a direct, explicitly-enrolled
	// NIP-43 member.
	MembershipActive
	// MembershipVirtual means access was derived from an owner's active
	// membership (NIP-AA), not from the pubkey's own enrollment.
	MembershipVirtual
)

func (m MembershipStatus) String() string {
	switch m {
	case MembershipActive:
		return "active"
	case MembershipVirtual:
		return "virtual"
	default:
		return "none"
	}
}

// AuthedIdentity records one pubkey authenticated on this connection via
// NIP-42, plus the membership status resolved for it at AUTH time.
//
// Membership status is resolved once, when the identity is added, and
// never re-checked for the rest of the connection's life -- this follows
// NIP-AA's own revocation wording ("virtual membership is checked on each
// new connection, not cached across reconnects... the relay does not
// proactively expire mid-session"), and is also this design's main
// performance property: every REQ/EVENT membership check thereafter is a
// read of this connection's own (at most a handful of entries) identity
// list, never a lookup against the shared, cross-connection membership
// cache.
type AuthedIdentity struct {
	Pubkey     string
	Membership MembershipStatus

	// Owner and Conditions are populated only when Membership ==
	// MembershipVirtual. Owner is the NIP-43-member pubkey this virtual
	// membership was derived from. Conditions is the already-verified
	// NIP-OA credential's parsed conditions, retained so optional per-event
	// kind enforcement (a later phase) never has to re-verify a signature
	// -- it's a nil pointer, not a zero-value struct, so plain NIP-43
	// active members and non-AA connections carry no incremental memory
	// for this field at all.
	Owner      string
	Conditions *nipOA.Conditions
}

type Session struct {
	id   int64
	conn *websocket.Conn

	wg sync.WaitGroup

	writeMu sync.Mutex

	negMu              sync.Mutex
	negentropySessions map[string]*nip77.Negentropy

	challenge string

	// identityMu protects primary/extra. A connection's own packet
	// processing is single-goroutine (see receiveMessages), so nothing
	// internal to normal packet handling actually contends on this lock;
	// it exists for cross-goroutine readers added by a later phase (e.g.
	// owner-scoped session enumeration/termination, which reads another
	// connection's Session from outside that connection's own goroutine).
	identityMu sync.RWMutex

	// primary is the first pubkey authenticated on this connection, stored
	// by value so the overwhelmingly common case -- zero or one identity,
	// no NIP-AA -- costs no heap allocation beyond Session's own. extra
	// holds any additional identities (a second, third, ... AUTH on the
	// same connection, e.g. a human's own key plus one or more agent keys)
	// and stays nil until that actually happens.
	primary AuthedIdentity
	extra   []AuthedIdentity

	*SessionContext
}

type SessionContext struct {
	subscriptions      *SubscriptionsMap
	store              *EventStore
	info               *ClientInfo
	config             *SessionConfig
	limitation         *nip11.Limitation
	relayURL           string
	selfPubkey         string
	storeLimiter       chan struct{}
	SearchService      search.Service
	VerificationWorker *ProfileVerificationWorker

	// membership resolves NIP-43 active-member status. nil means NIP-43 is
	// not configured on this relay -- every method on *MembershipService is
	// nil-safe and reports "not a member" unconditionally, so call sites
	// never need their own nil check before calling it. Populated for real
	// by a later phase.
	membership *MembershipService

	*replyer
}

func NewSessionContext(store *EventStore, info *ClientInfo, cfg *nip11.Metadata, searchService search.Service, vWorker *ProfileVerificationWorker, sessCfg *SessionConfig) *SessionContext {
	if sessCfg == nil {
		sessCfg = defaultSessionConfig()
	}
	if sessCfg.OutgoingBufferSize <= 0 {
		sessCfg.OutgoingBufferSize = defaultOutgoingBufferSize
	}
	if sessCfg.MaxConcurrentStoreTasks <= 0 {
		sessCfg.MaxConcurrentStoreTasks = defaultMaxConcurrentStoreTasks
	}
	return &SessionContext{
		store:              store,
		subscriptions:      NewSubscriptions(&cfg.Limitation),
		info:               info,
		config:             sessCfg,
		limitation:         &cfg.Limitation,
		relayURL:           cfg.URL,
		selfPubkey:         cfg.Self,
		storeLimiter:       make(chan struct{}, sessCfg.MaxConcurrentStoreTasks),
		SearchService:      searchService,
		VerificationWorker: vWorker,
		replyer: &replyer{
			incoming: make(chan wire.SubscriptionResponse, sessCfg.OutgoingBufferSize),
			closeCh:  make(chan interface{}),
		},
	}
}

func (sc *SessionContext) executeStoreTask(ctx context.Context, task Task) {
	select {
	case sc.storeLimiter <- struct{}{}:
		go func() {
			defer func() {
				<-sc.storeLimiter
			}()
			defer utils.RecoverPanic(sc.config.Logger)
			sc.store.Execute(ctx, task)
		}()
	case <-ctx.Done():
		task.Done(ctx.Err())
	case <-sc.closeCh:
		task.Done(ErrSessionClosed)
	default:
		task.Done(ErrRateLimited)
	}
}

func NewSession(id int64, conn *websocket.Conn, sc *SessionContext, maxMessageLength int64) *Session {

	s := &Session{
		id:                 id,
		conn:               conn,
		SessionContext:     sc,
		negentropySessions: make(map[string]*nip77.Negentropy),
	}

	if maxMessageLength == 0 {
		maxMessageLength = wsDefaultReadLimit
	}
	conn.SetReadLimit(maxMessageLength)

	if sc.config.PongTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(sc.config.PongTimeout))
	} else {
		var zero time.Time
		conn.SetReadDeadline(zero)
	}
	conn.SetPongHandler(func(string) error {
		if sc.config.PongTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(sc.config.PongTimeout))
		} else {
			var zero time.Time
			conn.SetReadDeadline(zero)
		}
		return nil
	})

	if sc.config.PingInterval > 0 {
		s.wg.Add(1)
		go s.pingLoop()
	}

	return s
}

// ID returns this session's server-assigned identifier.
func (s *Session) ID() int64 {
	return s.id
}

// AuthedPubkey returns the first pubkey this session authenticated as via
// NIP-42, or "" if it has not authenticated. A connection may hold more
// than one authenticated identity (see addIdentity) -- this returns only
// the first, which is all plain NIP-42 (no NIP-43/NIP-AA) ever produces.
// Callers that need a specific pubkey's own status should use
// IdentityMembership; callers that need "does anything on this connection
// hold membership" should use HasMembership.
func (s *Session) AuthedPubkey() string {
	s.identityMu.RLock()
	defer s.identityMu.RUnlock()
	return s.primary.Pubkey
}

// addIdentity records or updates id's status on this connection. If id's
// pubkey already has an identity here (a second AUTH for the same pubkey
// on the same connection -- e.g. NIP-AA's "replace the stored credential,
// never combine" rule for an agent re-authenticating with a different
// auth tag), it is overwritten in place, never appended as a duplicate.
func (s *Session) addIdentity(id AuthedIdentity) {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()

	if s.primary.Pubkey == "" || s.primary.Pubkey == id.Pubkey {
		s.primary = id
		return
	}
	for i := range s.extra {
		if s.extra[i].Pubkey == id.Pubkey {
			s.extra[i] = id
			return
		}
	}
	s.extra = append(s.extra, id)
}

// HasMembership reports whether any authenticated identity on this
// connection holds active or virtual NIP-43 membership. This is the
// REQ/COUNT gate: per NIP-AA, such requests pass "if at least one
// authenticated pubkey on the connection holds active or virtual
// membership."
func (s *Session) HasMembership() bool {
	s.identityMu.RLock()
	defer s.identityMu.RUnlock()

	if s.primary.Membership != MembershipNone {
		return true
	}
	for _, id := range s.extra {
		if id.Membership != MembershipNone {
			return true
		}
	}
	return false
}

// IdentityMembership looks up pubkey's own status among this connection's
// authenticated identities. This is the EVENT gate: per NIP-AA, the relay
// "MUST verify event.pubkey is authenticated on the connection AND holds
// active or virtual membership" -- never falling back to another
// identity's status. An event signed by a pubkey that never itself
// authenticated on this connection reports ok=false, even if some other
// pubkey on the same connection is a member.
func (s *Session) IdentityMembership(pubkey string) (AuthedIdentity, bool) {
	s.identityMu.RLock()
	defer s.identityMu.RUnlock()

	if s.primary.Pubkey == pubkey {
		return s.primary, true
	}
	for _, id := range s.extra {
		if id.Pubkey == pubkey {
			return id, true
		}
	}
	return AuthedIdentity{}, false
}

// HasOwnerIdentity reports whether any virtual identity on this connection
// was derived from owner. Used by owner-scoped session enumeration (a
// later phase), not the request/event hot path.
func (s *Session) HasOwnerIdentity(owner string) bool {
	s.identityMu.RLock()
	defer s.identityMu.RUnlock()

	if s.primary.Membership == MembershipVirtual && s.primary.Owner == owner {
		return true
	}
	for _, id := range s.extra {
		if id.Membership == MembershipVirtual && id.Owner == owner {
			return true
		}
	}
	return false
}

// Identities returns a defensive copy of every identity authenticated on
// this connection (at most a handful of entries in practice) -- for
// admin/audit use, not the hot path.
func (s *Session) Identities() []AuthedIdentity {
	s.identityMu.RLock()
	defer s.identityMu.RUnlock()

	if s.primary.Pubkey == "" {
		return nil
	}
	out := make([]AuthedIdentity, 0, 1+len(s.extra))
	out = append(out, s.primary)
	out = append(out, s.extra...)
	return out
}

// Info returns the client metadata (remote address, User-Agent, Origin,
// Host) captured when this session's connection was established.
func (s *Session) Info() *ClientInfo {
	return s.info
}

func (s *Session) Recv(ctx context.Context) error {

	var payload wire.RelayPayload
	err := s.conn.ReadJSON(&payload)

	if err != nil { // other exception
		if websocket.IsCloseError(err,
			websocket.CloseAbnormalClosure,
			websocket.CloseNormalClosure,
			websocket.CloseGoingAway,
			websocket.CloseNoStatusReceived,
		) {
			return ErrSessionClosed
		} else if websocket.IsCloseError(err, websocket.CloseMessageTooBig) {
			return fmt.Errorf("client sent an event that is too large")
		} else if ok := IsPacketError(err); ok {
			s.reply(&wire.NoticeSubscriptionResponse{
				Message: fmt.Sprintf("invalid request: %s", err.Error()),
			})
			return nil
		}
		return fmt.Errorf("unexpected error while processing payload: %w", err)
	}

	if err := s.ProcessPacket(ctx, payload.Packet); err != nil {
		return fmt.Errorf("failed to process payload: %w", err)
	}

	return nil
}

func (s *Session) Start(parent context.Context) error {
	defer s.Close()

	ctx, cancel := context.WithCancel(context.WithValue(parent, sessionContextKey{}, s))
	defer cancel()

	go func() {
		defer cancel()
		s.handleOutgoingMessages(ctx)
	}()

	// Send AUTH challenge
	if s.limitation.AuthRequired {
		s.challenge = nip42.NewChallenge()
		s.reply(&wire.AuthChallengeResponse{Challenge: s.challenge})
	}

	return s.receiveMessages(ctx)
}

func (s *Session) handleOutgoingMessages(ctx context.Context) {
	for {
		select {
		case packet := <-s.incoming:
			if err := s.sendPacket(packet); err != nil {
				return
			}

		case <-ctx.Done():
			return

		case <-s.closed():
			return
		}
	}
}

func (s *Session) sendPacket(packet wire.SubscriptionResponse) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.config.DataWriteTimeout > 0 {
		s.conn.SetWriteDeadline(time.Now().Add(s.config.DataWriteTimeout))
	} else {
		var zero time.Time
		s.conn.SetWriteDeadline(zero)
	}

	packetType := fmt.Sprintf("%T", packet)
	err := s.conn.WriteJSON(packet)
	if err != nil {
		if shouldLogError(err) {
			s.config.Logger.Warn().
				Int64("session", s.id).
				Str("remote", s.info.RemoteAddr).
				Str("packet_type", packetType).
				Err(err).
				Msg("sendPacket failed")
		} else {
			s.config.Logger.Debug().
				Int64("session", s.id).
				Str("remote", s.info.RemoteAddr).
				Str("packet_type", packetType).
				Err(err).
				Msg("sendPacket error (suppressed)")
		}
		return err
	}

	return nil
}

func (s *Session) writeControl(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var deadline time.Time
	if s.config.ControlWriteTimeout > 0 {
		deadline = time.Now().Add(s.config.ControlWriteTimeout)
	}
	s.conn.SetWriteDeadline(deadline)
	if err := s.conn.WriteControl(messageType, data, deadline); err != nil {
		// Ignore errors if connection is already closed/closing
		if errors.Is(err, websocket.ErrCloseSent) || errors.Is(err, net.ErrClosed) {
			return err
		}
		if shouldLogError(err) {
			s.config.Logger.Warn().
				Int64("session", s.id).
				Str("remote", s.info.RemoteAddr).
				Str("frame", controlFrameName(messageType)).
				Err(err).
				Msg("writeControl failed")
		} else {
			s.config.Logger.Debug().
				Int64("session", s.id).
				Str("remote", s.info.RemoteAddr).
				Str("frame", controlFrameName(messageType)).
				Err(err).
				Msg("writeControl error (suppressed)")
		}
		return err
	}
	return nil
}

func (s *Session) receiveMessages(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-s.closed():
			return nil

		default:
			if err := s.Recv(ctx); err != nil {
				if errors.Is(err, ErrSessionClosed) {
					s.config.Logger.Info().
						Int64("session", s.id).
						Str("remote", s.info.RemoteAddr).
						Msg("session closed by peer")
					return nil
				}
				return err
			}
		}
	}
}

func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.subscriptions.StopAll()
		closePayload := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
		if err := s.writeControl(websocket.CloseMessage, closePayload); err != nil {
			if !errors.Is(err, websocket.ErrCloseSent) && !errors.Is(err, net.ErrClosed) {
				s.config.Logger.Err(err).
					Int64("session", s.id).
					Str("remote", s.info.RemoteAddr).
					Msg("failed to send close control frame")
			}
		} else if s.config.CloseGracePeriod > 0 {
			_ = s.awaitPeerClose()
		}
		close(s.closeCh)
		s.conn.Close()

		s.negMu.Lock()
		s.negentropySessions = nil
		s.negMu.Unlock()
	})
	s.wg.Wait()
}

func (s *Session) closed() <-chan interface{} {
	return s.closeCh
}

func (s *Session) awaitPeerClose() error {
	deadline := time.Now().Add(s.config.CloseGracePeriod)
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	for {
		if _, _, err := s.conn.NextReader(); err != nil {
			var netErr net.Error
			switch {
			case errors.Is(err, net.ErrClosed):
				return nil
			case errors.As(err, &netErr) && netErr.Timeout():
				return nil
			case websocket.IsCloseError(err,
				websocket.CloseNormalClosure,
				websocket.CloseGoingAway,
				websocket.CloseNoStatusReceived,
				websocket.CloseAbnormalClosure):
				return nil
			default:
				if shouldLogError(err) {
					s.config.Logger.Debug().
						Int64("session", s.id).
						Str("remote", s.info.RemoteAddr).
						Err(err).
						Msg("awaitPeerClose read error")
				}
				return err
			}
		}
	}
}

type ClientInfo struct {
	RemoteAddr string

	HTTP struct {
		UserAgent string
		Origin    string
		Host      string
	}
}

type SessionHandler struct {
	store         *EventStore
	sessions      sync.Map
	relayMetadata *nip11.Metadata
	config        *SessionConfig
	nextSessID    int64
	searchService search.Service

	// VerificationWorker processes NIP-05/LUD-16 profile verification jobs.
	// NewSessionHandler constructs it but does not start it — call
	// VerificationWorker.Start(n) yourself before serving traffic, or use
	// relay.New, which starts it with a default worker count automatically.
	VerificationWorker *ProfileVerificationWorker
}

// NewSessionHandler constructs a SessionHandler ready to be used as an
// http.Handler. Note: the returned handler's VerificationWorker is
// constructed but not started — call VerificationWorker.Start(n) before
// serving traffic if profile verification should run, or use relay.New,
// which does this for you.
func NewSessionHandler(store *EventStore, relayMetadata *nip11.Metadata, searchService search.Service, opts ...SessionOption) *SessionHandler {
	cfg := defaultSessionConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return &SessionHandler{
		store:              store,
		sessions:           sync.Map{},
		relayMetadata:      relayMetadata,
		config:             cfg,
		searchService:      searchService,
		VerificationWorker: NewProfileVerificationWorker(store, searchService),
	}
}

func (sh *SessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.Header.Get("Accept") == nip11.ContentTypeHeader {
		nip11.NewHandler(sh.relayMetadata, sh.SupportedNIPs()).ServeHTTP(w, r)
		return
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  wsReadBuffer,
		WriteBufferSize: wsWriteBuffer,
		WriteBufferPool: wsBufferPool,
		CheckOrigin:     wsHandshakeValidator(sh.config.AllowedOrigins, sh.config.Logger),
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sh.config.Logger.Warn().AnErr("upgrade", err).Msg("ws")
		return
	}

	ws.SetCompressionLevel(flate.BestSpeed)

	info := &ClientInfo{
		RemoteAddr: ws.RemoteAddr().String(),
		HTTP: struct {
			UserAgent string
			Origin    string
			Host      string
		}{
			UserAgent: r.Header.Get("User-Agent"),
			Origin:    r.Header.Get("Origin"),
			Host:      r.Host,
		},
	}

	sessID := atomic.AddInt64(&sh.nextSessID, 1)

	sc := NewSessionContext(sh.store, info, sh.relayMetadata, sh.searchService, sh.VerificationWorker, sh.config)
	session := NewSession(sessID, ws, sc, sh.relayMetadata.Limitation.MaxMessageLength)
	sh.sessions.Store(sessID, session)
	defer sh.sessions.Delete(sessID)

	sh.config.Logger.Info().
		Int64("session", sessID).
		Msg("session started")

	if err := session.Start(r.Context()); err != nil && shouldLogError(err) {
		sh.config.Logger.Error().
			Int64("session", sessID).
			Err(err).
			Msg("unexpected error in session")
	}

	sh.config.Logger.Info().
		Int64("session", sessID).
		Msg("session ended")
}

// SessionCount returns the number of currently connected sessions.
func (sh *SessionHandler) SessionCount() int {
	count := 0
	sh.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func wsHandshakeValidator(allowedOrigins []string, logger zerolog.Logger) func(*http.Request) bool {
	origins := map[string]bool{}
	allowAllOrigins := false

	for _, origin := range allowedOrigins {
		if origin == "*" {
			allowAllOrigins = true
		}
		if origin != "" {
			origins[origin] = true
		}
	}
	if len(origins) == 0 {
		origins["http://localhost"] = true
		if hostname, err := os.Hostname(); err == nil {
			origins["http://"+hostname] = true
		}
	}

	f := func(req *http.Request) bool {
		if allowAllOrigins {
			return true
		}
		if _, ok := req.Header["Origin"]; !ok {
			return true
		}

		browserOrigin := strings.ToLower(req.Header.Get("Origin"))

		for origin := range origins {
			if ruleAllowsOrigin(origin, browserOrigin, logger) {
				return true
			}
		}

		logger.Warn().Msgf("Rejected WebSocket connection, origin=%s", browserOrigin)
		return false
	}

	return f
}

func ruleAllowsOrigin(allowedOrigin string, browserOrigin string, logger zerolog.Logger) bool {
	var (
		allowedScheme, allowedHostname, allowedPort string
		browserScheme, browserHostname, browserPort string
		err                                         error
	)
	allowedScheme, allowedHostname, allowedPort, err = parseOriginURL(allowedOrigin)
	if err != nil {
		logger.Warn().Msgf("Error parsing allowed origin specification, spec=%s. %v", allowedOrigin, err)
		return false
	}
	browserScheme, browserHostname, browserPort, err = parseOriginURL(browserOrigin)
	if err != nil {
		logger.Warn().Msgf("Error parsing browser 'Origin' field, Origin=%s. %v", browserOrigin, err)
		return false
	}
	if allowedScheme != "" && allowedScheme != browserScheme {
		return false
	}
	if allowedHostname != "" && allowedHostname != browserHostname {
		return false
	}
	if allowedPort != "" && allowedPort != browserPort {
		return false
	}
	return true
}

func parseOriginURL(origin string) (string, string, string, error) {
	parsedURL, err := url.Parse(strings.ToLower(origin))
	if err != nil {
		return "", "", "", err
	}
	var scheme, hostname, port string
	if strings.Contains(origin, "://") {
		scheme = parsedURL.Scheme
		hostname = parsedURL.Hostname()
		port = parsedURL.Port()
	} else {
		scheme = ""
		hostname = parsedURL.Scheme
		port = parsedURL.Opaque
		if hostname == "" {
			hostname = origin
		}
	}
	return scheme, hostname, port, nil
}

func shouldLogError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Only suppress logging for temporary timeouts; everything else (including resets)
		// is important for diagnosing client disconnects.
		return !(netErr.Timeout() && netErr.Temporary())
	}
	return true
}

func (s *Session) pingLoop() {
	defer s.wg.Done()
	if s.config.PingInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.closed():
			return
		case <-ticker.C:
			if err := s.writeControl(websocket.PingMessage, nil); err != nil {
				s.config.Logger.Err(err).
					Int64("session", s.id).
					Str("remote", s.info.RemoteAddr).
					Msg("ping failed, closing")
				go s.Close()
				return
			}
		}
	}
}

func controlFrameName(messageType int) string {
	switch messageType {
	case websocket.CloseMessage:
		return "close"
	case websocket.PingMessage:
		return "ping"
	case websocket.PongMessage:
		return "pong"
	default:
		return fmt.Sprintf("%d", messageType)
	}
}
