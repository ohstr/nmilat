package relay

import (
	"runtime"
	"time"

	"github.com/rs/zerolog"
)

const (
	defaultOutgoingBufferSize = 512

	defaultMaxConcurrentStoreTasks = 2048
	defaultCloseGracePeriod        = 2 * time.Second
)

// SessionConfig holds runtime behaviour for websocket sessions.
type SessionConfig struct {
	PingInterval            time.Duration
	PongTimeout             time.Duration
	ControlWriteTimeout     time.Duration
	DataWriteTimeout        time.Duration
	CloseGracePeriod        time.Duration
	OutgoingBufferSize      int
	MaxConcurrentStoreTasks int

	// Default limits for cache and search
	DefaultCacheWindow time.Duration
	DefaultCacheLimit  int
	DefaultSearchLimit int

	// EnableTopZapped gates the signed "top zapped" cache response (see
	// handler_cache.go). Off by default: serving it requires signing with
	// PrivKey, so it must be turned on deliberately rather than activating
	// itself just because a PrivKey happens to be configured.
	EnableTopZapped bool

	// NIP-26 Delegation
	PrivKey    string
	Delegation *DelegationConfig

	// AllowedOrigins is the CORS allowlist checked against the WebSocket
	// handshake's Origin header. Defaults to {"*"} (allow any origin),
	// matching prior behavior; set explicitly via WithSessionAllowedOrigins
	// to restrict which browser origins may connect.
	AllowedOrigins []string

	// Logger receives all session lifecycle/verification logging. Defaults
	// to zerolog.Nop() (silent) so embedding a Session/SessionHandler never
	// writes to the process-global logger unless the caller opts in.
	Logger zerolog.Logger
}

type DelegationConfig struct {
	Issuer     string
	Conditions string
	Token      string
}

// SessionOption mutates a SessionConfig instance.
type SessionOption func(*SessionConfig)

// WithSessionConfig replaces the default session configuration with the provided values.
func WithSessionConfig(cfg SessionConfig) SessionOption {
	return func(target *SessionConfig) {
		*target = cfg
	}
}

// WithSessionBufferSize sets the buffered capacity for outgoing replies.
func WithSessionBufferSize(size int) SessionOption {
	return func(target *SessionConfig) {
		target.OutgoingBufferSize = size
	}
}

// WithSessionWriteTimeouts configures write deadlines for control and data frames.
func WithSessionWriteTimeouts(control, data time.Duration) SessionOption {
	return func(target *SessionConfig) {
		target.ControlWriteTimeout = control
		target.DataWriteTimeout = data
	}
}

// WithSessionPingConfig overrides the ping-pong intervals.
func WithSessionPingConfig(pingInterval, pongTimeout time.Duration) SessionOption {
	return func(target *SessionConfig) {
		target.PingInterval = pingInterval
		target.PongTimeout = pongTimeout
	}
}

// WithSessionCloseGrace configures how long we wait for the peer close frame.
func WithSessionCloseGrace(delta time.Duration) SessionOption {
	return func(target *SessionConfig) {
		target.CloseGracePeriod = delta
	}
}

// WithSessionMaxConcurrentTasks limits concurrent store submissions per session.
func WithSessionMaxConcurrentTasks(limit int) SessionOption {
	return func(target *SessionConfig) {
		target.MaxConcurrentStoreTasks = limit
	}
}

// WithSessionCacheConfig sets the default window and limit for cache requests.
func WithSessionCacheConfig(window time.Duration, limit int) SessionOption {
	return func(target *SessionConfig) {
		target.DefaultCacheWindow = window
		target.DefaultCacheLimit = limit
	}
}

// WithSessionSearchLimit sets the default limit for search requests.
func WithSessionSearchLimit(limit int) SessionOption {
	return func(target *SessionConfig) {
		target.DefaultSearchLimit = limit
	}
}

// WithSessionPrivKey sets the relay's own private key, used to sign cache
// responses (see handler_cache.go). Setting this alone, unlike
// WithSessionConfig, does not discard any other configured defaults.
func WithSessionPrivKey(key string) SessionOption {
	return func(target *SessionConfig) {
		target.PrivKey = key
	}
}

// WithSessionTopZapped enables or disables the signed "top zapped" cache
// response (see handler_cache.go). Setting this alone, unlike
// WithSessionConfig, does not discard any other configured defaults.
func WithSessionTopZapped(enabled bool) SessionOption {
	return func(target *SessionConfig) {
		target.EnableTopZapped = enabled
	}
}

// WithSessionDelegation sets NIP-26 delegation for cache responses. Setting
// this alone, unlike WithSessionConfig, does not discard any other
// configured defaults.
func WithSessionDelegation(d *DelegationConfig) SessionOption {
	return func(target *SessionConfig) {
		target.Delegation = d
	}
}

// WithSessionAllowedOrigins restricts the CORS allowlist checked against the
// WebSocket handshake's Origin header to the given origins. Without this
// option, any origin is allowed ("*"), matching prior behavior.
func WithSessionAllowedOrigins(origins ...string) SessionOption {
	return func(target *SessionConfig) {
		target.AllowedOrigins = origins
	}
}

// WithLogger configures the logger used for session lifecycle,
// verification, and error logging. Defaults to zerolog.Nop() (silent).
func WithLogger(logger zerolog.Logger) SessionOption {
	return func(target *SessionConfig) {
		target.Logger = logger
	}
}

func defaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		PingInterval:            30 * time.Second,
		PongTimeout:             60 * time.Second,
		ControlWriteTimeout:     15 * time.Second,
		DataWriteTimeout:        0, // no hard data deadline by default
		CloseGracePeriod:        defaultCloseGracePeriod,
		OutgoingBufferSize:      defaultOutgoingBufferSize,
		MaxConcurrentStoreTasks: defaultMaxConcurrentStoreTasks,
		DefaultCacheWindow:      24 * time.Hour,
		DefaultCacheLimit:       50,
		DefaultSearchLimit:      100,
		AllowedOrigins:          wsDefaultAllowedOrigins,
		Logger:                  zerolog.Nop(),
	}
}

type EventStoreConfig struct {
	TaskQueueSize int
	WorkerCount   int
	BatchSize     int
	BatchInterval time.Duration

	// Logger receives store/migration logging. Defaults to zerolog.Nop()
	// (silent) so an EventStore never writes to the process-global logger
	// unless the caller opts in.
	Logger zerolog.Logger
}

// EventStoreOption mutates the internal event store configuration.
type EventStoreOption func(*EventStoreConfig)

// WithEventStoreQueueSize sets the buffered queue size for store tasks.
func WithEventStoreQueueSize(size int) EventStoreOption {
	return func(cfg *EventStoreConfig) {
		cfg.TaskQueueSize = size
	}
}

// WithEventStoreWorkerCount sets the number of background workers.
func WithEventStoreWorkerCount(count int) EventStoreOption {
	return func(cfg *EventStoreConfig) {
		cfg.WorkerCount = count
	}
}

// WithEventStoreBatchConfig sets the batch processing parameters.
func WithEventStoreBatchConfig(size int, interval time.Duration) EventStoreOption {
	return func(cfg *EventStoreConfig) {
		cfg.BatchSize = size
		cfg.BatchInterval = interval
	}
}

// WithEventStoreLogger configures the logger used for store and migration
// logging. Defaults to zerolog.Nop() (silent).
func WithEventStoreLogger(logger zerolog.Logger) EventStoreOption {
	return func(cfg *EventStoreConfig) {
		cfg.Logger = logger
	}
}

func defaultEventStoreConfig() EventStoreConfig {
	workers := runtime.NumCPU()
	if workers <= 0 {
		workers = 1
	}
	return EventStoreConfig{
		TaskQueueSize: 8192,
		WorkerCount:   workers,
		BatchSize:     500,
		// 10ms bounds a solo writer's added latency to roughly that, while
		// still leaving room for concurrent submissions to coalesce into one
		// bolt transaction; BatchSize remains the safety valve once real
		// concurrent load fills a batch before the timer would fire anyway.
		BatchInterval: 10 * time.Millisecond,
		Logger:        zerolog.Nop(),
	}
}
