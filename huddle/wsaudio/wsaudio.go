// Package wsaudio serves huddle audio over a WebSocket: NIP-42 authentication,
// room admission, and the frame relay that follows.
//
//	ServeHTTP
//	  └─ session.run
//	       ├─ send challenge, await auth (bounded)
//	       ├─ verify the NIP-42 event, authorize, join the room
//	       ├─ send joined to the joiner, broadcast it to everyone else
//	       ├─ start the writer and the ping loop
//	       ├─ read until the peer disconnects
//	       └─ leave the room and broadcast left
//
// # Why its own socket
//
// This endpoint deliberately does not share the Nostr socket. That one accepts
// JSON arrays and decodes every frame as JSON, so a binary audio frame arriving
// on it is a parse error that tears the session down. Audio therefore gets its
// own route and its own upgrader, which also means none of the relay's session
// machinery has to learn about binary frames.
//
// # Control plane
//
// Control messages are JSON *objects* (again unlike the Nostr socket's arrays):
//
//	server -> {"type":"challenge","challenge":"..."}
//	client -> {"type":"auth","event":{...},"protocol_version":2}
//	server -> {"type":"joined","revision":N,"pubkey":"...","peer_index":N,"epoch":N,"peers":[...]}
//	server -> {"type":"left","pubkey":"...","peer_index":N,"epoch":N,"revision":N}
//	server -> {"type":"error","code":"...","message":"..."}
package wsaudio

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"

	"github.com/ohstr/nmilat/huddle/room"
	"github.com/ohstr/nmilat/huddle/wire"
	"github.com/ohstr/nmilat/nip01"
)

// Defaults, mirroring the reference implementation so a client written against
// it needs no retuning.
const (
	DefaultAuthTimeout   = 5 * time.Second
	DefaultPingInterval  = 30 * time.Second
	DefaultWriteTimeout  = 10 * time.Second
	DefaultMaxMissedPong = 3
)

// Error codes a client is expected to branch on. The message beside them is for
// a human; these are the contract.
const (
	// CodeAuthFailed covers every authentication failure without saying which,
	// so a caller cannot use the endpoint to probe what a relay knows.
	CodeAuthFailed = "auth_failed"
	// CodeJoinRejected means authentication succeeded but the pubkey may not
	// join this room.
	CodeJoinRejected = "join_rejected"
	// CodeRoomFull means the room is at participant capacity.
	CodeRoomFull = "room_full"
	// CodeRoomEnded means the huddle is over.
	CodeRoomEnded = "room_ended"
	// CodeUpgradeRequired means the room is pinned to a protocol version the
	// client did not ask for. CurrentVersion names the room's.
	CodeUpgradeRequired = "upgrade_required"
	// CodeAudioUnavailable means this deployment does not serve huddle audio.
	CodeAudioUnavailable = "huddle_audio_unavailable"
	// CodeRoomUnavailable means the relay is already hosting as many rooms as
	// it will.
	CodeRoomUnavailable = "room_unavailable"
)

// Config configures a Handler.
type Config struct {
	// Enabled must be true for the endpoint to admit anyone. A deployment that
	// cannot serve audio -- horizontally scaled without a way to reach the pod
	// hosting a given room, say -- turns it off and clients are told so
	// explicitly rather than joining a room that can never carry their voice.
	Enabled bool

	// RelayURL is the base relay WebSocket URL a client must name in its NIP-42
	// event's "relay" tag. It is the relay's own URL, *not* this huddle
	// endpoint: a client authenticates to the relay, then uses that identity
	// here.
	RelayURL string

	// Rooms holds the live rooms. Required.
	Rooms *room.Manager

	// Authorize, when set, decides whether a pubkey may join a room. Returning
	// an error refuses the join with CodeJoinRejected. This is where relay
	// membership -- NIP-29 group state, NIP-43 relay access -- is consulted;
	// this package deliberately holds no such policy itself.
	Authorize func(ctx context.Context, roomID, pubkey string) error

	// AllowedOrigins restricts browser origins. Empty allows any, which is the
	// right default here: admission is gated by a signed challenge, so the
	// Origin header is not the security boundary and refusing on it only breaks
	// legitimate web clients. Operators who want it narrower can set it.
	AllowedOrigins []string

	// Timeouts. Zero means the corresponding Default above.
	AuthTimeout   time.Duration
	PingInterval  time.Duration
	WriteTimeout  time.Duration
	MaxMissedPong int

	Logger zerolog.Logger
}

func (c Config) authTimeout() time.Duration {
	if c.AuthTimeout <= 0 {
		return DefaultAuthTimeout
	}
	return c.AuthTimeout
}

func (c Config) pingInterval() time.Duration {
	if c.PingInterval <= 0 {
		return DefaultPingInterval
	}
	return c.PingInterval
}

func (c Config) writeTimeout() time.Duration {
	if c.WriteTimeout <= 0 {
		return DefaultWriteTimeout
	}
	return c.WriteTimeout
}

func (c Config) maxMissedPong() int {
	if c.MaxMissedPong <= 0 {
		return DefaultMaxMissedPong
	}
	return c.MaxMissedPong
}

// readDeadline is how long a silent peer is tolerated: long enough for the ping
// loop to have missed its allowance of pongs, so the pong counter is what
// decides, not a race between two independent timers.
func (c Config) readDeadline() time.Duration {
	return c.pingInterval() * time.Duration(c.maxMissedPong()+1)
}

// Handler serves the huddle audio endpoint. Mount it on a path carrying the
// room id as a wildcard, e.g. "/huddle/{id}/audio", and it reads the id with
// Request.PathValue.
type Handler struct {
	cfg      Config
	upgrader websocket.Upgrader
}

// PathValueKey is the wildcard name Handler reads the room id from.
const PathValueKey = "id"

// NewHandler returns a Handler for cfg.
func NewHandler(cfg Config) *Handler {
	h := &Handler{cfg: cfg}
	h.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     h.checkOrigin,
	}
	return h
}

// checkOrigin allows any request without an Origin header (every non-browser
// client) and, when AllowedOrigins is set, only the listed origins.
func (h *Handler) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if len(h.cfg.AllowedOrigins) == 0 {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	for _, allowed := range h.cfg.AllowedOrigins {
		if allowed == "*" {
			return true
		}
		if strings.EqualFold(allowed, origin) || strings.EqualFold(allowed, parsed.Host) {
			return true
		}
	}
	return false
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	roomID := r.PathValue(PathValueKey)
	if roomID == "" {
		http.Error(w, "missing room id", http.StatusBadRequest)
		return
	}
	if h.cfg.Rooms == nil {
		http.Error(w, "huddle audio is not configured", http.StatusServiceUnavailable)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has already written a response.
		h.cfg.Logger.Debug().Err(err).Msg("huddle audio upgrade failed")
		return
	}

	// A disabled deployment still completes the upgrade so it can answer with a
	// code the client understands, rather than a bare HTTP error that looks
	// like the route does not exist.
	s := &session{cfg: h.cfg, conn: conn, roomID: roomID, log: h.cfg.Logger.With().Str("room", roomID).Logger()}
	s.run(r.Context())
}

/////////////////////////////////////////////////////////////////////
// Control-plane messages
/////////////////////////////////////////////////////////////////////

type challengeMessage struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
}

// authMessage is what a client sends in reply to the challenge. ProtocolVersion
// defaults to wire.DefaultProtocolVersion when absent so clients predating
// negotiation keep working.
type authMessage struct {
	Type            string       `json:"type"`
	Event           *nip01.Event `json:"event"`
	ParentChannelID string       `json:"parent_channel_id,omitempty"`
	ProtocolVersion *uint8       `json:"protocol_version,omitempty"`
}

type peerMessage struct {
	Pubkey    string `json:"pubkey"`
	PeerIndex uint8  `json:"peer_index"`
	Epoch     uint8  `json:"epoch"`
}

type joinedMessage struct {
	Type      string        `json:"type"`
	Revision  uint64        `json:"revision"`
	Pubkey    string        `json:"pubkey"`
	PeerIndex uint8         `json:"peer_index"`
	Epoch     uint8         `json:"epoch"`
	Peers     []peerMessage `json:"peers"`
}

type leftMessage struct {
	Type      string `json:"type"`
	Revision  uint64 `json:"revision"`
	Pubkey    string `json:"pubkey"`
	PeerIndex uint8  `json:"peer_index"`
	Epoch     uint8  `json:"epoch"`
}

type errorMessage struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
	// CurrentVersion accompanies CodeUpgradeRequired so a client can retry
	// against the version the room is actually pinned to.
	CurrentVersion *uint8 `json:"current_version,omitempty"`
}

func rosterMessages(peers []room.PeerInfo) []peerMessage {
	out := make([]peerMessage, 0, len(peers))
	for _, p := range peers {
		out = append(out, peerMessage{Pubkey: p.Pubkey, PeerIndex: p.Index, Epoch: p.Epoch})
	}
	return out
}

// protocolVersion resolves the version a client asked for, defaulting when the
// field is absent.
func (a authMessage) protocolVersion() uint8 {
	if a.ProtocolVersion == nil {
		return wire.DefaultProtocolVersion
	}
	return *a.ProtocolVersion
}
