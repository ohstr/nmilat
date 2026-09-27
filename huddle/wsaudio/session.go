package wsaudio

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"

	"github.com/ohstr/nmilat/huddle/room"
	"github.com/ohstr/nmilat/huddle/wire"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/utils"
)

// session is one connected peer's lifetime on this endpoint.
type session struct {
	cfg    Config
	log    zerolog.Logger
	conn   *websocket.Conn
	roomID string

	pubkey  string
	version uint8
	room    *room.Room
	peer    *room.Peer
	// sink is this session's own delivery queues. The room writes into it and
	// writeLoop drains it; holding the concrete type here is what lets the
	// writer read the channels without asking the room for them.
	sink *room.ChannelSink

	missedPongs atomic.Int32
	done        chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup
}

// run drives the whole lifetime and returns once the peer is gone.
func (s *session) run(ctx context.Context) {
	defer func() { _ = s.conn.Close() }()

	s.done = make(chan struct{})

	// One limit covers both message kinds: control JSON is the larger of the
	// two, and binary frames are bounded more tightly after parsing.
	s.conn.SetReadLimit(wire.MaxControlBytes)

	if !s.cfg.Enabled {
		// Answer with a code rather than a bare HTTP error, so a client can tell
		// "this relay does not do audio" from "that route does not exist".
		s.writeError(CodeAudioUnavailable, "this relay does not serve huddle audio", nil)
		return
	}

	if !s.handshake(ctx) {
		return
	}

	// From here on exactly one goroutine writes data frames. The ping loop only
	// writes control frames, which gorilla explicitly allows concurrently.
	s.wg.Add(2)
	go s.writeLoop()
	go s.pingLoop()

	s.readLoop()

	s.shutdown()
	s.wg.Wait()
	s.leave()
}

// handshake runs challenge -> auth -> join, and reports whether the peer is in.
// Every failure path answers with an error code before returning.
func (s *session) handshake(ctx context.Context) bool {
	challenge := nip42.NewChallenge()
	if err := s.writeJSON(challengeMessage{Type: "challenge", Challenge: challenge}); err != nil {
		s.log.Debug().Err(err).Msg("failed to send huddle challenge")
		return false
	}

	auth, ok := s.readAuth()
	if !ok {
		return false
	}

	// The relay tag names the relay, not this endpoint. Validating it against
	// the configured relay URL is what stops an event signed for one relay being
	// replayed at another.
	if auth.Event == nil {
		s.writeError(CodeAuthFailed, "auth event is missing", nil)
		return false
	}
	if err := nip42.ValidateAuthEvent(auth.Event.Kind, auth.Event.Tags, auth.Event.CreatedAt, challenge, s.cfg.RelayURL); err != nil {
		// Deliberately not echoing which check failed: that would let a caller
		// probe the relay's clock skew and configured URL.
		s.log.Debug().Err(err).Msg("huddle auth event rejected")
		s.writeError(CodeAuthFailed, "auth failed", nil)
		return false
	}
	if err := auth.Event.Verify(); err != nil {
		s.log.Debug().Err(err).Msg("huddle auth signature rejected")
		s.writeError(CodeAuthFailed, "auth failed", nil)
		return false
	}
	s.pubkey = auth.Event.PubKey
	s.version = auth.protocolVersion()

	if s.cfg.Authorize != nil {
		if err := s.cfg.Authorize(ctx, s.roomID, s.pubkey); err != nil {
			s.log.Debug().Err(err).Str("pubkey", s.pubkey).Msg("huddle join not authorized")
			s.writeError(CodeJoinRejected, "not permitted to join this room", nil)
			return false
		}
	}

	s.sink = room.NewChannelSink()
	joinedRoom, peer, roster, err := s.cfg.Rooms.Join(s.roomID, s.pubkey, s.version, s.sink)
	if err != nil {
		s.writeJoinError(err)
		return false
	}
	s.room, s.peer = joinedRoom, peer
	s.log = s.log.With().Str("pubkey", s.pubkey).Uint8("peer_index", peer.Index).Logger()

	// The joiner learns its own identity and the roster including itself; every
	// other peer is told separately, so nobody has to merge its own entry in.
	if err := s.writeJSON(joinedMessage{
		Type:      "joined",
		Revision:  roster.Revision,
		Pubkey:    s.pubkey,
		PeerIndex: peer.Index,
		Epoch:     peer.Epoch,
		Peers:     rosterMessages(roster.Peers),
	}); err != nil {
		s.log.Debug().Err(err).Msg("failed to send joined")
		s.cfg.Rooms.Leave(s.roomID, peer.ID)
		return false
	}

	s.broadcastJoined(roster)
	return true
}

// writeJoinError maps a room admission failure onto the wire code a client acts
// on.
func (s *session) writeJoinError(err error) {
	switch {
	case errors.Is(err, room.ErrRoomFull):
		s.writeError(CodeRoomFull, "room participant capacity reached", nil)
	case errors.Is(err, room.ErrRoomEnded):
		s.writeError(CodeRoomEnded, "huddle has ended", nil)
	case errors.Is(err, room.ErrUpgradeRequired):
		var current *uint8
		if r, ok := s.cfg.Rooms.Get(s.roomID); ok {
			v := r.ProtocolVersion()
			current = &v
		}
		s.writeError(CodeUpgradeRequired, "huddle audio protocol version not supported by this room", current)
	case errors.Is(err, room.ErrBadVersion):
		v := uint8(wire.CurrentProtocolVersion)
		s.writeError(CodeUpgradeRequired, "unsupported huddle audio protocol version", &v)
	case errors.Is(err, room.ErrTooManyRooms):
		s.writeError(CodeRoomUnavailable, "relay is hosting too many rooms", nil)
	default:
		s.log.Warn().Err(err).Msg("huddle join failed")
		s.writeError(CodeJoinRejected, "join rejected", nil)
	}
}

func (s *session) broadcastJoined(roster room.Roster) {
	message, err := json.Marshal(joinedMessage{
		Type:      "joined",
		Revision:  roster.Revision,
		Pubkey:    s.pubkey,
		PeerIndex: s.peer.Index,
		Epoch:     s.peer.Epoch,
		Peers:     rosterMessages(roster.Peers),
	})
	if err != nil {
		return
	}
	if dropped := s.room.BroadcastControl(string(message), s.peer.ID); dropped > 0 {
		// A dropped control message leaves that peer's index-to-pubkey map
		// stale, which misattributes every later frame. Worth a warning even
		// though this session is not the one harmed.
		s.log.Warn().Int("peers", dropped).Msg("joined notice dropped for peers with a full control queue")
	}
}

// readAuth waits for the auth message, bounded so an idle connection cannot
// hold a slot open indefinitely.
func (s *session) readAuth() (authMessage, bool) {
	if err := s.conn.SetReadDeadline(time.Now().Add(s.cfg.authTimeout())); err != nil {
		return authMessage{}, false
	}

	for {
		kind, data, err := s.conn.ReadMessage()
		if err != nil {
			s.log.Debug().Err(err).Msg("huddle auth read failed")
			return authMessage{}, false
		}
		if kind == websocket.BinaryMessage {
			// Audio before authentication is not tolerated: accepting it would
			// mean relaying frames from an unidentified peer.
			s.writeError(CodeAuthFailed, "audio received before authentication", nil)
			return authMessage{}, false
		}

		var auth authMessage
		if err := json.Unmarshal(data, &auth); err != nil {
			// A malformed control frame is ignored rather than fatal, so a
			// client that sends something unexpected can still authenticate.
			s.log.Debug().Err(err).Msg("huddle control frame is not JSON")
			continue
		}
		if auth.Type != "auth" {
			continue
		}
		return auth, true
	}
}

// readLoop carries frames from this peer into the room until the socket closes.
func (s *session) readLoop() {
	defer utils.RecoverPanic(s.log)

	s.conn.SetPongHandler(func(string) error {
		s.missedPongs.Store(0)
		return s.conn.SetReadDeadline(time.Now().Add(s.cfg.readDeadline()))
	})
	if err := s.conn.SetReadDeadline(time.Now().Add(s.cfg.readDeadline())); err != nil {
		return
	}

	for {
		kind, data, err := s.conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.log.Debug().Err(err).Msg("huddle read ended")
			}
			return
		}

		switch kind {
		case websocket.BinaryMessage:
			if ok, reason := wire.ValidClientFrame(s.version, data); !ok {
				// A malformed frame is dropped, not fatal. One bad frame should
				// not end a call, and the sender may simply be a version ahead.
				s.log.Debug().Str("reason", reason).Int("bytes", len(data)).Msg("dropping huddle frame")
				continue
			}
			s.room.BroadcastFrame(s.peer.ID, data)
		case websocket.TextMessage:
			// No client-to-server control message is defined past auth. Unknown
			// ones are ignored so the protocol can grow without breaking peers.
			s.log.Debug().Int("bytes", len(data)).Msg("ignoring unexpected huddle control frame")
		}
	}
}

// writeLoop is the sole writer of data frames.
func (s *session) writeLoop() {
	defer s.wg.Done()
	defer utils.RecoverPanic(s.log)

	for {
		select {
		case <-s.done:
			return
		case frame := <-s.sink.Audio():
			if err := s.writeBinary(frame); err != nil {
				s.shutdown()
				return
			}
		case control := <-s.sink.Control():
			if control.Close {
				s.shutdown()
				return
			}
			if err := s.writeText(control.JSON); err != nil {
				s.shutdown()
				return
			}
		}
	}
}

// pingLoop keeps the connection warm and disconnects a peer that has stopped
// answering. It writes only control frames, which is safe alongside writeLoop.
func (s *session) pingLoop() {
	defer s.wg.Done()
	defer utils.RecoverPanic(s.log)

	ticker := time.NewTicker(s.cfg.pingInterval())
	defer ticker.Stop()

	limit := int32(s.cfg.maxMissedPong())
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.missedPongs.Load() >= limit {
				s.log.Debug().Int32("missed", s.missedPongs.Load()).Msg("huddle peer stopped answering pings")
				s.shutdown()
				return
			}
			s.missedPongs.Add(1)
			deadline := time.Now().Add(s.cfg.writeTimeout())
			if err := s.conn.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
				s.shutdown()
				return
			}
		}
	}
}

// leave removes this peer from its room and tells the remaining peers.
func (s *session) leave() {
	if s.peer == nil || s.room == nil {
		return
	}

	// Snapshot after removal so the revision the peers see matches the roster
	// they would read.
	s.cfg.Rooms.Leave(s.roomID, s.peer.ID)
	roster := s.room.Roster()

	message, err := json.Marshal(leftMessage{
		Type:      "left",
		Revision:  roster.Revision,
		Pubkey:    s.pubkey,
		PeerIndex: s.peer.Index,
		Epoch:     s.peer.Epoch,
	})
	if err != nil {
		return
	}
	s.room.BroadcastControl(string(message), s.peer.ID)
}

// shutdown signals every goroutine of this session to stop. Idempotent.
func (s *session) shutdown() {
	s.closeOnce.Do(func() {
		close(s.done)
		// Unblock a reader parked in ReadMessage.
		_ = s.conn.SetReadDeadline(time.Now())
	})
}

func (s *session) writeJSON(v any) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.cfg.writeTimeout())); err != nil {
		return err
	}
	return s.conn.WriteJSON(v)
}

func (s *session) writeText(payload string) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.cfg.writeTimeout())); err != nil {
		return err
	}
	return s.conn.WriteMessage(websocket.TextMessage, []byte(payload))
}

func (s *session) writeBinary(payload []byte) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.cfg.writeTimeout())); err != nil {
		return err
	}
	return s.conn.WriteMessage(websocket.BinaryMessage, payload)
}

// writeError reports a refusal. It is only ever called before the writer
// goroutine starts, or on a path that then stops the session, so it does not
// contend with writeLoop.
func (s *session) writeError(code, message string, currentVersion *uint8) {
	_ = s.writeJSON(errorMessage{Type: "error", Code: code, Message: message, CurrentVersion: currentVersion})
}
