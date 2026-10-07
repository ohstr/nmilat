package wsaudio_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"

	"github.com/ohstr/nmilat/huddle/room"
	"github.com/ohstr/nmilat/huddle/wire"
	"github.com/ohstr/nmilat/huddle/wsaudio"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/utils"
)

const (
	relayURL   = "wss://relay.example"
	alicePriv  = "0acd1245d4b0e9cae1a3b0e1a1e0cf3d1e5b2a7c8d9e0f1a2b3c4d5e6f70268c"
	bobPriv    = "1bde2356e5c1fadbf2b4c1f2b2f1d04e2f6c3b8d9eaf102b3c4d5e6f78901234"
	carolPriv  = "2cef3467f6d20bece3c5d203c3020f5f306d4c9e0fb0213c4d5e6f7890123456"
	readWindow = 10 * time.Second
)

// harness runs the endpoint over a real HTTP server.
//
// The handler logs to a Nop logger on purpose. Routing zerolog into t.Log looks
// helpful but is a trap: this session's goroutines can outlive the test, and a
// log line written into a completed *testing.T panics the whole package. Tests
// assert on protocol messages instead, which is the contract anyway.
type harness struct {
	t     *testing.T
	srv   *httptest.Server
	rooms *room.Manager
}

func newHarness(t *testing.T, mutate func(*wsaudio.Config)) *harness {
	t.Helper()

	rooms := room.NewManager(0)
	cfg := wsaudio.Config{
		Enabled:  true,
		RelayURL: relayURL,
		Rooms:    rooms,
		Logger:   zerolog.Nop(),
	}
	if mutate != nil {
		mutate(&cfg)
	}

	mux := http.NewServeMux()
	mux.Handle("/huddle/{id}/audio", wsaudio.NewHandler(cfg))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Track whichever manager the config ended up with: a mutate func may have
	// swapped in its own, and asserting against the discarded one would pass
	// while testing nothing.
	_ = rooms
	return &harness{t: t, srv: srv, rooms: cfg.Rooms}
}

func (h *harness) dial(roomID string) *websocket.Conn {
	h.t.Helper()
	url := "ws" + strings.TrimPrefix(h.srv.URL, "http") + "/huddle/" + roomID + "/audio"
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// waitForOccupancy polls until a room holds want peers, proving the server-side
// session reached the state under test rather than guessing from timing.
func (h *harness) waitForOccupancy(roomID string, want int) {
	h.t.Helper()
	deadline := time.Now().Add(readWindow)
	for {
		if h.rooms.Occupancy()[roomID] == want {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("room %q occupancy = %d, want %d", roomID, h.rooms.Occupancy()[roomID], want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readJSON[T any](t *testing.T, conn *websocket.Conn) T {
	t.Helper()
	var out T
	if err := conn.SetReadDeadline(time.Now().Add(readWindow)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	kind, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if kind != websocket.TextMessage {
		t.Fatalf("expected a text frame, got kind %d (%x)", kind, data)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
	return out
}

type controlEnvelope struct {
	Type           string `json:"type"`
	Challenge      string `json:"challenge"`
	Code           string `json:"code"`
	Message        string `json:"message"`
	CurrentVersion *uint8 `json:"current_version"`
	Revision       uint64 `json:"revision"`
	Pubkey         string `json:"pubkey"`
	PeerIndex      uint8  `json:"peer_index"`
	Epoch          uint8  `json:"epoch"`
	Peers          []struct {
		Pubkey    string `json:"pubkey"`
		PeerIndex uint8  `json:"peer_index"`
		Epoch     uint8  `json:"epoch"`
	} `json:"peers"`
}

func readChallenge(t *testing.T, conn *websocket.Conn) string {
	t.Helper()
	msg := readJSON[controlEnvelope](t, conn)
	if msg.Type != "challenge" || msg.Challenge == "" {
		t.Fatalf("expected a challenge, got %+v", msg)
	}
	return msg.Challenge
}

func signedAuth(t *testing.T, privKey, challenge, relay string) *nip01.Event {
	t.Helper()
	ev := nip42.NewAuthEvent(challenge, relay)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return ev
}

func sendAuth(t *testing.T, conn *websocket.Conn, ev *nip01.Event, version *uint8) {
	t.Helper()
	payload := map[string]any{"type": "auth", "event": ev}
	if version != nil {
		payload["protocol_version"] = *version
	}
	if err := conn.WriteJSON(payload); err != nil {
		t.Fatalf("write auth: %v", err)
	}
}

func u8(v uint8) *uint8 { return &v }

// join runs the whole handshake and returns the joined message.
func (h *harness) join(roomID, privKey string, version *uint8) (*websocket.Conn, controlEnvelope) {
	h.t.Helper()
	conn := h.dial(roomID)
	challenge := readChallenge(h.t, conn)
	sendAuth(h.t, conn, signedAuth(h.t, privKey, challenge, relayURL), version)
	joined := readJSON[controlEnvelope](h.t, conn)
	if joined.Type != "joined" {
		h.t.Fatalf("expected joined, got %+v", joined)
	}
	return conn, joined
}

/////////////////////////////////////////////////////////////////////
// Handshake
/////////////////////////////////////////////////////////////////////

func TestHandshakeAdmitsAnAuthenticatedPeer(t *testing.T) {
	h := newHarness(t, nil)
	pubkey, err := utils.GetPublicKey(alicePriv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	_, joined := h.join("room-1", alicePriv, u8(3))

	if joined.Pubkey != pubkey {
		t.Errorf("Pubkey = %q, want %q", joined.Pubkey, pubkey)
	}
	if joined.Revision == 0 {
		t.Error("Revision = 0, want a real roster revision")
	}
	if len(joined.Peers) != 1 || joined.Peers[0].Pubkey != pubkey {
		t.Errorf("Peers = %+v, want the joiner's own entry", joined.Peers)
	}
	if joined.Epoch == 0 {
		t.Error("Epoch = 0, want epochs to start at 1 so 0 can mean unset")
	}
	h.waitForOccupancy("room-1", 1)
}

func TestHandshakeDefaultsProtocolVersionWhenAbsent(t *testing.T) {
	h := newHarness(t, nil)
	// No protocol_version field at all: a client predating negotiation.
	h.join("room-1", alicePriv, nil)
	h.waitForOccupancy("room-1", 1)

	r, ok := h.rooms.Get("room-1")
	if !ok {
		t.Fatal("room missing")
	}
	if got := r.ProtocolVersion(); got != wire.DefaultProtocolVersion {
		t.Errorf("room pinned to v%d, want the default v%d", got, wire.DefaultProtocolVersion)
	}
}

func TestHandshakeRejections(t *testing.T) {
	tests := []struct {
		name     string
		wantCode string
		// send performs whatever the client does after reading the challenge.
		send func(t *testing.T, conn *websocket.Conn, challenge string)
	}{
		{
			name:     "bad signature",
			wantCode: wsaudio.CodeAuthFailed,
			send: func(t *testing.T, conn *websocket.Conn, challenge string) {
				ev := signedAuth(t, alicePriv, challenge, relayURL)
				ev.Sig = strings.Repeat("00", 64)
				sendAuth(t, conn, ev, u8(3))
			},
		},
		{
			name:     "relay tag names a different relay",
			wantCode: wsaudio.CodeAuthFailed,
			send: func(t *testing.T, conn *websocket.Conn, challenge string) {
				sendAuth(t, conn, signedAuth(t, alicePriv, challenge, "wss://somewhere.else"), u8(3))
			},
		},
		{
			name:     "wrong challenge",
			wantCode: wsaudio.CodeAuthFailed,
			send: func(t *testing.T, conn *websocket.Conn, _ string) {
				sendAuth(t, conn, signedAuth(t, alicePriv, "not-the-challenge", relayURL), u8(3))
			},
		},
		{
			name:     "stale created_at",
			wantCode: wsaudio.CodeAuthFailed,
			send: func(t *testing.T, conn *websocket.Conn, challenge string) {
				ev := nip42.NewAuthEvent(challenge, relayURL)
				ev.CreatedAt = uint64(time.Now().Add(-24 * time.Hour).Unix())
				if err := ev.Sign(alicePriv); err != nil {
					t.Fatalf("sign: %v", err)
				}
				sendAuth(t, conn, ev, u8(3))
			},
		},
		{
			name:     "missing auth event",
			wantCode: wsaudio.CodeAuthFailed,
			send: func(t *testing.T, conn *websocket.Conn, _ string) {
				if err := conn.WriteJSON(map[string]any{"type": "auth"}); err != nil {
					t.Fatalf("write: %v", err)
				}
			},
		},
		{
			name:     "audio before authentication",
			wantCode: wsaudio.CodeAuthFailed,
			send: func(t *testing.T, conn *websocket.Conn, _ string) {
				frame := wire.EncodeFrame(wire.FrameHeader{}, []byte("opus"))
				if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					t.Fatalf("write: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			conn := h.dial("room-1")
			challenge := readChallenge(t, conn)
			tc.send(t, conn, challenge)

			msg := readJSON[controlEnvelope](t, conn)
			if msg.Type != "error" || msg.Code != tc.wantCode {
				t.Fatalf("got %+v, want an error with code %q", msg, tc.wantCode)
			}
			if h.rooms.Len() != 0 {
				t.Errorf("a refused join left %d room(s) behind", h.rooms.Len())
			}
		})
	}
}

// A non-auth control frame before auth is ignored rather than fatal, so a
// client that says hello first can still authenticate.
func TestHandshakeIgnoresUnknownControlBeforeAuth(t *testing.T) {
	h := newHarness(t, nil)
	conn := h.dial("room-1")
	challenge := readChallenge(t, conn)

	if err := conn.WriteJSON(map[string]any{"type": "hello"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("{not json")); err != nil {
		t.Fatalf("write: %v", err)
	}
	sendAuth(t, conn, signedAuth(t, alicePriv, challenge, relayURL), u8(3))

	if msg := readJSON[controlEnvelope](t, conn); msg.Type != "joined" {
		t.Fatalf("got %+v, want joined", msg)
	}
}

func TestHandshakeAuthTimeout(t *testing.T) {
	h := newHarness(t, func(c *wsaudio.Config) { c.AuthTimeout = 100 * time.Millisecond })
	conn := h.dial("room-1")
	readChallenge(t, conn)

	// Never send auth. The server must drop the connection rather than hold the
	// slot open indefinitely.
	if err := conn.SetReadDeadline(time.Now().Add(readWindow)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected the connection to be closed after the auth timeout")
	}
	if h.rooms.Len() != 0 {
		t.Errorf("timed-out handshake left %d room(s)", h.rooms.Len())
	}
}

func TestDisabledEndpointSaysSoExplicitly(t *testing.T) {
	h := newHarness(t, func(c *wsaudio.Config) { c.Enabled = false })
	conn := h.dial("room-1")

	msg := readJSON[controlEnvelope](t, conn)
	if msg.Type != "error" || msg.Code != wsaudio.CodeAudioUnavailable {
		t.Fatalf("got %+v, want %q", msg, wsaudio.CodeAudioUnavailable)
	}
}

func TestAuthorizeHookCanRefuseAJoin(t *testing.T) {
	h := newHarness(t, func(c *wsaudio.Config) {
		c.Authorize = func(_ context.Context, roomID, pubkey string) error {
			if roomID == "private" {
				return errors.New("not a member")
			}
			return nil
		}
	})

	conn := h.dial("private")
	challenge := readChallenge(t, conn)
	sendAuth(t, conn, signedAuth(t, alicePriv, challenge, relayURL), u8(3))

	msg := readJSON[controlEnvelope](t, conn)
	if msg.Type != "error" || msg.Code != wsaudio.CodeJoinRejected {
		t.Fatalf("got %+v, want %q", msg, wsaudio.CodeJoinRejected)
	}

	// The same identity joins an open room fine.
	h.join("open", alicePriv, u8(3))
}

func TestProtocolVersionMismatchIsRefusedWithTheRoomsVersion(t *testing.T) {
	h := newHarness(t, nil)
	h.join("room-1", alicePriv, u8(2))
	h.waitForOccupancy("room-1", 1)

	conn := h.dial("room-1")
	challenge := readChallenge(t, conn)
	sendAuth(t, conn, signedAuth(t, bobPriv, challenge, relayURL), u8(3))

	msg := readJSON[controlEnvelope](t, conn)
	if msg.Type != "error" || msg.Code != wsaudio.CodeUpgradeRequired {
		t.Fatalf("got %+v, want %q", msg, wsaudio.CodeUpgradeRequired)
	}
	if msg.CurrentVersion == nil || *msg.CurrentVersion != 2 {
		t.Errorf("CurrentVersion = %v, want 2 so the client can retry correctly", msg.CurrentVersion)
	}
}

func TestUnsupportedProtocolVersionIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	conn := h.dial("room-1")
	challenge := readChallenge(t, conn)
	sendAuth(t, conn, signedAuth(t, alicePriv, challenge, relayURL), u8(99))

	msg := readJSON[controlEnvelope](t, conn)
	if msg.Type != "error" || msg.Code != wsaudio.CodeUpgradeRequired {
		t.Fatalf("got %+v, want %q", msg, wsaudio.CodeUpgradeRequired)
	}
}

func TestRoomCapIsReported(t *testing.T) {
	h := newHarness(t, func(c *wsaudio.Config) { c.Rooms = room.NewManager(1) })
	_, _ = h.join("first", alicePriv, u8(3))
	h.waitForOccupancy("first", 1)

	conn := h.dial("second")
	challenge := readChallenge(t, conn)
	sendAuth(t, conn, signedAuth(t, bobPriv, challenge, relayURL), u8(3))

	msg := readJSON[controlEnvelope](t, conn)
	if msg.Type != "error" || msg.Code != wsaudio.CodeRoomUnavailable {
		t.Fatalf("got %+v, want %q", msg, wsaudio.CodeRoomUnavailable)
	}
}

/////////////////////////////////////////////////////////////////////
// Relay behaviour
/////////////////////////////////////////////////////////////////////

func TestFrameReachesTheOtherPeerAndNotItsSender(t *testing.T) {
	h := newHarness(t, nil)
	aliceConn, alice := h.join("room-1", alicePriv, u8(3))
	bobConn, _ := h.join("room-1", bobPriv, u8(3))
	h.waitForOccupancy("room-1", 2)

	// Alice's join notice reaches Bob... but Bob joined second, so it is Bob's
	// own joined message Alice must have received.
	if msg := readJSON[controlEnvelope](t, aliceConn); msg.Type != "joined" {
		t.Fatalf("alice got %+v, want bob's joined notice", msg)
	}

	frame := wire.EncodeFrame(wire.FrameHeader{Seq: 7, Ts48k: 960, LevelDbov: -20}, []byte("opus-payload"))
	if err := aliceConn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	if err := bobConn.SetReadDeadline(time.Now().Add(readWindow)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	// Control messages (text) may be interleaved ahead of the frame; the
	// frame is the first binary message.
	var got []byte
	for {
		kind, data, err := bobConn.ReadMessage()
		if err != nil {
			t.Fatalf("bob read: %v", err)
		}
		if kind == websocket.BinaryMessage {
			got = data
			break
		}
	}

	index, epoch, payload, ok := wire.ParseRelayFrame(3, got)
	if !ok {
		t.Fatalf("bob got an unparseable frame %x", got)
	}
	if index != alice.PeerIndex || epoch != alice.Epoch {
		t.Errorf("attribution = %d/%d, want alice at %d/%d", index, epoch, alice.PeerIndex, alice.Epoch)
	}
	if string(payload) != string(frame) {
		t.Errorf("payload = %x, want alice's frame verbatim %x", payload, frame)
	}

	// Alice must not hear herself.
	if err := aliceConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if kind, data, err := aliceConn.ReadMessage(); err == nil && kind == websocket.BinaryMessage {
		t.Errorf("alice received her own frame back: %x", data)
	}
}

// A malformed frame is dropped without ending the call: one bad frame from a
// peer a version ahead must not disconnect everyone.
func TestMalformedFrameIsDroppedWithoutEndingTheSession(t *testing.T) {
	h := newHarness(t, nil)
	aliceConn, alice := h.join("room-1", alicePriv, u8(3))
	bobConn, _ := h.join("room-1", bobPriv, u8(3))
	h.waitForOccupancy("room-1", 2)
	readJSON[controlEnvelope](t, aliceConn) // bob's joined

	// Too short to hold a header, and an oversize frame.
	for _, bad := range [][]byte{{0x01, 0x02}, make([]byte, wire.MaxFrameBytes+1)} {
		if err := aliceConn.WriteMessage(websocket.BinaryMessage, bad); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// A text frame past auth is also ignored rather than fatal.
	if err := aliceConn.WriteMessage(websocket.TextMessage, []byte(`{"type":"whatever"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The session survives, so a good frame still gets through.
	good := wire.EncodeFrame(wire.FrameHeader{Seq: 1}, []byte("ok"))
	if err := aliceConn.WriteMessage(websocket.BinaryMessage, good); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := bobConn.SetReadDeadline(time.Now().Add(readWindow)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	kind, got, err := bobConn.ReadMessage()
	if err != nil {
		t.Fatalf("bob read: %v", err)
	}
	if kind != websocket.BinaryMessage {
		t.Fatalf("bob got kind %d, want the good frame", kind)
	}
	_, _, payload, ok := wire.ParseRelayFrame(3, got)
	if !ok || string(payload) != string(good) {
		t.Errorf("bob got %x, want the good frame %x", payload, good)
	}
	_ = alice
}

func TestJoinAndLeaveAreBroadcastToTheRoom(t *testing.T) {
	h := newHarness(t, nil)
	aliceConn, _ := h.join("room-1", alicePriv, u8(3))
	bobConn, bob := h.join("room-1", bobPriv, u8(3))
	h.waitForOccupancy("room-1", 2)

	joined := readJSON[controlEnvelope](t, aliceConn)
	if joined.Type != "joined" || joined.Pubkey != bob.Pubkey {
		t.Fatalf("alice got %+v, want bob's joined", joined)
	}

	// Bob leaves; alice is told, with bob's routing identity so she can retire it.
	_ = bobConn.Close()
	h.waitForOccupancy("room-1", 1)

	left := readJSON[controlEnvelope](t, aliceConn)
	if left.Type != "left" || left.Pubkey != bob.Pubkey {
		t.Fatalf("alice got %+v, want bob's left", left)
	}
	if left.PeerIndex != bob.PeerIndex || left.Epoch != bob.Epoch {
		t.Errorf("left identity = %d/%d, want %d/%d", left.PeerIndex, left.Epoch, bob.PeerIndex, bob.Epoch)
	}
}

func TestRoomIsDroppedWhenTheLastPeerLeaves(t *testing.T) {
	h := newHarness(t, nil)
	conn, _ := h.join("room-1", alicePriv, u8(3))
	h.waitForOccupancy("room-1", 1)

	_ = conn.Close()

	deadline := time.Now().Add(readWindow)
	for h.rooms.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("rooms = %v, want the empty room dropped", h.rooms.Occupancy())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestThreePeersEachHearTheOtherTwo(t *testing.T) {
	h := newHarness(t, nil)

	type participant struct {
		conn *websocket.Conn
		info controlEnvelope
	}
	var peers []participant
	for _, key := range []string{alicePriv, bobPriv, carolPriv} {
		conn, info := h.join("room-1", key, u8(3))
		peers = append(peers, participant{conn: conn, info: info})
	}
	h.waitForOccupancy("room-1", 3)

	// Each peer speaks once; every other peer must hear it, correctly attributed.
	for speaker := range peers {
		frame := wire.EncodeFrame(wire.FrameHeader{Seq: uint16(speaker)}, []byte(fmt.Sprintf("from-%d", speaker)))
		if err := peers[speaker].conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			t.Fatalf("speaker %d write: %v", speaker, err)
		}

		for listener := range peers {
			if listener == speaker {
				continue
			}
			got, ok := readNextBinary(t, peers[listener].conn)
			if !ok {
				t.Fatalf("listener %d heard nothing from speaker %d", listener, speaker)
			}
			index, _, payload, parsed := wire.ParseRelayFrame(3, got)
			if !parsed {
				t.Fatalf("listener %d got an unparseable frame", listener)
			}
			if index != peers[speaker].info.PeerIndex {
				t.Errorf("listener %d attributed the frame to %d, want %d", listener, index, peers[speaker].info.PeerIndex)
			}
			if string(payload) != string(frame) {
				t.Errorf("listener %d got %x, want %x", listener, payload, frame)
			}
		}
	}
}

// readNextBinary skips control frames (joins land interleaved with audio) and
// returns the next binary frame.
func readNextBinary(t *testing.T, conn *websocket.Conn) ([]byte, bool) {
	t.Helper()
	deadline := time.Now().Add(readWindow)
	for time.Now().Before(deadline) {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, false
		}
		kind, data, err := conn.ReadMessage()
		if err != nil {
			return nil, false
		}
		if kind == websocket.BinaryMessage {
			return data, true
		}
	}
	return nil, false
}

/////////////////////////////////////////////////////////////////////
// Origin policy
/////////////////////////////////////////////////////////////////////

// Origin is not this endpoint's security boundary -- admission is gated by a
// signed challenge -- so the default must not lock browsers out. Refusing on
// Origin by default is exactly the bug that makes a relay unreachable from a web
// client while every CLI keeps working, so it stays off unless configured.
func TestOriginPolicy(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		origin  string
		wantOK  bool
	}{
		{name: "no origin header is always allowed", origin: "", wantOK: true},
		{name: "unconfigured allows any browser origin", origin: "https://app.example", wantOK: true},
		{name: "wildcard allows any origin", allowed: []string{"*"}, origin: "https://app.example", wantOK: true},
		{name: "exact origin match", allowed: []string{"https://app.example"}, origin: "https://app.example", wantOK: true},
		{name: "host match", allowed: []string{"app.example"}, origin: "https://app.example", wantOK: true},
		{name: "match is case-insensitive", allowed: []string{"https://APP.example"}, origin: "https://app.example", wantOK: true},
		{name: "unlisted origin is refused", allowed: []string{"https://app.example"}, origin: "https://evil.example", wantOK: false},
		{name: "a configured list still allows a header-less client", allowed: []string{"https://app.example"}, origin: "", wantOK: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *wsaudio.Config) { c.AllowedOrigins = tc.allowed })
			url := "ws" + strings.TrimPrefix(h.srv.URL, "http") + "/huddle/room-1/audio"

			var header http.Header
			if tc.origin != "" {
				header = http.Header{"Origin": []string{tc.origin}}
			}
			conn, _, err := websocket.DefaultDialer.Dial(url, header)
			if conn != nil {
				t.Cleanup(func() { _ = conn.Close() })
			}
			if tc.wantOK && err != nil {
				t.Fatalf("dial was refused: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("dial succeeded for an unlisted origin")
			}
		})
	}
}

/////////////////////////////////////////////////////////////////////
// Heartbeat
/////////////////////////////////////////////////////////////////////

// A peer that stops answering pings is disconnected rather than left occupying a
// routing index forever. A client that never calls ReadMessage never auto-pongs,
// which is exactly how a wedged peer behaves.
func TestHeartbeatDisconnectsASilentPeer(t *testing.T) {
	h := newHarness(t, func(c *wsaudio.Config) {
		c.PingInterval = 50 * time.Millisecond
		c.MaxMissedPong = 1
	})

	conn, _ := h.join("room-1", alicePriv, u8(3))
	h.waitForOccupancy("room-1", 1)

	// Deliberately stop reading, so no pong is ever produced. The server should
	// give up within roughly MaxMissedPong intervals and drop the peer.
	deadline := time.Now().Add(readWindow)
	for h.rooms.Occupancy()["room-1"] != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a silent peer was never disconnected by the heartbeat")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The socket really is gone from the client's side too.
	if err := conn.SetReadDeadline(time.Now().Add(readWindow)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// The complement: a peer that keeps reading answers pings automatically and is
// never dropped, so the heartbeat cannot evict a healthy participant.
func TestHeartbeatKeepsAHealthyPeer(t *testing.T) {
	h := newHarness(t, func(c *wsaudio.Config) {
		c.PingInterval = 20 * time.Millisecond
		c.MaxMissedPong = 1
	})

	conn, _ := h.join("room-1", alicePriv, u8(3))
	h.waitForOccupancy("room-1", 1)

	// Keep reading so gorilla's default handler answers each ping.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	defer close(stop)

	// Well past several ping intervals.
	time.Sleep(300 * time.Millisecond)
	if got := h.rooms.Occupancy()["room-1"]; got != 1 {
		t.Errorf("occupancy = %d, want the healthy peer still present", got)
	}
}

/////////////////////////////////////////////////////////////////////
// Mounting
/////////////////////////////////////////////////////////////////////

func TestServeHTTPRequiresARoomID(t *testing.T) {
	// Mounted without the wildcard, so PathValue yields nothing.
	mux := http.NewServeMux()
	mux.Handle("/huddle/audio", wsaudio.NewHandler(wsaudio.Config{
		Enabled: true, RelayURL: relayURL, Rooms: room.NewManager(0), Logger: zerolog.Nop(),
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/huddle/audio")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestServeHTTPWithoutRoomsConfigured(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/huddle/{id}/audio", wsaudio.NewHandler(wsaudio.Config{
		Enabled: true, RelayURL: relayURL, Logger: zerolog.Nop(),
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/huddle/room-1/audio")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}
