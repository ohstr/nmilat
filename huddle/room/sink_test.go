package room

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/ohstr/nmilat/huddle/wire"
)

// recordingSink stands in for a sink that repacketizes onto another transport:
// it keeps the structured parts and ignores the WebSocket-shaped Relayed bytes
// entirely, which is exactly the split this interface exists to allow.
type recordingSink struct {
	mu       sync.Mutex
	frames   []Frame
	payloads [][]byte
	headers  []wire.FrameHeader
	controls []Control
	refuse   bool
}

func (s *recordingSink) SendFrame(f Frame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refuse {
		return false
	}
	header, payload, hasHeader := f.Payload()
	s.frames = append(s.frames, f)
	// Copy: Frame's slices alias the broadcast's buffers.
	s.payloads = append(s.payloads, append([]byte(nil), payload...))
	if hasHeader {
		s.headers = append(s.headers, header)
	}
	return true
}

func (s *recordingSink) SendControl(c Control) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refuse {
		return false
	}
	s.controls = append(s.controls, c)
	return true
}

func (s *recordingSink) snapshot() ([]Frame, [][]byte, []wire.FrameHeader, []Control) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frames, s.payloads, s.headers, s.controls
}

/////////////////////////////////////////////////////////////////////
// The Sink seam
/////////////////////////////////////////////////////////////////////

func TestAddPeerRequiresASink(t *testing.T) {
	r := New()
	if _, _, err := r.AddPeer("alice", v3, nil); !errors.Is(err, ErrNoSink) {
		t.Fatalf("err = %v, want ErrNoSink", err)
	}
	if r.Len() != 0 {
		t.Errorf("Len() = %d, want the refused peer not admitted", r.Len())
	}
}

func TestSinkReceivesTheAuthorAndBothFrameShapes(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)

	listener := &recordingSink{}
	if _, _, err := r.AddPeer("listener", v3, listener); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	opus := []byte("opus-payload")
	header := wire.FrameHeader{Seq: 42, Ts48k: 960, LevelDbov: -20, Flags: wire.FlagDTX}
	client := wire.EncodeFrame(header, opus)

	if dropped := r.BroadcastFrame(alice.ID, client); dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}

	frames, payloads, headers, _ := listener.snapshot()
	if len(frames) != 1 {
		t.Fatalf("sink got %d frames, want 1", len(frames))
	}
	got := frames[0]

	if got.Author.Pubkey != "alice" || got.Author.Index != alice.Index || got.Author.Epoch != alice.Epoch {
		t.Errorf("Author = %+v, want alice at %d/%d", got.Author, alice.Index, alice.Epoch)
	}
	if got.Version != v3 {
		t.Errorf("Version = %d, want %d", got.Version, v3)
	}
	// Client is the author's bytes untouched...
	if !bytes.Equal(got.Client, client) {
		t.Errorf("Client = %x, want the author's frame verbatim %x", got.Client, client)
	}
	// ...and Relayed is those bytes behind the routing prefix.
	wantRelayed := wire.RelayFrame(v3, alice.Index, alice.Epoch, client)
	if !bytes.Equal(got.Relayed, wantRelayed) {
		t.Errorf("Relayed = %x, want %x", got.Relayed, wantRelayed)
	}

	// The payoff: a repacketizing sink recovers the opaque Opus byte-identically
	// and the sender's header, with no codec anywhere in the path.
	if !bytes.Equal(payloads[0], opus) {
		t.Errorf("payload = %x, want the Opus bytes verbatim %x", payloads[0], opus)
	}
	if len(headers) != 1 || headers[0] != header {
		t.Errorf("header = %+v, want %+v", headers, header)
	}
}

func TestFramePayload(t *testing.T) {
	opus := []byte("opus")
	withHeader := wire.EncodeFrame(wire.FrameHeader{Seq: 9, LevelDbov: -3}, opus)

	t.Run("v3 exposes the header and payload", func(t *testing.T) {
		header, payload, hasHeader := Frame{Version: 3, Client: withHeader}.Payload()
		if !hasHeader {
			t.Fatal("hasHeader = false for v3")
		}
		if header.Seq != 9 || header.LevelDbov != -3 {
			t.Errorf("header = %+v", header)
		}
		if !bytes.Equal(payload, opus) {
			t.Errorf("payload = %x, want %x", payload, opus)
		}
	})

	t.Run("v1 carries a bare payload and no header", func(t *testing.T) {
		header, payload, hasHeader := Frame{Version: 1, Client: opus}.Payload()
		if hasHeader {
			t.Error("hasHeader = true for v1, which predates the header")
		}
		if header != (wire.FrameHeader{}) {
			t.Errorf("header = %+v, want the zero value", header)
		}
		if !bytes.Equal(payload, opus) {
			t.Errorf("payload = %x, want the whole client frame %x", payload, opus)
		}
	})

	t.Run("a malformed v2 frame reports no header", func(t *testing.T) {
		_, payload, hasHeader := Frame{Version: 2, Client: []byte{0x01}}.Payload()
		if hasHeader {
			t.Error("hasHeader = true for a frame too short to hold one")
		}
		if payload != nil {
			t.Errorf("payload = %x, want nil", payload)
		}
	})
}

// A WebSocket peer and a repacketizing peer sit in one room and both hear the
// same speaker, each getting the shape it needs. This is the precondition the
// audio bridge is built on.
func TestChannelAndRepacketizingSinksCoexist(t *testing.T) {
	r := New()
	speaker := addPeer(t, r, "speaker", v3)
	websocket := addPeer(t, r, "websocket", v3)

	bridged := &recordingSink{}
	if _, _, err := r.AddPeer("bridged", v3, bridged); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	opus := []byte("shared-opus")
	client := wire.EncodeFrame(wire.FrameHeader{Seq: 1}, opus)
	if dropped := r.BroadcastFrame(speaker.ID, client); dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}

	// The WebSocket peer gets wire-ready bytes it can write straight out.
	wsFrame := recvFrame(t, websocket)
	index, epoch, payload, ok := wire.ParseRelayFrame(v3, wsFrame)
	if !ok || index != speaker.Index || epoch != speaker.Epoch {
		t.Fatalf("websocket peer got %x (ok=%v)", wsFrame, ok)
	}
	if !bytes.Equal(payload, client) {
		t.Errorf("websocket payload = %x, want %x", payload, client)
	}

	// The bridged peer gets the opaque Opus, identical to what the speaker sent.
	_, payloads, _, _ := bridged.snapshot()
	if len(payloads) != 1 || !bytes.Equal(payloads[0], opus) {
		t.Fatalf("bridged payloads = %x, want one copy of %x", payloads, opus)
	}
}

func TestSinkRefusalCountsAsADrop(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)

	refusing := &recordingSink{refuse: true}
	peer, _, err := r.AddPeer("refusing", v3, refusing)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	if dropped := r.BroadcastFrame(alice.ID, wire.EncodeFrame(wire.FrameHeader{}, []byte("x"))); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("Dropped() = %d, want 1", got)
	}
	// A refusing control sink is reported too, since control loss is not
	// acceptable degradation.
	if dropped := r.BroadcastControl("msg", alice.ID); dropped != 1 {
		t.Errorf("control dropped = %d, want 1", dropped)
	}
	if r.SendControl(peer.ID, "msg") {
		t.Error("SendControl reported success against a refusing sink")
	}
}

func TestPeerSinkAccessor(t *testing.T) {
	r := New()
	sink := NewChannelSink()
	peer, _, err := r.AddPeer("alice", v3, sink)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if peer.Sink() != Sink(sink) {
		t.Error("Sink() did not return the sink the peer was admitted with")
	}
}

/////////////////////////////////////////////////////////////////////
// ChannelSink
/////////////////////////////////////////////////////////////////////

func TestChannelSinkDropsWhenFull(t *testing.T) {
	sink := NewChannelSinkWithDepth(2, 2)
	frame := Frame{Relayed: []byte("relayed")}

	for i := 0; i < 2; i++ {
		if !sink.SendFrame(frame) {
			t.Fatalf("frame %d refused while the queue had room", i)
		}
	}
	if sink.SendFrame(frame) {
		t.Error("SendFrame accepted a frame with the queue full")
	}

	for i := 0; i < 2; i++ {
		if !sink.SendControl(Control{JSON: "m"}) {
			t.Fatalf("control %d refused while the queue had room", i)
		}
	}
	if sink.SendControl(Control{JSON: "m"}) {
		t.Error("SendControl accepted a message with the queue full")
	}
}

func TestChannelSinkQueuesTheWireReadyBytes(t *testing.T) {
	sink := NewChannelSink()
	if !sink.SendFrame(Frame{Client: []byte("client"), Relayed: []byte("relayed")}) {
		t.Fatal("SendFrame refused")
	}
	// A WebSocket sink wants the prefixed form, not the author's raw frame.
	if got := string(<-sink.Audio()); got != "relayed" {
		t.Errorf("queued %q, want the relayed bytes", got)
	}
}

// A zero-capacity channel would make every send a rendezvous with the reader,
// which is precisely the blocking a Sink must never do.
func TestChannelSinkDepthIsAtLeastOne(t *testing.T) {
	for _, depth := range []int{0, -1} {
		sink := NewChannelSinkWithDepth(depth, depth)
		if !sink.SendFrame(Frame{Relayed: []byte("x")}) {
			t.Errorf("depth %d: SendFrame refused with nothing queued", depth)
		}
		if !sink.SendControl(Control{JSON: "x"}) {
			t.Errorf("depth %d: SendControl refused with nothing queued", depth)
		}
	}
}

func TestChannelSinkDefaultDepths(t *testing.T) {
	sink := NewChannelSink()
	if got := cap(sink.audio); got != AudioQueueDepth {
		t.Errorf("audio capacity = %d, want %d", got, AudioQueueDepth)
	}
	if got := cap(sink.ctrl); got != ControlQueueDepth {
		t.Errorf("control capacity = %d, want %d", got, ControlQueueDepth)
	}
}
