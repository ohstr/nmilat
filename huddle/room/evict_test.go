package room

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/huddle/wire"
)

func testFrame() []byte {
	return wire.EncodeFrame(wire.FrameHeader{Seq: 1, Ts48k: 960, LevelDbov: -20}, []byte("opus"))
}

func recvControlMsg(t *testing.T, peer testPeer) Control {
	t.Helper()
	select {
	case msg := <-peer.sink.Control():
		return msg
	case <-time.After(time.Second):
		t.Fatal("expected a control message, got none")
		return Control{}
	}
}

func expectNoFrame(t *testing.T, peer testPeer) {
	t.Helper()
	select {
	case frame := <-peer.sink.Audio():
		t.Fatalf("expected no frame, got %d bytes", len(frame))
	case <-time.After(50 * time.Millisecond):
	}
}

func TestEvictPubkeyRemovesThePeerAndTellsIt(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)
	bob := addPeer(t, r, "bob", v3)
	before := r.Roster().Revision

	if n := r.EvictPubkey("alice", `{"type":"error","code":"join_rejected"}`); n != 1 {
		t.Fatalf("EvictPubkey = %d, want 1", n)
	}

	if msg := recvControlMsg(t, alice); msg.JSON == "" || msg.Close {
		t.Fatalf("first control message = %+v, want the error JSON", msg)
	}
	if msg := recvControlMsg(t, alice); !msg.Close {
		t.Fatalf("second control message = %+v, want Close", msg)
	}

	if r.Len() != 1 {
		t.Fatalf("room holds %d peers, want 1", r.Len())
	}
	if r.Roster().Revision <= before {
		t.Fatal("eviction should bump the roster revision")
	}
	_ = bob
}

// Revoking one membership ends that membership, not the call.
func TestEvictPubkeyLeavesTheOtherPeers(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)
	bob := addPeer(t, r, "bob", v3)
	carol := addPeer(t, r, "carol", v3)

	r.EvictPubkey("alice", "")

	if r.BroadcastFrame(bob.ID, testFrame()) != 0 {
		t.Fatal("bob's frame should still reach carol")
	}
	if got := recvFrame(t, carol); len(got) == 0 {
		t.Fatal("carol received nothing")
	}
	expectNoFrame(t, alice)
}

// The security guarantee: an evicted peer is neither heard nor hearing, even
// before its socket has gone away.
func TestEvictedPeerIsNoLongerHeard(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)
	bob := addPeer(t, r, "bob", v3)

	r.EvictPubkey("alice", "")

	if dropped := r.BroadcastFrame(alice.ID, testFrame()); dropped != 0 {
		t.Fatalf("dropped = %d, want 0 (an unknown sender is a no-op)", dropped)
	}
	expectNoFrame(t, bob)
}

func TestEvictPubkeyUnknownIsANoOp(t *testing.T) {
	r := New()
	addPeer(t, r, "alice", v3)

	if n := r.EvictPubkey("nobody", "gone"); n != 0 {
		t.Fatalf("EvictPubkey = %d, want 0", n)
	}
	if r.Len() != 1 {
		t.Fatalf("room holds %d peers, want 1", r.Len())
	}
}

// One pubkey may hold more than one peer -- two devices in the same call.
// Revoking it has to take all of them.
func TestEvictPubkeyRemovesEveryPeerForThatPubkey(t *testing.T) {
	r := New()
	addPeer(t, r, "alice", v3)
	addPeer(t, r, "alice", v3)
	addPeer(t, r, "bob", v3)

	if n := r.EvictPubkey("alice", ""); n != 2 {
		t.Fatalf("EvictPubkey = %d, want 2", n)
	}
	if r.Len() != 1 {
		t.Fatalf("room holds %d peers, want 1", r.Len())
	}
}

func TestEvictPubkeyEmptyMessageOnlyCloses(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)

	r.EvictPubkey("alice", "")

	if msg := recvControlMsg(t, alice); !msg.Close {
		t.Fatalf("control message = %+v, want Close only", msg)
	}
}

func TestManagerEvictPubkeyAcrossRooms(t *testing.T) {
	m := NewManager(0)
	if _, _, _, err := m.Join("room-a", "alice", v3, NewChannelSink()); err != nil {
		t.Fatalf("Join room-a: %v", err)
	}
	if _, _, _, err := m.Join("room-b", "alice", v3, NewChannelSink()); err != nil {
		t.Fatalf("Join room-b: %v", err)
	}
	if _, _, _, err := m.Join("room-b", "bob", v3, NewChannelSink()); err != nil {
		t.Fatalf("Join room-b as bob: %v", err)
	}

	if n := m.EvictPubkey("alice", "revoked"); n != 2 {
		t.Fatalf("EvictPubkey = %d, want 2", n)
	}

	// room-a held only alice, so it is gone; room-b still has bob.
	if _, ok := m.Get("room-a"); ok {
		t.Fatal("room-a should be dropped once empty")
	}
	roomB, ok := m.Get("room-b")
	if !ok {
		t.Fatal("room-b should survive")
	}
	if roomB.Len() != 1 {
		t.Fatalf("room-b holds %d peers, want 1", roomB.Len())
	}
}

func TestManagerEvictPubkeyUnknownIsANoOp(t *testing.T) {
	m := NewManager(0)
	if _, _, _, err := m.Join("room-a", "alice", v3, NewChannelSink()); err != nil {
		t.Fatalf("Join: %v", err)
	}

	if n := m.EvictPubkey("nobody", ""); n != 0 {
		t.Fatalf("EvictPubkey = %d, want 0", n)
	}
	if m.Len() != 1 {
		t.Fatalf("manager holds %d rooms, want 1", m.Len())
	}
}
