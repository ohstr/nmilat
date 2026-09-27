package room

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/huddle/wire"
)

const v2 = 2
const v3 = 3

func addPeer(t *testing.T, r *Room, pubkey string, version uint8) *Peer {
	t.Helper()
	peer, _, err := r.AddPeer(pubkey, version)
	if err != nil {
		t.Fatalf("AddPeer(%q): %v", pubkey, err)
	}
	return peer
}

// recvFrame reads one frame, failing if none arrives. The timeout is generous:
// these are in-process channel sends, so anything approaching it means a real
// hang rather than a slow machine.
func recvFrame(t *testing.T, peer *Peer) []byte {
	t.Helper()
	select {
	case frame := <-peer.Audio():
		return frame
	case <-time.After(5 * time.Second):
		t.Fatalf("peer %d received no frame", peer.Index)
		return nil
	}
}

func assertNoFrame(t *testing.T, peer *Peer) {
	t.Helper()
	select {
	case frame := <-peer.Audio():
		t.Fatalf("peer %d unexpectedly received %x", peer.Index, frame)
	default:
	}
}

/////////////////////////////////////////////////////////////////////
// Admission
/////////////////////////////////////////////////////////////////////

func TestAddPeerAssignsDistinctIndices(t *testing.T) {
	r := New()
	seen := map[uint8]bool{}
	for i := 0; i < MaxPeers; i++ {
		peer := addPeer(t, r, fmt.Sprintf("peer-%d", i), v3)
		if seen[peer.Index] {
			t.Fatalf("index %d handed out twice", peer.Index)
		}
		seen[peer.Index] = true
	}
	if r.Len() != MaxPeers {
		t.Errorf("Len() = %d, want %d", r.Len(), MaxPeers)
	}
}

func TestAddPeerRejectsBeyondCapacity(t *testing.T) {
	r := New()
	for i := 0; i < MaxPeers; i++ {
		addPeer(t, r, fmt.Sprintf("peer-%d", i), v3)
	}

	_, _, err := r.AddPeer("one-too-many", v3)
	if !errors.Is(err, ErrRoomFull) {
		t.Fatalf("err = %v, want ErrRoomFull", err)
	}
	// The existing occupants are untouched by the refusal.
	if r.Len() != MaxPeers {
		t.Errorf("Len() = %d, want the room unchanged at %d", r.Len(), MaxPeers)
	}
}

func TestAddPeerPinsProtocolVersion(t *testing.T) {
	r := New()
	if got := r.ProtocolVersion(); got != 0 {
		t.Errorf("an empty room should be unpinned, got version %d", got)
	}

	addPeer(t, r, "first", v2)
	if got := r.ProtocolVersion(); got != v2 {
		t.Fatalf("ProtocolVersion() = %d, want %d", got, v2)
	}

	if _, _, err := r.AddPeer("mismatched", v3); !errors.Is(err, ErrUpgradeRequired) {
		t.Fatalf("err = %v, want ErrUpgradeRequired", err)
	}
	// A matching peer still joins.
	addPeer(t, r, "second", v2)
	if r.Len() != 2 {
		t.Errorf("Len() = %d, want 2", r.Len())
	}
}

func TestAddPeerRejectsUnsupportedVersion(t *testing.T) {
	r := New()
	for _, v := range []uint8{0, wire.CurrentProtocolVersion + 1, 255} {
		if _, _, err := r.AddPeer("peer", v); !errors.Is(err, ErrBadVersion) {
			t.Errorf("AddPeer(version %d) err = %v, want ErrBadVersion", v, err)
		}
	}
}

func TestAddPeerRosterIncludesTheJoiner(t *testing.T) {
	r := New()
	addPeer(t, r, "alice", v3)

	peer, roster, err := r.AddPeer("bob", v3)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if len(roster.Peers) != 2 {
		t.Fatalf("roster has %d peers, want 2 including the joiner", len(roster.Peers))
	}
	var found bool
	for _, info := range roster.Peers {
		if info.Pubkey == "bob" && info.Index == peer.Index && info.Epoch == peer.Epoch {
			found = true
		}
	}
	if !found {
		t.Errorf("roster %+v does not contain the joiner's own entry", roster.Peers)
	}
}

/////////////////////////////////////////////////////////////////////
// Index rotation and epochs
/////////////////////////////////////////////////////////////////////

// Indices sweep forward through the whole space rather than recycling the
// lowest free one, so a departed peer's index is not immediately reissued.
func TestIndicesRotateRatherThanRecycleTheLowest(t *testing.T) {
	r := New()
	first := addPeer(t, r, "first", v3)
	second := addPeer(t, r, "second", v3)

	r.RemovePeer(first.ID)

	third := addPeer(t, r, "third", v3)
	if third.Index == first.Index {
		t.Errorf("index %d was reissued immediately after being freed", third.Index)
	}
	if third.Index == second.Index {
		t.Fatalf("index %d collides with a live peer", third.Index)
	}
}

// Once the space wraps, an index is reused -- and then the epoch is what
// distinguishes the new holder from the old.
func TestEpochIncrementsWhenAnIndexIsReused(t *testing.T) {
	r := New()

	// Cycle one peer at a time so allocation sweeps the whole index space and
	// comes back around to the start.
	var firstIndex, firstEpoch uint8
	for i := 0; i < IndexSpace; i++ {
		peer := addPeer(t, r, fmt.Sprintf("peer-%d", i), v3)
		if i == 0 {
			firstIndex, firstEpoch = peer.Index, peer.Epoch
		}
		r.RemovePeer(peer.ID)
	}

	wrapped := addPeer(t, r, "wrapped", v3)
	if wrapped.Index != firstIndex {
		t.Fatalf("after %d allocations the index should have wrapped to %d, got %d", IndexSpace, firstIndex, wrapped.Index)
	}
	if wrapped.Epoch == firstEpoch {
		t.Errorf("epoch is still %d after the index was reused; a departed peer's frames are indistinguishable", wrapped.Epoch)
	}
	if wrapped.Epoch != firstEpoch+1 {
		t.Errorf("epoch = %d, want %d", wrapped.Epoch, firstEpoch+1)
	}
}

// Epochs start at 1, leaving 0 free to mean "no epoch known".
func TestFirstEpochIsOne(t *testing.T) {
	r := New()
	if got := addPeer(t, r, "first", v3).Epoch; got != 1 {
		t.Errorf("first epoch = %d, want 1", got)
	}
}

/////////////////////////////////////////////////////////////////////
// Fan-out
/////////////////////////////////////////////////////////////////////

func TestBroadcastFrameReachesEveryoneElse(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)
	bob := addPeer(t, r, "bob", v3)
	carol := addPeer(t, r, "carol", v3)

	frame := wire.EncodeFrame(wire.FrameHeader{Seq: 1, Ts48k: 960, LevelDbov: -20}, []byte("opus"))
	if dropped := r.BroadcastFrame(alice.ID, frame); dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}

	for _, listener := range []*Peer{bob, carol} {
		got := recvFrame(t, listener)
		index, epoch, payload, ok := wire.ParseRelayFrame(v3, got)
		if !ok {
			t.Fatalf("listener %d got an unparseable frame %x", listener.Index, got)
		}
		if index != alice.Index || epoch != alice.Epoch {
			t.Errorf("attribution = %d/%d, want alice at %d/%d", index, epoch, alice.Index, alice.Epoch)
		}
		if string(payload) != string(frame) {
			t.Errorf("payload = %x, want the author's frame verbatim %x", payload, frame)
		}
	}

	// The speaker must never hear itself.
	assertNoFrame(t, alice)
}

func TestBroadcastFramePrefixMatchesTheRoomVersion(t *testing.T) {
	for _, version := range []uint8{1, 2, 3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			r := New()
			alice := addPeer(t, r, "alice", version)
			bob := addPeer(t, r, "bob", version)

			frame := []byte("raw")
			r.BroadcastFrame(alice.ID, frame)

			got := recvFrame(t, bob)
			if len(got) != wire.PrefixLen(version)+len(frame) {
				t.Fatalf("relayed length = %d, want prefix %d plus frame %d", len(got), wire.PrefixLen(version), len(frame))
			}
			_, _, payload, ok := wire.ParseRelayFrame(version, got)
			if !ok || string(payload) != "raw" {
				t.Errorf("payload = %q ok = %v, want the frame verbatim", payload, ok)
			}
		})
	}
}

func TestBroadcastFrameFromAnUnknownPeerIsANoOp(t *testing.T) {
	r := New()
	bob := addPeer(t, r, "bob", v3)

	if dropped := r.BroadcastFrame(PeerID(9999), []byte("x")); dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	assertNoFrame(t, bob)
}

func TestBroadcastFrameToASoleOccupantGoesNowhere(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)
	if dropped := r.BroadcastFrame(alice.ID, []byte("x")); dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	assertNoFrame(t, alice)
}

// The defining real-time property: a listener that stops draining loses frames,
// and the speaker is never blocked by it.
func TestFullAudioQueueDropsAndNeverBlocks(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)
	bob := addPeer(t, r, "bob", v3)

	frame := wire.EncodeFrame(wire.FrameHeader{}, []byte("opus"))

	// Fill bob's queue exactly.
	for i := 0; i < AudioQueueDepth; i++ {
		if dropped := r.BroadcastFrame(alice.ID, frame); dropped != 0 {
			t.Fatalf("frame %d dropped while the queue still had room", i)
		}
	}

	// Every further frame is dropped, and each call still returns promptly.
	done := make(chan int, 1)
	go func() {
		total := 0
		for i := 0; i < 50; i++ {
			total += r.BroadcastFrame(alice.ID, frame)
		}
		done <- total
	}()

	select {
	case dropped := <-done:
		if dropped != 50 {
			t.Errorf("dropped = %d, want all 50 once the queue is full", dropped)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BroadcastFrame blocked on a full queue; a slow listener must never stall the speaker")
	}

	if got := bob.Dropped(); got != 50 {
		t.Errorf("bob.Dropped() = %d, want 50", got)
	}
	if got := len(bob.Audio()); got != AudioQueueDepth {
		t.Errorf("queue depth = %d, want it capped at %d", got, AudioQueueDepth)
	}
}

/////////////////////////////////////////////////////////////////////
// Control plane
/////////////////////////////////////////////////////////////////////

func TestBroadcastControlSkipsTheNamedPeer(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)
	bob := addPeer(t, r, "bob", v3)

	if dropped := r.BroadcastControl(`{"type":"joined"}`, alice.ID); dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}

	select {
	case msg := <-bob.Control():
		if msg.JSON != `{"type":"joined"}` {
			t.Errorf("bob got %q", msg.JSON)
		}
	default:
		t.Error("bob received no control message")
	}
	select {
	case msg := <-alice.Control():
		t.Errorf("the skipped peer received %q", msg.JSON)
	default:
	}
}

func TestBroadcastControlReportsAFullQueue(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)
	addPeer(t, r, "bob", v3)

	for i := 0; i < ControlQueueDepth; i++ {
		if dropped := r.BroadcastControl("msg", alice.ID); dropped != 0 {
			t.Fatalf("message %d dropped early", i)
		}
	}
	// Control loss is not acceptable degradation, so it must be reported rather
	// than swallowed: the caller is expected to disconnect that peer.
	if dropped := r.BroadcastControl("overflow", alice.ID); dropped != 1 {
		t.Errorf("dropped = %d, want 1 so the caller can act on it", dropped)
	}
}

func TestSendControl(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)

	if !r.SendControl(alice.ID, "hello") {
		t.Fatal("SendControl returned false for a live peer")
	}
	if r.SendControl(PeerID(9999), "hello") {
		t.Error("SendControl returned true for an unknown peer")
	}
}

/////////////////////////////////////////////////////////////////////
// Removal, roster revisions, and End
/////////////////////////////////////////////////////////////////////

func TestRemovePeer(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)

	removed, ok := r.RemovePeer(alice.ID)
	if !ok || removed.ID != alice.ID {
		t.Fatalf("RemovePeer = %v, %v", removed, ok)
	}
	if _, ok := r.RemovePeer(alice.ID); ok {
		t.Error("removing a peer twice reported success")
	}
	if r.Len() != 0 {
		t.Errorf("Len() = %d, want 0", r.Len())
	}
}

func TestRosterRevisionIncreasesMonotonically(t *testing.T) {
	r := New()
	var last uint64

	step := func(what string) {
		roster := r.Roster()
		if roster.Revision <= last {
			t.Fatalf("after %s revision = %d, want greater than %d", what, roster.Revision, last)
		}
		last = roster.Revision
	}

	alice := addPeer(t, r, "alice", v3)
	step("first join")
	bob := addPeer(t, r, "bob", v3)
	step("second join")
	r.RemovePeer(alice.ID)
	step("a leave")
	r.RemovePeer(bob.ID)
	step("the last leave")
	r.End()
	step("End")
}

func TestEnd(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", v3)

	r.End()

	if !r.Ended() {
		t.Error("Ended() = false after End()")
	}
	if r.Len() != 0 {
		t.Errorf("Len() = %d, want the registry cleared", r.Len())
	}
	select {
	case msg := <-alice.Control():
		if !msg.Close {
			t.Errorf("peer got %+v, want a Close", msg)
		}
	default:
		t.Error("End() did not ask the peer's writer to close")
	}
	if _, _, err := r.AddPeer("late", v3); !errors.Is(err, ErrRoomEnded) {
		t.Errorf("err = %v, want ErrRoomEnded", err)
	}
	// Idempotent.
	r.End()
}

/////////////////////////////////////////////////////////////////////
// Concurrency
/////////////////////////////////////////////////////////////////////

// Run under -race: joins, leaves, broadcasts and roster reads all contend for
// the same registry, and an index handed to two live peers at once would
// silently misattribute audio.
func TestConcurrentJoinLeaveAndBroadcast(t *testing.T) {
	r := New()
	resident := addPeer(t, r, "resident", v3)

	// Keep the resident drained so it is never the bottleneck.
	stop := make(chan struct{})
	var drain sync.WaitGroup
	drain.Add(1)
	go func() {
		defer drain.Done()
		for {
			select {
			case <-resident.Audio():
			case <-stop:
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				peer, _, err := r.AddPeer(fmt.Sprintf("w%d-%d", worker, j), v3)
				if err != nil {
					// ErrRoomFull is legitimate under contention.
					continue
				}
				r.BroadcastFrame(peer.ID, []byte("x"))
				r.Roster()
				r.RemovePeer(peer.ID)
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	drain.Wait()

	if r.Len() != 1 {
		t.Errorf("Len() = %d, want only the resident left", r.Len())
	}
	// Every transient peer was removed, so every index but the resident's is
	// free again.
	roster := r.Roster()
	if len(roster.Peers) != 1 || roster.Peers[0].Pubkey != "resident" {
		t.Errorf("roster = %+v, want just the resident", roster.Peers)
	}
}

func TestRosterSnapshotIsACopy(t *testing.T) {
	r := New()
	addPeer(t, r, "alice", v3)

	roster := r.Roster()
	roster.Peers[0].Pubkey = "tampered"

	if again := r.Roster(); again.Peers[0].Pubkey != "alice" {
		t.Error("mutating a returned roster changed the room's state")
	}
}
