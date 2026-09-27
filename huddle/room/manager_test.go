package room

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestManagerCreatesAndReusesRooms(t *testing.T) {
	m := NewManager(0)

	r1, alice, roster, err := m.Join("room-1", "alice", v3)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if m.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", m.Len())
	}
	if len(roster.Peers) != 1 {
		t.Errorf("roster = %+v, want just the joiner", roster.Peers)
	}

	r2, bob, _, err := m.Join("room-1", "bob", v3)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if r1 != r2 {
		t.Error("the second join created a new room instead of reusing the first")
	}
	if m.Len() != 1 {
		t.Errorf("Len() = %d, want still 1", m.Len())
	}
	if alice.Index == bob.Index {
		t.Error("two peers in one room share a routing index")
	}
}

func TestManagerDropsTheRoomWhenTheLastPeerLeaves(t *testing.T) {
	m := NewManager(0)
	_, alice, _, _ := m.Join("room-1", "alice", v3)
	_, bob, _, _ := m.Join("room-1", "bob", v3)

	if !m.Leave("room-1", alice.ID) {
		t.Fatal("Leave reported the peer absent")
	}
	if m.Len() != 1 {
		t.Errorf("Len() = %d, want the room kept while bob remains", m.Len())
	}

	m.Leave("room-1", bob.ID)
	if m.Len() != 0 {
		t.Errorf("Len() = %d, want the empty room dropped", m.Len())
	}
	if _, ok := m.Get("room-1"); ok {
		t.Error("Get returned a room that should have been dropped")
	}
}

func TestManagerLeaveOnUnknownRoomOrPeer(t *testing.T) {
	m := NewManager(0)
	if m.Leave("nope", PeerID(1)) {
		t.Error("Leave on an unknown room returned true")
	}
	_, alice, _, _ := m.Join("room-1", "alice", v3)
	if m.Leave("room-1", PeerID(9999)) {
		t.Error("Leave on an unknown peer returned true")
	}
	// The real peer is still there.
	if m.Len() != 1 {
		t.Errorf("Len() = %d, want 1", m.Len())
	}
	m.Leave("room-1", alice.ID)
}

func TestManagerRespectsTheRoomCap(t *testing.T) {
	m := NewManager(2)
	if _, _, _, err := m.Join("a", "alice", v3); err != nil {
		t.Fatalf("Join a: %v", err)
	}
	if _, _, _, err := m.Join("b", "alice", v3); err != nil {
		t.Fatalf("Join b: %v", err)
	}
	if _, _, _, err := m.Join("c", "alice", v3); !errors.Is(err, ErrTooManyRooms) {
		t.Fatalf("err = %v, want ErrTooManyRooms", err)
	}
	// Joining an existing room is never blocked by the cap.
	if _, _, _, err := m.Join("a", "bob", v3); err != nil {
		t.Errorf("joining an existing room hit the cap: %v", err)
	}
}

// A join that fails against a room this call created must not leave that room
// behind, or a client failing admission repeatedly would exhaust the cap.
func TestManagerDoesNotLeakARoomOnAFailedFirstJoin(t *testing.T) {
	m := NewManager(0)

	if _, _, _, err := m.Join("room-1", "alice", 99); err == nil {
		t.Fatal("expected an unsupported-version error")
	}
	if m.Len() != 0 {
		t.Fatalf("Len() = %d, want no room left behind by the failed join", m.Len())
	}

	// A pre-existing room survives a failed join against it.
	m.Join("room-2", "alice", v2)
	if _, _, _, err := m.Join("room-2", "bob", v3); !errors.Is(err, ErrUpgradeRequired) {
		t.Fatalf("err = %v, want ErrUpgradeRequired", err)
	}
	if m.Len() != 1 {
		t.Errorf("Len() = %d, want the existing room kept", m.Len())
	}
}

func TestManagerEnd(t *testing.T) {
	m := NewManager(0)
	_, alice, _, _ := m.Join("room-1", "alice", v3)

	if !m.End("room-1") {
		t.Fatal("End reported the room absent")
	}
	if m.Len() != 0 {
		t.Errorf("Len() = %d, want the room removed", m.Len())
	}
	select {
	case msg := <-alice.Control():
		if !msg.Close {
			t.Errorf("peer got %+v, want a Close", msg)
		}
	default:
		t.Error("End did not ask the peer to close")
	}
	if m.End("room-1") {
		t.Error("End on an already-ended room returned true")
	}
}

func TestManagerOccupancy(t *testing.T) {
	m := NewManager(0)
	m.Join("a", "alice", v3)
	m.Join("a", "bob", v3)
	m.Join("b", "carol", v3)

	got := m.Occupancy()
	if got["a"] != 2 || got["b"] != 1 || len(got) != 2 {
		t.Errorf("Occupancy() = %v, want a:2 b:1", got)
	}

	// The returned map is a copy.
	got["a"] = 99
	if again := m.Occupancy(); again["a"] != 2 {
		t.Error("mutating the returned map changed the manager's state")
	}
}

// Run under -race: joins and leaves across several rooms contend for the
// manager and for each room, and the create/drop edges are where a lost wakeup
// or a leaked empty room would show up.
func TestManagerConcurrentJoinAndLeave(t *testing.T) {
	m := NewManager(0)

	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				id := fmt.Sprintf("room-%d", i%4)
				_, peer, _, err := m.Join(id, fmt.Sprintf("w%d-%d", worker, i), v3)
				if err != nil {
					continue
				}
				m.Leave(id, peer.ID)
			}
		}(worker)
	}
	wg.Wait()

	if m.Len() != 0 {
		t.Errorf("Len() = %d, want every room dropped once emptied: %v", m.Len(), m.Occupancy())
	}
}
