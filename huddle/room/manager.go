package room

import (
	"errors"
	"sync"
)

// DefaultMaxRooms caps how many rooms one process will host at once. Rooms are
// cheap while empty, but each occupied one costs goroutines and per-peer
// buffers, so an unbounded count is a way for anyone who can reach the endpoint
// to exhaust memory.
const DefaultMaxRooms = 256

// ErrTooManyRooms is returned when a join would create a room beyond the
// configured cap.
var ErrTooManyRooms = errors.New("room: too many concurrent rooms")

// Manager holds the live rooms, keyed by room id. Rooms are created on the
// first join and removed once the last peer leaves, so an idle process holds
// none. It is safe for concurrent use.
//
// # Lock ordering
//
// Manager takes its own mutex and then, while holding it, may take a Room's.
// Nothing ever acquires them the other way round, which is what keeps the pair
// deadlock-free. Every Manager method that touches a Room does so under this
// order; callers holding a Room lock must not call back into Manager.
type Manager struct {
	mu       sync.Mutex
	rooms    map[string]*Room
	maxRooms int
}

// NewManager returns an empty Manager. A maxRooms of zero or less means
// DefaultMaxRooms.
func NewManager(maxRooms int) *Manager {
	if maxRooms <= 0 {
		maxRooms = DefaultMaxRooms
	}
	return &Manager{rooms: make(map[string]*Room), maxRooms: maxRooms}
}

// Join admits a peer to the room with this id, creating the room if it does not
// exist yet, and returns the room, the peer, and the roster as of the join.
// sink is where that peer's audio and control are delivered; see Room.AddPeer.
//
// A join that fails against a room this call had to create removes that room
// again rather than leaving an empty one behind. Without that, a client
// repeatedly failing admission -- wrong protocol version, say -- would leave a
// room per attempt until the cap was hit.
func (m *Manager) Join(id, pubkey string, protocolVersion uint8, sink Sink) (*Room, *Peer, Roster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, existed := m.rooms[id]
	if !existed {
		if len(m.rooms) >= m.maxRooms {
			return nil, nil, Roster{}, ErrTooManyRooms
		}
		r = New()
		m.rooms[id] = r
	}

	peer, roster, err := r.AddPeer(pubkey, protocolVersion, sink)
	if err != nil {
		if !existed {
			delete(m.rooms, id)
		}
		return nil, nil, Roster{}, err
	}
	return r, peer, roster, nil
}

// Leave removes a peer from the room with this id and drops the room once it is
// empty, reporting whether the peer was present.
func (m *Manager) Leave(id string, peer PeerID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.rooms[id]
	if !ok {
		return false
	}
	_, removed := r.RemovePeer(peer)
	if r.Len() == 0 {
		delete(m.rooms, id)
	}
	return removed
}

// Get returns the room with this id if it is live.
func (m *Manager) Get(id string) (*Room, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rooms[id]
	return r, ok
}

// End ends the room with this id and removes it, reporting whether it existed.
// Peers still connected are asked to close.
func (m *Manager) End(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.rooms[id]
	if !ok {
		return false
	}
	r.End()
	delete(m.rooms, id)
	return true
}

// Len is the number of live rooms.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rooms)
}

// Occupancy returns the peer count per live room, for diagnostics and metrics.
func (m *Manager) Occupancy() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make(map[string]int, len(m.rooms))
	for id, r := range m.rooms {
		out[id] = r.Len()
	}
	return out
}
