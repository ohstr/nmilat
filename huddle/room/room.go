// Package room implements a huddle audio room: the peer registry, the routing
// identities it hands out, and the fan-out that carries one peer's frames to
// everyone else. It is transport-agnostic -- peers are channels, not sockets --
// so the same room serves a WebSocket peer and any other sink. It has no
// dependency on relay/.
//
// # Fan-out shape
//
//	peer A ──frame──> Room.BroadcastFrame ──> peer B, peer C, ...
//	                                          (routing prefix prepended)
//
// A sender never receives its own frame.
//
// # Real-time, not reliable
//
// Audio tolerates loss and cannot tolerate delay, so a peer's audio queue is
// small and **drops when full rather than blocking**. One slow consumer must
// never stall the peer that is talking. Control messages are the opposite:
// they carry roster state a client needs to interpret later frames, so they get
// their own larger queue and are never dropped silently.
package room

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/ohstr/nmilat/huddle/wire"
)

// Queue capacities, per peer.
const (
	// AudioQueueDepth is 8 frames, which at 20 ms per frame is 160 ms of
	// buffered audio. Deeper would trade latency for loss in the wrong
	// direction: a listener 400 ms behind is worse off than one that dropped a
	// frame.
	AudioQueueDepth = 8
	// ControlQueueDepth is sized so a burst of joins and leaves cannot push out
	// a message. Control messages are state-bearing -- a client maps peer
	// indices to pubkeys from them -- so dropping one corrupts attribution for
	// every later frame.
	ControlQueueDepth = 32
)

// MaxPeers caps occupancy. Fan-out is quadratic: N peers produce N*(N-1) frame
// copies every 20 ms, so 25 peers is 600 copies per tick, which is affordable.
// This is defence in depth, not the only admission control.
const MaxPeers = 25

// IndexSpace is the number of distinct routing identities. A peer index is one
// byte and 255 is reserved, leaving 0..=254. Indices rotate through this whole
// space rather than reusing the lowest free one, so a departed peer's index is
// not immediately handed to someone else.
const IndexSpace = 255

// Failure modes, for callers that need to distinguish them (e.g. via
// errors.Is) rather than match on message text. Each maps to a wire-level
// error code a client acts on.
var (
	ErrRoomFull        = errors.New("room: participant capacity reached")
	ErrRoomEnded       = errors.New("room: huddle has ended")
	ErrUpgradeRequired = errors.New("room: protocol version does not match the room")
	ErrBadVersion      = errors.New("room: unsupported protocol version")
)

// PeerID identifies one occupancy of a room. It is distinct from a peer's
// routing index: the index is a byte that gets reused and is visible on the
// wire, whereas a PeerID is never reused and never leaves the process. Keeping
// them separate is what makes "did this frame come from the peer I think it
// did" answerable.
type PeerID uint64

// Control is a message for one peer's control channel.
type Control struct {
	// JSON is the control message to deliver. Empty when Close is set.
	JSON string
	// Close asks the peer's writer to shut down gracefully.
	Close bool
}

// Peer is one connected participant.
type Peer struct {
	ID     PeerID
	Pubkey string
	// Index is the routing identity prefixed onto this peer's relayed frames,
	// in 0..=254.
	Index uint8
	// Epoch counts how many times Index has been assigned. It is prefixed
	// alongside Index from protocol v3 so a late frame from a previous holder
	// of the index is distinguishable.
	Epoch uint8

	audio   chan []byte
	ctrl    chan Control
	dropped atomic.Uint64
}

// Audio is the peer's outbound audio queue: relayed frames, already carrying
// their routing prefix.
func (p *Peer) Audio() <-chan []byte { return p.audio }

// Control is the peer's outbound control queue.
func (p *Peer) Control() <-chan Control { return p.ctrl }

// Dropped is how many frames were discarded because this peer's audio queue
// was full. Non-zero means this peer is not keeping up; it is a diagnostic,
// not an error.
func (p *Peer) Dropped() uint64 { return p.dropped.Load() }

// PeerInfo is one entry in a roster snapshot: what a joining client needs to
// attribute incoming frames.
type PeerInfo struct {
	Pubkey string
	Index  uint8
	Epoch  uint8
}

// Roster is a point-in-time view of a room's occupants. Revision increases on
// every membership change, so a client can tell an older snapshot from a newer
// one and discard the stale one rather than interleaving them.
type Roster struct {
	Revision uint64
	Peers    []PeerInfo
}

// Room is a single audio room. It is safe for concurrent use.
type Room struct {
	mu       sync.Mutex
	peers    map[PeerID]*Peer
	byIndex  map[uint8]PeerID
	epochs   [IndexSpace]uint8
	cursor   uint16
	nextID   PeerID
	revision uint64
	version  uint8
	ended    bool
}

// New returns an empty room with no pinned protocol version. The first peer to
// join pins it.
func New() *Room {
	return &Room{
		peers:   make(map[PeerID]*Peer),
		byIndex: make(map[uint8]PeerID),
		nextID:  1,
	}
}

// ProtocolVersion is the version this room is pinned to, or 0 if it is empty
// and unpinned.
func (r *Room) ProtocolVersion() uint8 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.version
}

// Len is the current occupancy.
func (r *Room) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.peers)
}

// Ended reports whether the room has been ended and will accept no more peers.
func (r *Room) Ended() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ended
}

// AddPeer admits a peer and returns it alongside the roster as of the moment it
// joined -- including itself, so a client sees exactly the room it is in rather
// than having to merge its own entry into a snapshot taken before it arrived.
//
// The first peer pins the room's protocol version. A later peer naming a
// different one gets ErrUpgradeRequired: serving it would mean sending frames
// it would misparse.
func (r *Room) AddPeer(pubkey string, protocolVersion uint8) (*Peer, Roster, error) {
	if !wire.SupportedProtocolVersion(protocolVersion) {
		return nil, Roster{}, ErrBadVersion
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ended {
		return nil, Roster{}, ErrRoomEnded
	}
	if len(r.peers) >= MaxPeers {
		return nil, Roster{}, ErrRoomFull
	}
	if r.version == 0 {
		r.version = protocolVersion
	} else if r.version != protocolVersion {
		return nil, Roster{}, ErrUpgradeRequired
	}

	index, ok := r.allocateIndexLocked()
	if !ok {
		// Unreachable while MaxPeers < IndexSpace, but a silent wrong index
		// would corrupt attribution, so refuse rather than guess.
		return nil, Roster{}, ErrRoomFull
	}
	r.epochs[index]++

	peer := &Peer{
		ID:     r.nextID,
		Pubkey: pubkey,
		Index:  index,
		Epoch:  r.epochs[index],
		audio:  make(chan []byte, AudioQueueDepth),
		ctrl:   make(chan Control, ControlQueueDepth),
	}
	r.nextID++
	r.peers[peer.ID] = peer
	r.byIndex[index] = peer.ID
	r.revision++

	return peer, r.rosterLocked(), nil
}

// allocateIndexLocked hands out the next free routing index, sweeping forward
// from where the last allocation stopped so indices rotate through the whole
// space instead of the lowest few being recycled immediately.
func (r *Room) allocateIndexLocked() (uint8, bool) {
	for i := 0; i < IndexSpace; i++ {
		candidate := uint8((r.cursor + uint16(i)) % IndexSpace)
		if _, taken := r.byIndex[candidate]; !taken {
			r.cursor = (uint16(candidate) + 1) % IndexSpace
			return candidate, true
		}
	}
	return 0, false
}

// RemovePeer removes a peer and reports whether it was present. The peer's
// routing index becomes available again, but its epoch is not reset, so the
// next holder is distinguishable from this one.
func (r *Room) RemovePeer(id PeerID) (*Peer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	peer, ok := r.peers[id]
	if !ok {
		return nil, false
	}
	delete(r.peers, id)
	if holder, ok := r.byIndex[peer.Index]; ok && holder == id {
		delete(r.byIndex, peer.Index)
	}
	r.revision++
	return peer, true
}

// Roster returns a snapshot of the room's occupants.
func (r *Room) Roster() Roster {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rosterLocked()
}

func (r *Room) rosterLocked() Roster {
	peers := make([]PeerInfo, 0, len(r.peers))
	for _, peer := range r.peers {
		peers = append(peers, PeerInfo{Pubkey: peer.Pubkey, Index: peer.Index, Epoch: peer.Epoch})
	}
	return Roster{Revision: r.revision, Peers: peers}
}

// BroadcastFrame fans one peer's frame out to every other peer, prefixed with
// the author's routing identity. It returns how many peers the frame was
// dropped for.
//
// frame is the author's bytes verbatim; this method never inspects or rewrites
// them. The prefixed frame is built once and shared by every recipient, which
// is safe because no recipient mutates it.
//
// Delivery is non-blocking: a recipient whose queue is full loses the frame.
// That is the point -- the alternative is one slow listener stalling the
// speaker, which would degrade the call for everyone rather than just them.
func (r *Room) BroadcastFrame(author PeerID, frame []byte) (dropped int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	sender, ok := r.peers[author]
	if !ok {
		return 0
	}
	out := wire.RelayFrame(r.version, sender.Index, sender.Epoch, frame)

	for id, peer := range r.peers {
		if id == author {
			continue
		}
		select {
		case peer.audio <- out:
		default:
			peer.dropped.Add(1)
			dropped++
		}
	}
	return dropped
}

// BroadcastControl delivers a control message to every peer, optionally
// skipping one (the author of a join, say, which already learned its own state
// from AddPeer). It returns the number of peers whose control queue was full.
//
// A full control queue is a real problem rather than acceptable loss: the
// client's index-to-pubkey map goes stale and every later frame is
// misattributed. The caller should treat a non-zero result as grounds to
// disconnect that peer, not ignore it.
func (r *Room) BroadcastControl(message string, skip PeerID) (dropped int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, peer := range r.peers {
		if id == skip {
			continue
		}
		select {
		case peer.ctrl <- Control{JSON: message}:
		default:
			dropped++
		}
	}
	return dropped
}

// SendControl delivers one control message to one peer, reporting whether it
// was queued.
func (r *Room) SendControl(id PeerID, message string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	peer, ok := r.peers[id]
	if !ok {
		return false
	}
	select {
	case peer.ctrl <- Control{JSON: message}:
		return true
	default:
		return false
	}
}

// End marks the room ended, asks every peer's writer to close, and clears the
// registry. Further AddPeer calls fail with ErrRoomEnded. It is idempotent.
func (r *Room) End() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ended {
		return
	}
	r.ended = true
	for id, peer := range r.peers {
		select {
		case peer.ctrl <- Control{Close: true}:
		default:
		}
		delete(r.peers, id)
		delete(r.byIndex, peer.Index)
	}
	r.revision++
}
