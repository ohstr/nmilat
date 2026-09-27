package room

import "github.com/ohstr/nmilat/huddle/wire"

// Frame is one peer's audio as delivered to a Sink.
//
// It carries both shapes deliberately. A WebSocket peer wants Relayed -- the
// bytes to put on the wire, already prefixed -- while a sink that repacketizes
// into some other transport wants Author plus the opaque payload inside Client
// and has no use for the prefix at all. Building Relayed once per broadcast and
// sharing it costs one allocation for the whole room rather than one per
// recipient, which is why the room builds it rather than each sink.
//
// Client and Relayed alias buffers owned by the broadcast. A sink that keeps
// either past the SendFrame call must copy.
type Frame struct {
	// Author identifies who spoke, including the routing identity a receiver
	// uses to attribute the audio.
	Author PeerInfo

	// Version is the room's pinned protocol version. It tells a sink whether
	// Client carries a wire.FrameHeader -- see wire.HasHeader -- so a sink that
	// needs the header does not have to guess.
	Version uint8

	// Client is the author's frame exactly as it arrived: for protocol v2 and
	// up, an 8-byte header followed by the Opus payload.
	Client []byte

	// Relayed is Client with the routing prefix prepended.
	Relayed []byte
}

// Payload returns the opaque Opus bytes, and the parsed header when the room's
// protocol version carries one. It is a convenience for sinks that repacketize;
// a sink forwarding Relayed never needs to call it, which is the point of not
// parsing on the broadcast path.
func (f Frame) Payload() (header wire.FrameHeader, payload []byte, hasHeader bool) {
	if !wire.HasHeader(f.Version) {
		return wire.FrameHeader{}, f.Client, false
	}
	header, payload, ok := wire.ParseFrame(f.Client)
	if !ok {
		return wire.FrameHeader{}, nil, false
	}
	return header, payload, true
}

// Sink is where a room delivers one peer's audio and control messages. It is
// the seam that keeps Room transport-agnostic: a WebSocket peer and a peer
// bridged onto some other transport differ only in their Sink.
//
// # Both methods must return promptly and must never block
//
// They are called while the room holds its lock, with every other peer waiting
// behind them, so a sink that blocks stalls the whole room rather than just
// itself. A sink whose destination can block -- a socket write, an RTP track --
// owns a bounded queue and a goroutine of its own, and its Send methods only
// hand over to that queue.
//
// Returning false means the message was dropped. For audio that is expected and
// fine: audio tolerates loss and not delay, so a peer falling behind loses
// frames rather than holding up whoever is talking. For control it is not fine
// -- control messages carry the routing-identity mapping a receiver needs, so
// losing one misattributes every later frame -- and the room reports it to the
// caller rather than swallowing it.
type Sink interface {
	// SendFrame delivers one relayed frame, reporting whether it was accepted.
	SendFrame(Frame) bool
	// SendControl delivers one control message, reporting whether it was
	// accepted.
	SendControl(Control) bool
}

// ChannelSink is the default Sink: two bounded queues for a writer goroutine to
// drain, which is what a WebSocket peer wants. Its Send methods never block --
// a full queue drops instead.
type ChannelSink struct {
	audio chan []byte
	ctrl  chan Control
}

// NewChannelSink returns a ChannelSink with the package's default queue depths.
func NewChannelSink() *ChannelSink {
	return NewChannelSinkWithDepth(AudioQueueDepth, ControlQueueDepth)
}

// NewChannelSinkWithDepth returns a ChannelSink with explicit queue depths, for
// callers with a reason to deviate. Depths below one are raised to one: a
// zero-capacity channel would make every send a rendezvous with the reader,
// which is exactly the blocking a Sink must not do.
func NewChannelSinkWithDepth(audioDepth, controlDepth int) *ChannelSink {
	if audioDepth < 1 {
		audioDepth = 1
	}
	if controlDepth < 1 {
		controlDepth = 1
	}
	return &ChannelSink{
		audio: make(chan []byte, audioDepth),
		ctrl:  make(chan Control, controlDepth),
	}
}

// Audio is the queue of relayed frames to write to this peer, already carrying
// their routing prefix.
func (s *ChannelSink) Audio() <-chan []byte { return s.audio }

// Control is the queue of control messages to write to this peer.
func (s *ChannelSink) Control() <-chan Control { return s.ctrl }

// SendFrame queues the wire-ready bytes, dropping when the queue is full.
func (s *ChannelSink) SendFrame(f Frame) bool {
	select {
	case s.audio <- f.Relayed:
		return true
	default:
		return false
	}
}

// SendControl queues a control message, dropping when the queue is full.
func (s *ChannelSink) SendControl(c Control) bool {
	select {
	case s.ctrl <- c:
		return true
	default:
		return false
	}
}
