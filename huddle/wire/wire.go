// Package wire implements the huddle audio frame protocol: the per-frame
// header clients author, and the routing prefix a relay prepends when it fans
// a frame out. This package is a pure codec (parse and encode, no I/O); it has
// no dependency on relay/.
//
// Not to be confused with the top-level nmilat/wire, which carries Nostr's
// JSON packet types. Huddle audio deliberately does not share the Nostr
// socket: that one accepts JSON arrays and drops binary frames, while these
// are binary frames alongside JSON object control messages.
//
// # Opaque payloads
//
// The Opus payload is never decoded, re-encoded, or rewritten -- not by this
// package and not by a relay using it. A relay parses the header for
// telemetry and to reject frames that are clearly malformed for the room's
// pinned protocol version, then forwards the client's bytes verbatim. Keeping
// the payload opaque is what lets a relay carry audio without linking a codec.
//
// # Threat-model invariant
//
// LevelDbov is client-authored telemetry. Anything derived from it -- logs,
// active-speaker hints, dominant-talker decisions -- must treat it as
// untrusted. ParseFrame clamps out-of-range values into the canonical
// -127..=0 range but never drops a frame over bad metadata: bad telemetry
// must not become audible loss. Trust decisions (admission, moderation,
// kicks) MUST NOT consume it.
package wire

import "encoding/binary"

// Audio format. Every frame carries exactly one 20 ms Opus packet at 48 kHz
// mono, which is 960 samples.
const (
	SampleRate          = 48000
	Channels            = 1
	FrameDurationMillis = 20
	SamplesPerFrame     = SampleRate * FrameDurationMillis / 1000
)

// Protocol versions. A client names the version it wants when it
// authenticates; a room pins whichever version its first peer asked for, and a
// later peer that does not match is refused rather than fed frames it would
// misparse. Older versions stay supported indefinitely so a rollout can be
// staged.
const (
	MinProtocolVersion = 1
	// CurrentProtocolVersion is the highest version this build understands.
	CurrentProtocolVersion = 3
	// DefaultProtocolVersion is assumed when a client names no version, so
	// clients predating version negotiation keep working.
	DefaultProtocolVersion = 1
)

// HeaderLen is the length of the per-frame header, present from protocol
// version 2 onward. The wire layout is, in network byte order:
//
//	byte 0..=1 : Seq        uint16
//	byte 2..=5 : Ts48k      uint32
//	byte 6     : LevelDbov  int8   range [-127, 0]
//	byte 7     : Flags      uint8  bit 0 = DTX; other bits reserved
const HeaderLen = 8

// FlagDTX marks a DTX/comfort-noise frame. Other bits of Flags are reserved:
// a receiver ignores them, and this package round-trips them untouched rather
// than masking them off, so a future flag survives an intermediate hop.
const FlagDTX uint8 = 0x01

// LevelSilenceFloor is the canonical "no signal" level, and the value an
// out-of-range LevelDbov is clamped to.
const LevelSilenceFloor int8 = -127

// Frame size limits. MaxFrameBytes bounds a client-authored frame -- header
// plus Opus payload -- and is generous for a single 20 ms Opus packet, which
// is typically under a hundred bytes. MaxControlBytes bounds the JSON control
// messages that share the socket.
const (
	MaxFrameBytes   = 4096
	MaxControlBytes = 8192
)

// SupportedProtocolVersion reports whether v is a version this build can
// serve. Version 0 is not a thing: it means a client sent a version field it
// had not thought about.
func SupportedProtocolVersion(v uint8) bool {
	return v >= MinProtocolVersion && v <= CurrentProtocolVersion
}

// HasHeader reports whether frames under protocol version v carry a
// FrameHeader. Version 1 predates it and carries a bare Opus payload.
func HasHeader(v uint8) bool { return v >= 2 }

// FrameHeader is a parsed per-frame header. It is small and copied by value.
type FrameHeader struct {
	// Seq is the sender-authored sequence number. It wraps every 2^16 frames,
	// which at 20 ms per frame is a little over 21 minutes, so a receiver must
	// treat it as wrapping rather than monotonic.
	Seq uint16
	// Ts48k is the sender-authored RTP-style media timestamp in 48 kHz units.
	// It also wraps.
	Ts48k uint32
	// LevelDbov is the audio level in dBov, always in -127..=0 after parsing.
	// Untrusted; diagnostics and UI hints only.
	LevelDbov int8
	// Flags is the raw flags byte. Test it with masks -- reserved bits may be
	// set by a newer peer.
	Flags uint8
}

// IsDTX reports whether FlagDTX is set.
func (h FrameHeader) IsDTX() bool { return h.Flags&FlagDTX != 0 }

// ClampLevel returns level if it is within the canonical -127..=0 range, and
// LevelSilenceFloor otherwise. Note that -128 clamps too: it is below the
// floor, not a louder signal.
func ClampLevel(level int8) int8 {
	if level < LevelSilenceFloor || level > 0 {
		return LevelSilenceFloor
	}
	return level
}

// ParseFrame parses a protocol v2+ frame into its header and the opaque Opus
// payload that follows. The payload aliases b rather than copying it, so a
// caller that retains it past the read buffer's lifetime must copy.
//
// ok is false when b is too short to hold a header, which the caller should
// treat as a malformed frame and drop. An out-of-range LevelDbov is clamped
// and ok stays true -- bad telemetry is not audible loss.
//
// A frame whose payload is empty parses with ok true and an empty payload.
// Whether to forward that is a policy decision, not a parse error: see
// ValidClientFrame.
func ParseFrame(b []byte) (header FrameHeader, payload []byte, ok bool) {
	if len(b) < HeaderLen {
		return FrameHeader{}, nil, false
	}
	return FrameHeader{
		Seq:       binary.BigEndian.Uint16(b[0:2]),
		Ts48k:     binary.BigEndian.Uint32(b[2:6]),
		LevelDbov: ClampLevel(int8(b[6])),
		Flags:     b[7],
	}, b[HeaderLen:], true
}

// ValidClientFrame reports whether b is a frame a relay should accept from a
// client on a room pinned to protocol version v, and returns the reason it is
// not. This is the admission policy the parse half deliberately leaves out:
// a v2+ frame must carry a full header and a non-empty payload, and no frame
// may exceed MaxFrameBytes.
func ValidClientFrame(v uint8, b []byte) (ok bool, reason string) {
	switch {
	case len(b) == 0:
		return false, "empty frame"
	case len(b) > MaxFrameBytes:
		return false, "frame exceeds the maximum size"
	}
	if !HasHeader(v) {
		return true, ""
	}
	if len(b) <= HeaderLen {
		return false, "frame carries a header but no payload"
	}
	if _, payload, parsed := ParseFrame(b); !parsed || len(payload) == 0 {
		return false, "frame header failed to parse"
	}
	return true, ""
}

// AppendFrame encodes header followed by opus onto dst and returns the
// extended slice. This is the client half of the protocol: a relay never
// authors a frame, but an ncli peer sending its own microphone does.
func AppendFrame(dst []byte, header FrameHeader, opus []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, header.Seq)
	dst = binary.BigEndian.AppendUint32(dst, header.Ts48k)
	dst = append(dst, byte(ClampLevel(header.LevelDbov)), header.Flags)
	return append(dst, opus...)
}

// EncodeFrame is AppendFrame against a fresh, exactly-sized buffer.
func EncodeFrame(header FrameHeader, opus []byte) []byte {
	return AppendFrame(make([]byte, 0, HeaderLen+len(opus)), header, opus)
}

// PrefixLen is the number of routing bytes a relay prepends when fanning a
// frame out under protocol version v: one peer index, plus a per-index epoch
// from version 3 onward.
//
// The epoch exists because peer indices are reused. Without it, a frame
// authored by a peer that has since left is indistinguishable from one
// authored by the peer that later took its index.
func PrefixLen(v uint8) int {
	if v >= 3 {
		return 2
	}
	return 1
}

// AppendRelayPrefix prepends the routing prefix for protocol version v onto
// dst and returns the extended slice. epoch is ignored below version 3, which
// has no field for it.
//
// The prefix is routing metadata only. It never touches the client's frame
// bytes, which is why a relay can add it without understanding the payload.
func AppendRelayPrefix(dst []byte, v, peerIndex, epoch uint8) []byte {
	dst = append(dst, peerIndex)
	if v >= 3 {
		dst = append(dst, epoch)
	}
	return dst
}

// RelayFrame builds the bytes a relay sends to one subscriber: the routing
// prefix for version v followed by the author's frame verbatim.
func RelayFrame(v, peerIndex, epoch uint8, frame []byte) []byte {
	out := make([]byte, 0, PrefixLen(v)+len(frame))
	out = AppendRelayPrefix(out, v, peerIndex, epoch)
	return append(out, frame...)
}

// ParseRelayFrame splits a relayed frame under protocol version v back into
// its routing prefix and the author's opaque frame. It is the receiving half
// of AppendRelayPrefix, used by a client.
//
// epoch is zero below version 3, which does not carry one. frame aliases b.
func ParseRelayFrame(v uint8, b []byte) (peerIndex, epoch uint8, frame []byte, ok bool) {
	n := PrefixLen(v)
	if len(b) < n {
		return 0, 0, nil, false
	}
	peerIndex = b[0]
	if v >= 3 {
		epoch = b[1]
	}
	return peerIndex, epoch, b[n:], true
}
