package wire

import (
	"bytes"
	"testing"
)

// Canonical layout: BE uint16 seq, BE uint32 ts, int8 level, uint8 flags. This
// pins the byte order so an accidental endianness flip on either side of the
// protocol is caught immediately.
func TestParseFrameReadsNetworkByteOrder(t *testing.T) {
	b := []byte{
		0x01, 0x02, // seq = 0x0102
		0x03, 0x04, 0x05, 0x06, // ts48k = 0x03040506
		0xFF,             // level = -1
		0x01,             // flags = FlagDTX
		0xAA, 0xBB, 0xCC, // opaque payload
	}

	header, payload, ok := ParseFrame(b)
	if !ok {
		t.Fatal("ParseFrame returned ok = false")
	}
	if header.Seq != 0x0102 {
		t.Errorf("Seq = %#x, want 0x0102", header.Seq)
	}
	if header.Ts48k != 0x03040506 {
		t.Errorf("Ts48k = %#x, want 0x03040506", header.Ts48k)
	}
	if header.LevelDbov != -1 {
		t.Errorf("LevelDbov = %d, want -1", header.LevelDbov)
	}
	if !header.IsDTX() {
		t.Error("IsDTX() = false, want true")
	}
	if !bytes.Equal(payload, []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("payload = %x, want aabbcc", payload)
	}
}

// Anything shorter than the fixed header is malformed.
func TestParseFrameRejectsShortInput(t *testing.T) {
	for n := 0; n < HeaderLen; n++ {
		if _, _, ok := ParseFrame(make([]byte, n)); ok {
			t.Errorf("%d-byte input must fail to parse", n)
		}
	}
	if _, _, ok := ParseFrame(make([]byte, HeaderLen)); !ok {
		t.Error("an exactly-header-length input must parse, with an empty payload")
	}
}

// Out-of-range telemetry must not drop the frame. The metric is suppressed
// (clamped to the silence floor) but the audio payload is preserved for
// forwarding. This is the "bad VU metadata is not audible loss" invariant.
func TestParseFrameClampsOutOfRangeLevelAndKeepsFrame(t *testing.T) {
	b := []byte{
		0x00, 0x07, // seq = 7
		0x00, 0x00, 0x03, 0xC0, // ts48k = 960
		0x7F, // level = +127, outside [-127, 0]
		0x00, // flags
		'o', 'p', 'u', 's',
	}

	header, payload, ok := ParseFrame(b)
	if !ok {
		t.Fatal("parse must succeed")
	}
	if header.LevelDbov != LevelSilenceFloor {
		t.Errorf("LevelDbov = %d, want the silence floor %d", header.LevelDbov, LevelSilenceFloor)
	}
	if header.Seq != 7 {
		t.Errorf("Seq = %d, want valid fields preserved alongside the clamp", header.Seq)
	}
	if string(payload) != "opus" {
		t.Errorf("payload = %q, want it still available for forwarding", payload)
	}
}

// Reserved flag bits are passed through untouched. Receivers ignore them; this
// package's only job is to carry them faithfully so a future flag survives an
// intermediate hop.
func TestParseFramePreservesReservedFlagBits(t *testing.T) {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0b1010_1010, 'x'}

	header, _, ok := ParseFrame(b)
	if !ok {
		t.Fatal("parse failed")
	}
	if header.Flags != 0b1010_1010 {
		t.Errorf("Flags = %#b, want the reserved bits untouched", header.Flags)
	}
	if header.IsDTX() {
		t.Error("IsDTX() = true, but FlagDTX is clear")
	}
}

func TestClampLevel(t *testing.T) {
	tests := []struct {
		in, want int8
	}{
		{in: 0, want: 0},
		{in: -1, want: -1},
		{in: -126, want: -126},
		{in: -127, want: -127},
		{in: 1, want: LevelSilenceFloor},
		{in: 127, want: LevelSilenceFloor},
		// -128 is below the floor, not a louder signal.
		{in: -128, want: LevelSilenceFloor},
	}
	for _, tc := range tests {
		if got := ClampLevel(tc.in); got != tc.want {
			t.Errorf("ClampLevel(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	opus := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	tests := []struct {
		name   string
		header FrameHeader
	}{
		{name: "zero header", header: FrameHeader{}},
		{name: "typical", header: FrameHeader{Seq: 1234, Ts48k: 960 * 1234, LevelDbov: -30}},
		{name: "dtx", header: FrameHeader{Seq: 1, Ts48k: 960, LevelDbov: -127, Flags: FlagDTX}},
		{name: "reserved flags", header: FrameHeader{Flags: 0xFE}},
		// Both counters wrap; the codec must carry the wrapped values as-is.
		{name: "seq at wrap boundary", header: FrameHeader{Seq: 65535}},
		{name: "seq just past wrap", header: FrameHeader{Seq: 0}},
		{name: "ts at wrap boundary", header: FrameHeader{Ts48k: 4294967295}},
		{name: "loudest level", header: FrameHeader{LevelDbov: 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeFrame(tc.header, opus)
			if len(encoded) != HeaderLen+len(opus) {
				t.Fatalf("encoded length = %d, want %d", len(encoded), HeaderLen+len(opus))
			}
			header, payload, ok := ParseFrame(encoded)
			if !ok {
				t.Fatal("round-trip parse failed")
			}
			if header != tc.header {
				t.Errorf("header = %+v, want %+v", header, tc.header)
			}
			if !bytes.Equal(payload, opus) {
				t.Errorf("payload = %x, want %x", payload, opus)
			}
		})
	}
}

func TestEncodeFrameClampsLevel(t *testing.T) {
	// A caller cannot smuggle an out-of-range level onto the wire.
	encoded := EncodeFrame(FrameHeader{LevelDbov: 100}, []byte{1})
	header, _, ok := ParseFrame(encoded)
	if !ok {
		t.Fatal("parse failed")
	}
	if header.LevelDbov != LevelSilenceFloor {
		t.Errorf("LevelDbov = %d, want %d", header.LevelDbov, LevelSilenceFloor)
	}
}

func TestAppendFrameAppendsRatherThanOverwrites(t *testing.T) {
	dst := []byte{0xAA}
	out := AppendFrame(dst, FrameHeader{Seq: 1}, []byte{0xBB})
	if out[0] != 0xAA {
		t.Errorf("AppendFrame overwrote existing bytes: %x", out)
	}
	if len(out) != 1+HeaderLen+1 {
		t.Errorf("length = %d, want %d", len(out), 1+HeaderLen+1)
	}
}

func TestValidClientFrame(t *testing.T) {
	header := EncodeFrame(FrameHeader{Seq: 1}, nil) // header, no payload
	good := EncodeFrame(FrameHeader{Seq: 1}, []byte{0x01})

	tests := []struct {
		name    string
		version uint8
		frame   []byte
		wantOK  bool
	}{
		{name: "v2 frame with payload", version: 2, frame: good, wantOK: true},
		{name: "v3 frame with payload", version: 3, frame: good, wantOK: true},
		{name: "v2 header with no payload", version: 2, frame: header, wantOK: false},
		{name: "v2 frame shorter than a header", version: 2, frame: make([]byte, HeaderLen-1), wantOK: false},
		{name: "empty frame", version: 2, frame: nil, wantOK: false},
		// v1 predates the header, so a bare payload is legitimate there.
		{name: "v1 bare payload", version: 1, frame: []byte{0x01, 0x02}, wantOK: true},
		{name: "v1 empty frame", version: 1, frame: nil, wantOK: false},
		{name: "at the size limit", version: 2, frame: EncodeFrame(FrameHeader{}, make([]byte, MaxFrameBytes-HeaderLen)), wantOK: true},
		{name: "one byte over the size limit", version: 2, frame: EncodeFrame(FrameHeader{}, make([]byte, MaxFrameBytes-HeaderLen+1)), wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := ValidClientFrame(tc.version, tc.frame)
			if ok != tc.wantOK {
				t.Fatalf("ValidClientFrame = %v (%q), want %v", ok, reason, tc.wantOK)
			}
			if !ok && reason == "" {
				t.Error("a rejection must explain itself")
			}
		})
	}
}

func TestProtocolVersionPredicates(t *testing.T) {
	for v := uint8(1); v <= CurrentProtocolVersion; v++ {
		if !SupportedProtocolVersion(v) {
			t.Errorf("SupportedProtocolVersion(%d) = false", v)
		}
	}
	for _, v := range []uint8{0, CurrentProtocolVersion + 1, 255} {
		if SupportedProtocolVersion(v) {
			t.Errorf("SupportedProtocolVersion(%d) = true", v)
		}
	}
	if HasHeader(1) {
		t.Error("v1 predates the frame header")
	}
	for v := uint8(2); v <= CurrentProtocolVersion; v++ {
		if !HasHeader(v) {
			t.Errorf("HasHeader(%d) = false", v)
		}
	}
}

func TestRelayPrefix(t *testing.T) {
	frame := EncodeFrame(FrameHeader{Seq: 42, Ts48k: 960, LevelDbov: -20}, []byte("opus"))

	tests := []struct {
		name      string
		version   uint8
		peerIndex uint8
		epoch     uint8
		wantLen   int
		wantEpoch uint8
	}{
		{name: "v1 carries only a peer index", version: 1, peerIndex: 7, epoch: 3, wantLen: 1, wantEpoch: 0},
		{name: "v2 carries only a peer index", version: 2, peerIndex: 7, epoch: 3, wantLen: 1, wantEpoch: 0},
		{name: "v3 carries a peer index and an epoch", version: 3, peerIndex: 7, epoch: 3, wantLen: 2, wantEpoch: 3},
		{name: "v3 with the highest index and epoch", version: 3, peerIndex: 254, epoch: 255, wantLen: 2, wantEpoch: 255},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PrefixLen(tc.version); got != tc.wantLen {
				t.Fatalf("PrefixLen(%d) = %d, want %d", tc.version, got, tc.wantLen)
			}

			relayed := RelayFrame(tc.version, tc.peerIndex, tc.epoch, frame)
			if len(relayed) != tc.wantLen+len(frame) {
				t.Fatalf("relayed length = %d, want %d", len(relayed), tc.wantLen+len(frame))
			}

			peerIndex, epoch, got, ok := ParseRelayFrame(tc.version, relayed)
			if !ok {
				t.Fatal("ParseRelayFrame returned ok = false")
			}
			if peerIndex != tc.peerIndex {
				t.Errorf("peerIndex = %d, want %d", peerIndex, tc.peerIndex)
			}
			if epoch != tc.wantEpoch {
				t.Errorf("epoch = %d, want %d", epoch, tc.wantEpoch)
			}
			// The whole point: the author's bytes survive the round trip
			// unchanged, so a relay never has to understand them.
			if !bytes.Equal(got, frame) {
				t.Errorf("frame = %x, want it byte-identical to %x", got, frame)
			}
		})
	}
}

func TestParseRelayFrameRejectsTruncatedPrefix(t *testing.T) {
	if _, _, _, ok := ParseRelayFrame(1, nil); ok {
		t.Error("v1 with no bytes must fail")
	}
	if _, _, _, ok := ParseRelayFrame(3, []byte{0x01}); ok {
		t.Error("v3 with only one byte must fail: the epoch is missing")
	}
	// A prefix with no frame after it parses: an empty frame is a policy
	// question for the receiver, not a framing error.
	if _, _, frame, ok := ParseRelayFrame(3, []byte{0x01, 0x02}); !ok || len(frame) != 0 {
		t.Errorf("ok = %v, frame = %x; want ok with an empty frame", ok, frame)
	}
}

func TestAudioFormatConstants(t *testing.T) {
	// 20 ms at 48 kHz is 960 samples. If this drifts, every jitter buffer and
	// timestamp increment built on it drifts too.
	if SamplesPerFrame != 960 {
		t.Errorf("SamplesPerFrame = %d, want 960", SamplesPerFrame)
	}
	if SampleRate != 48000 || Channels != 1 || FrameDurationMillis != 20 {
		t.Errorf("audio format drifted: %d Hz, %d ch, %d ms", SampleRate, Channels, FrameDurationMillis)
	}
}

// ParseFrame reads attacker-controlled bytes on the hot path, so fuzz it: it
// must never panic, and must never report a payload longer than its input.
func FuzzParseFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, HeaderLen))
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x7F, 0xFF, 'o', 'p'})

	f.Fuzz(func(t *testing.T, b []byte) {
		header, payload, ok := ParseFrame(b)
		if !ok {
			return
		}
		if len(payload) != len(b)-HeaderLen {
			t.Fatalf("payload length = %d, want %d", len(payload), len(b)-HeaderLen)
		}
		if header.LevelDbov < LevelSilenceFloor || header.LevelDbov > 0 {
			t.Fatalf("LevelDbov = %d escaped the canonical range", header.LevelDbov)
		}
		// Re-encoding a parsed frame must reproduce the input exactly, except
		// where the level was clamped.
		if ClampLevel(int8(b[6])) == int8(b[6]) {
			if got := EncodeFrame(header, payload); !bytes.Equal(got, b) {
				t.Fatalf("re-encode = %x, want %x", got, b)
			}
		}
	})
}
