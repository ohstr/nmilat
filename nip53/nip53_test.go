package nip53

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Fixed test keys. The all-hex literals exercise parsing only; the real
// keypair is needed wherever a signature is actually produced or checked.
const (
	testPubkeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPubkeyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testPrivKey = "0acd1245d4b0e9cae1a3b0e1a1e0cf3d1e5b2a7c8d9e0f1a2b3c4d5e6f70268c"
	altPrivKey  = "1bde2356e5c1fadbf2b4c1f2b2f1d04e2f6c3b8d9eaf102b3c4d5e6f78901234"
)

func intPtr(n int) *int       { return &n }
func u64Ptr(n uint64) *uint64 { return &n }
func ev(kind int, tags ...[]string) *nip01.Event {
	return &nip01.Event{Kind: kind, PubKey: testPubkeyA, Tags: tags}
}

func testPubkeyFor(t *testing.T, privKey string) string {
	t.Helper()
	pub, err := utils.GetPublicKey(privKey)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	return pub
}

/////////////////////////////////////////////////////////////////////
// Meeting Spaces (kind 30312)
/////////////////////////////////////////////////////////////////////

func TestParseMeetingSpace(t *testing.T) {
	host := []string{"p", testPubkeyA, "wss://provider.example", RoleHost}

	tests := []struct {
		name        string
		tags        [][]string
		wantErrIs   error
		wantID      string
		wantService string
		wantHosts   int
	}{
		{
			name: "minimal valid",
			tags: [][]string{
				{"d", "room-1"}, {"room", "Standup"},
				{"status", SpaceStatusOpen}, {"service", "wss://relay.example/huddle/room-1"},
				host,
			},
			wantID:      "room-1",
			wantService: "wss://relay.example/huddle/room-1",
			wantHosts:   1,
		},
		{
			name: "full spec example",
			tags: [][]string{
				{"d", "room-1"}, {"room", "Standup"},
				{"summary", "daily"}, {"image", "https://img.example/a.png"},
				{"status", SpaceStatusPrivate}, {"service", "wss://x/y"},
				{"endpoint", "https://api.example/status"},
				{"t", "eng"}, {"t", "daily"},
				host,
				{"p", testPubkeyB, "", RoleModerator},
				{"relays", "wss://one.example", "wss://two.example"},
			},
			wantID:      "room-1",
			wantService: "wss://x/y",
			wantHosts:   1,
		},
		{
			name: "tag order does not matter",
			tags: [][]string{
				host, {"service", "wss://x/y"},
				{"status", SpaceStatusOpen}, {"room", "Standup"}, {"d", "room-1"},
			},
			wantID:      "room-1",
			wantService: "wss://x/y",
			wantHosts:   1,
		},
		{
			name: "unknown tags are ignored, not fatal",
			tags: [][]string{
				{"d", "room-1"}, {"room", "R"}, {"status", SpaceStatusOpen},
				{"service", "wss://x"}, host,
				{"future_tag", "whatever"},
			},
			wantID:      "room-1",
			wantService: "wss://x",
			wantHosts:   1,
		},
		{
			name:      "missing d tag",
			tags:      [][]string{{"room", "R"}, {"status", SpaceStatusOpen}, {"service", "wss://x"}, host},
			wantErrIs: ErrMissingDTag,
		},
		{
			name:      "missing room tag",
			tags:      [][]string{{"d", "r"}, {"status", SpaceStatusOpen}, {"service", "wss://x"}, host},
			wantErrIs: ErrMissingRoomTag,
		},
		{
			name:      "missing status tag",
			tags:      [][]string{{"d", "r"}, {"room", "R"}, {"service", "wss://x"}, host},
			wantErrIs: ErrMissingStatusTag,
		},
		{
			name:      "missing service tag",
			tags:      [][]string{{"d", "r"}, {"room", "R"}, {"status", SpaceStatusOpen}, host},
			wantErrIs: ErrMissingServiceTag,
		},
		{
			name:      "invalid space status",
			tags:      [][]string{{"d", "r"}, {"room", "R"}, {"status", "live"}, {"service", "wss://x"}, host},
			wantErrIs: ErrInvalidSpaceStatus,
		},
		{
			name: "no host provider",
			tags: [][]string{
				{"d", "r"}, {"room", "R"}, {"status", SpaceStatusOpen}, {"service", "wss://x"},
				{"p", testPubkeyB, "", RoleModerator},
			},
			wantErrIs: ErrMissingHost,
		},
		{
			name: "no providers at all",
			tags: [][]string{
				{"d", "r"}, {"room", "R"}, {"status", SpaceStatusOpen}, {"service", "wss://x"},
			},
			wantErrIs: ErrMissingHost,
		},
		{
			name: "invalid provider pubkey",
			tags: [][]string{
				{"d", "r"}, {"room", "R"}, {"status", SpaceStatusOpen}, {"service", "wss://x"},
				{"p", "not-a-key", "", RoleHost},
			},
			wantErrIs: ErrInvalidPubkey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			space, err := ParseMeetingSpace(ev(KindMeetingSpace, tc.tags...))
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if space.Identifier != tc.wantID {
				t.Errorf("Identifier = %q, want %q", space.Identifier, tc.wantID)
			}
			if space.Service != tc.wantService {
				t.Errorf("Service = %q, want %q", space.Service, tc.wantService)
			}
			if got := len(space.Hosts()); got != tc.wantHosts {
				t.Errorf("Hosts() = %d, want %d", got, tc.wantHosts)
			}
		})
	}
}

func TestParseMeetingSpace_WrongKind(t *testing.T) {
	_, err := ParseMeetingSpace(ev(KindMeetingRoomEvent, []string{"d", "x"}))
	if !errors.Is(err, ErrWrongKind) {
		t.Fatalf("err = %v, want ErrWrongKind", err)
	}
}

func TestNewMeetingSpace_RoundTrip(t *testing.T) {
	built := NewMeetingSpace(MeetingSpaceParams{
		Pubkey:     testPubkeyA,
		Identifier: "room-1",
		Room:       "Standup",
		Summary:    "daily",
		Status:     SpaceStatusOpen,
		Service:    "wss://relay.example/huddle/room-1",
		Endpoint:   "https://api.example/s",
		Hashtags:   []string{"eng"},
		Providers:  []Participant{{Pubkey: testPubkeyA, Role: RoleHost}},
		Relays:     []string{"wss://one.example"},
	})

	space, err := ParseMeetingSpace(built)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if space.Room != "Standup" || space.Status != SpaceStatusOpen {
		t.Errorf("unexpected space: %+v", space)
	}
	if space.Endpoint != "https://api.example/s" {
		t.Errorf("Endpoint = %q", space.Endpoint)
	}
	if len(space.Relays) != 1 || space.Relays[0] != "wss://one.example" {
		t.Errorf("Relays = %v", space.Relays)
	}
	if len(space.Hashtags) != 1 || space.Hashtags[0] != "eng" {
		t.Errorf("Hashtags = %v", space.Hashtags)
	}
}

/////////////////////////////////////////////////////////////////////
// Meeting Room Events (kind 30313)
/////////////////////////////////////////////////////////////////////

func TestParseMeetingRoomEvent(t *testing.T) {
	spaceATag, err := SpaceATag(testPubkeyA, "room-1")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}
	streamATag, err := StreamATag(testPubkeyA, "room-1")
	if err != nil {
		t.Fatalf("StreamATag: %v", err)
	}

	base := func(extra ...[]string) [][]string {
		tags := [][]string{
			{"d", "meeting-1"},
			{"a", spaceATag, "wss://nostr.example"},
			{"title", "Weekly sync"},
			{"starts", "1700000000"},
			{"status", StatusLive},
		}
		return append(tags, extra...)
	}

	tests := []struct {
		name      string
		tags      [][]string
		wantErrIs error
		wantStart uint64
		wantCurr  *int
	}{
		{name: "minimal valid", tags: base(), wantStart: 1700000000},
		{
			name:      "with counts and ends",
			tags:      base([]string{"ends", "1700003600"}, []string{"current_participants", "3"}, []string{"total_participants", "9"}),
			wantStart: 1700000000,
			wantCurr:  intPtr(3),
		},
		{name: "missing d tag", tags: [][]string{{"a", spaceATag}, {"title", "T"}, {"starts", "1"}, {"status", StatusLive}}, wantErrIs: ErrMissingDTag},
		{name: "missing a tag", tags: [][]string{{"d", "m"}, {"title", "T"}, {"starts", "1"}, {"status", StatusLive}}, wantErrIs: ErrMissingATag},
		{name: "missing title", tags: [][]string{{"d", "m"}, {"a", spaceATag}, {"starts", "1"}, {"status", StatusLive}}, wantErrIs: ErrMissingTitleTag},
		{name: "missing starts", tags: [][]string{{"d", "m"}, {"a", spaceATag}, {"title", "T"}, {"status", StatusLive}}, wantErrIs: ErrMissingStartsTag},
		{name: "missing status", tags: [][]string{{"d", "m"}, {"a", spaceATag}, {"title", "T"}, {"starts", "1"}}, wantErrIs: ErrMissingStatusTag},
		{
			name:      "a tag points at the wrong kind",
			tags:      [][]string{{"d", "m"}, {"a", streamATag}, {"title", "T"}, {"starts", "1"}, {"status", StatusLive}},
			wantErrIs: ErrWrongATagKind,
		},
		{
			name:      "malformed a tag",
			tags:      [][]string{{"d", "m"}, {"a", "nonsense"}, {"title", "T"}, {"starts", "1"}, {"status", StatusLive}},
			wantErrIs: ErrInvalidATag,
		},
		{
			name:      "invalid status",
			tags:      [][]string{{"d", "m"}, {"a", spaceATag}, {"title", "T"}, {"starts", "1"}, {"status", "streaming"}},
			wantErrIs: ErrInvalidStatus,
		},
		{
			name:      "non-numeric starts",
			tags:      [][]string{{"d", "m"}, {"a", spaceATag}, {"title", "T"}, {"starts", "soon"}, {"status", StatusLive}},
			wantErrIs: ErrInvalidTimestamp,
		},
		{name: "negative participant count", tags: base([]string{"current_participants", "-1"}), wantErrIs: ErrInvalidCount},
		{name: "non-numeric participant count", tags: base([]string{"total_participants", "many"}), wantErrIs: ErrInvalidCount},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meeting, err := ParseMeetingRoomEvent(ev(KindMeetingRoomEvent, tc.tags...))
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if meeting.Starts != tc.wantStart {
				t.Errorf("Starts = %d, want %d", meeting.Starts, tc.wantStart)
			}
			if meeting.SpacePubkey != testPubkeyA || meeting.SpaceIdentifier != "room-1" {
				t.Errorf("space components = %q/%q", meeting.SpacePubkey, meeting.SpaceIdentifier)
			}
			if tc.wantCurr != nil {
				if meeting.CurrentParticipants == nil || *meeting.CurrentParticipants != *tc.wantCurr {
					t.Errorf("CurrentParticipants = %v, want %d", meeting.CurrentParticipants, *tc.wantCurr)
				}
			}
		})
	}
}

func TestNewMeetingRoomEvent_RoundTrip(t *testing.T) {
	spaceATag, err := SpaceATag(testPubkeyA, "room-1")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}
	built := NewMeetingRoomEvent(MeetingRoomEventParams{
		Pubkey:     testPubkeyA,
		Identifier: "meeting-1",
		Space:      spaceATag,
		SpaceRelay: "wss://nostr.example",
		Title:      "Weekly sync",
		Starts:     1700000000,
		Ends:       u64Ptr(1700003600),
		Status:     StatusPlanned,
	})
	meeting, err := ParseMeetingRoomEvent(built)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if meeting.SpaceRelay != "wss://nostr.example" {
		t.Errorf("SpaceRelay = %q", meeting.SpaceRelay)
	}
	if meeting.Ends == nil || *meeting.Ends != 1700003600 {
		t.Errorf("Ends = %v", meeting.Ends)
	}
}

/////////////////////////////////////////////////////////////////////
// Room Presence (kind 10312)
/////////////////////////////////////////////////////////////////////

func TestParseRoomPresence(t *testing.T) {
	roomA, err := SpaceATag(testPubkeyA, "room-1")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}
	roomB, err := SpaceATag(testPubkeyB, "room-2")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}

	tests := []struct {
		name      string
		tags      [][]string
		wantErrIs error
		wantHand  bool
	}{
		{name: "valid, hand down", tags: [][]string{{"a", roomA, "wss://r.example", "root"}}},
		{name: "valid, hand raised", tags: [][]string{{"a", roomA, "", "root"}, {"hand", "1"}}, wantHand: true},
		{name: "hand explicitly zero", tags: [][]string{{"a", roomA}, {"hand", "0"}}},
		{
			name:      "two rooms at once is rejected",
			tags:      [][]string{{"a", roomA}, {"a", roomB}},
			wantErrIs: ErrMultipleATags,
		},
		{name: "missing a tag", tags: [][]string{{"hand", "1"}}, wantErrIs: ErrMissingATag},
		{name: "malformed a tag", tags: [][]string{{"a", "30312:nope"}}, wantErrIs: ErrInvalidATag},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			presence, err := ParseRoomPresence(ev(KindRoomPresence, tc.tags...))
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if presence.HandRaised != tc.wantHand {
				t.Errorf("HandRaised = %v, want %v", presence.HandRaised, tc.wantHand)
			}
			if presence.Room != roomA {
				t.Errorf("Room = %q, want %q", presence.Room, roomA)
			}
		})
	}
}

func TestNewRoomPresence_DefaultsMarkerToRoot(t *testing.T) {
	roomA, err := SpaceATag(testPubkeyA, "room-1")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}
	built := NewRoomPresence(RoomPresenceParams{Pubkey: testPubkeyA, Room: roomA, HandRaised: true})
	presence, err := ParseRoomPresence(built)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if presence.Marker != "root" {
		t.Errorf("Marker = %q, want root", presence.Marker)
	}
	if !presence.HandRaised {
		t.Error("HandRaised = false, want true")
	}
}

/////////////////////////////////////////////////////////////////////
// Live Chat Messages (kind 1311)
/////////////////////////////////////////////////////////////////////

func TestParseLiveChatMessage(t *testing.T) {
	activity, err := StreamATag(testPubkeyA, "stream-1")
	if err != nil {
		t.Fatalf("StreamATag: %v", err)
	}

	t.Run("valid with parent and quotes", func(t *testing.T) {
		event := &nip01.Event{
			Kind:    KindLiveChatMessage,
			PubKey:  testPubkeyA,
			Content: "zaps to live streams is beautiful",
			Tags: [][]string{
				{"a", activity, "wss://r.example"},
				{"e", "parentid"},
				{"q", "quotedid"},
			},
		}
		msg, err := ParseLiveChatMessage(event)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Activity != activity || msg.ActivityRelay != "wss://r.example" {
			t.Errorf("activity = %q / %q", msg.Activity, msg.ActivityRelay)
		}
		if msg.Parent != "parentid" || len(msg.Quotes) != 1 {
			t.Errorf("parent = %q quotes = %v", msg.Parent, msg.Quotes)
		}
		if msg.Content != event.Content {
			t.Errorf("Content = %q", msg.Content)
		}
	})

	t.Run("missing a tag", func(t *testing.T) {
		_, err := ParseLiveChatMessage(ev(KindLiveChatMessage, []string{"e", "x"}))
		if !errors.Is(err, ErrMissingATag) {
			t.Fatalf("err = %v, want ErrMissingATag", err)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		built := NewLiveChatMessage(LiveChatMessageParams{
			Pubkey:   testPubkeyA,
			Activity: activity,
			Content:  "hi",
		})
		msg, err := ParseLiveChatMessage(built)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if msg.Content != "hi" {
			t.Errorf("Content = %q", msg.Content)
		}
	})
}

/////////////////////////////////////////////////////////////////////
// Live Streaming Events (kind 30311)
/////////////////////////////////////////////////////////////////////

func TestParseLiveStream(t *testing.T) {
	t.Run("only d tag is required", func(t *testing.T) {
		ls, err := ParseLiveStream(ev(KindLiveStreamingEvent, []string{"d", "stream-1"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ls.Identifier != "stream-1" || ls.Status != "" || ls.Starts != nil {
			t.Errorf("unexpected: %+v", ls)
		}
	})

	t.Run("full spec example", func(t *testing.T) {
		ls, err := ParseLiveStream(ev(KindLiveStreamingEvent,
			[]string{"d", "stream-1"},
			[]string{"title", "Live from the hive"},
			[]string{"summary", "a description"},
			[]string{"image", "https://img.example/p.png"},
			[]string{"t", "nostr"},
			[]string{"streaming", "https://cdn.example/live.m3u8"},
			[]string{"recording", "https://cdn.example/vod.mp4"},
			[]string{"starts", "1700000000"},
			[]string{"ends", "1700003600"},
			[]string{"status", StatusLive},
			[]string{"current_participants", "42"},
			[]string{"total_participants", "108"},
			[]string{"p", testPubkeyA, "wss://one.example", RoleHost},
			[]string{"p", testPubkeyB, "wss://two.example", RoleSpeaker},
			[]string{"relays", "wss://one.example", "wss://two.example"},
			[]string{"pinned", "pinnedeventid"},
		))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ls.Status != StatusLive || ls.Starts == nil || *ls.Starts != 1700000000 {
			t.Errorf("status/starts wrong: %+v", ls)
		}
		if ls.CurrentParticipants == nil || *ls.CurrentParticipants != 42 {
			t.Errorf("CurrentParticipants = %v", ls.CurrentParticipants)
		}
		if len(ls.Participants) != 2 {
			t.Fatalf("Participants = %d, want 2", len(ls.Participants))
		}
		if ls.Participants[0].Role != RoleHost {
			t.Errorf("first role = %q", ls.Participants[0].Role)
		}
		if len(ls.Relays) != 2 || len(ls.Pinned) != 1 {
			t.Errorf("relays = %v pinned = %v", ls.Relays, ls.Pinned)
		}
	})

	t.Run("missing d tag", func(t *testing.T) {
		_, err := ParseLiveStream(ev(KindLiveStreamingEvent, []string{"title", "T"}))
		if !errors.Is(err, ErrMissingDTag) {
			t.Fatalf("err = %v, want ErrMissingDTag", err)
		}
	})

	t.Run("invalid status", func(t *testing.T) {
		_, err := ParseLiveStream(ev(KindLiveStreamingEvent, []string{"d", "s"}, []string{"status", "on-air"}))
		if !errors.Is(err, ErrInvalidStatus) {
			t.Fatalf("err = %v, want ErrInvalidStatus", err)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		built := NewLiveStream(LiveStreamParams{
			Pubkey:     testPubkeyA,
			Identifier: "stream-1",
			Title:      "Live",
			Status:     StatusLive,
			Starts:     u64Ptr(1700000000),
			Streaming:  []string{"https://cdn.example/live.m3u8"},
			Relays:     []string{"wss://one.example"},
		})
		ls, err := ParseLiveStream(built)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if ls.Title != "Live" || ls.Status != StatusLive {
			t.Errorf("unexpected: %+v", ls)
		}
	})
}

/////////////////////////////////////////////////////////////////////
// Staleness and presence freshness
/////////////////////////////////////////////////////////////////////

func TestIsStale(t *testing.T) {
	now := time.Unix(1700000000, 0)

	tests := []struct {
		name   string
		status string
		age    time.Duration
		want   bool
	}{
		{name: "live, 59 minutes old", status: StatusLive, age: 59 * time.Minute, want: false},
		{name: "live, exactly one hour old", status: StatusLive, age: time.Hour, want: false},
		{name: "live, 61 minutes old", status: StatusLive, age: 61 * time.Minute, want: true},
		{name: "ended is never stale", status: StatusEnded, age: 48 * time.Hour, want: false},
		{name: "planned is never stale", status: StatusPlanned, age: 48 * time.Hour, want: false},
		{name: "empty status is never stale", status: "", age: 48 * time.Hour, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createdAt := uint64(now.Add(-tc.age).Unix())
			if got := IsStale(tc.status, createdAt, now, DefaultStaleWindow); got != tc.want {
				t.Errorf("IsStale = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsPresenceFresh(t *testing.T) {
	now := time.Unix(1700000000, 0)
	window := DefaultPresenceWindow

	tests := []struct {
		name string
		age  time.Duration
		want bool
	}{
		{name: "just published", age: 0, want: true},
		{name: "inside the window", age: window - time.Second, want: true},
		{name: "exactly at the window", age: window, want: true},
		{name: "past the window", age: window + time.Second, want: false},
		{name: "timestamped in the future stays fresh", age: -time.Minute, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createdAt := uint64(now.Add(-tc.age).Unix())
			if got := IsPresenceFresh(createdAt, now, window); got != tc.want {
				t.Errorf("IsPresenceFresh = %v, want %v", got, tc.want)
			}
		})
	}
}

/////////////////////////////////////////////////////////////////////
// Proof of agreement to participate
/////////////////////////////////////////////////////////////////////

func TestParticipationProof(t *testing.T) {
	pubkey := testPubkeyFor(t, testPrivKey)
	aTag, err := SpaceATag(pubkey, "room-1")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}

	proof, err := SignParticipationProof(testPrivKey, aTag)
	if err != nil {
		t.Fatalf("SignParticipationProof: %v", err)
	}

	t.Run("valid proof verifies", func(t *testing.T) {
		if err := VerifyParticipationProof(pubkey, aTag, proof); err != nil {
			t.Fatalf("VerifyParticipationProof: %v", err)
		}
	})

	t.Run("tampered a tag is rejected", func(t *testing.T) {
		other, err := SpaceATag(pubkey, "room-2")
		if err != nil {
			t.Fatalf("SpaceATag: %v", err)
		}
		if err := VerifyParticipationProof(pubkey, other, proof); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("err = %v, want ErrInvalidProof", err)
		}
	})

	t.Run("wrong signer is rejected", func(t *testing.T) {
		altProof, err := SignParticipationProof(altPrivKey, aTag)
		if err != nil {
			t.Fatalf("SignParticipationProof: %v", err)
		}
		if err := VerifyParticipationProof(pubkey, aTag, altProof); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("err = %v, want ErrInvalidProof", err)
		}
	})

	t.Run("absent proof is distinguishable", func(t *testing.T) {
		if err := VerifyParticipationProof(pubkey, aTag, ""); !errors.Is(err, ErrMissingProof) {
			t.Fatalf("err = %v, want ErrMissingProof", err)
		}
	})

	t.Run("non-hex proof is rejected", func(t *testing.T) {
		if err := VerifyParticipationProof(pubkey, aTag, "zzzz"); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("err = %v, want ErrInvalidProof", err)
		}
	})

	t.Run("digest is stable and sized", func(t *testing.T) {
		if got := len(ParticipationProofDigest(aTag)); got != 32 {
			t.Fatalf("digest length = %d, want 32", got)
		}
	})

	t.Run("proof survives a p tag round trip", func(t *testing.T) {
		space := NewMeetingSpace(MeetingSpaceParams{
			Pubkey:     pubkey,
			Identifier: "room-1",
			Room:       "R",
			Status:     SpaceStatusOpen,
			Service:    "wss://x",
			Providers:  []Participant{{Pubkey: pubkey, RelayURL: "wss://r.example", Role: RoleHost, Proof: proof}},
		})
		parsed, err := ParseMeetingSpace(space)
		if err != nil {
			t.Fatalf("ParseMeetingSpace: %v", err)
		}
		hosts := parsed.Hosts()
		if len(hosts) != 1 {
			t.Fatalf("hosts = %d, want 1", len(hosts))
		}
		if !hosts[0].HasProof() {
			t.Fatal("HasProof() = false, want true")
		}
		if err := VerifyParticipationProof(hosts[0].Pubkey, aTag, hosts[0].Proof); err != nil {
			t.Fatalf("proof did not survive round trip: %v", err)
		}
	})

	t.Run("proof survives a round trip without a relay hint", func(t *testing.T) {
		space := NewMeetingSpace(MeetingSpaceParams{
			Pubkey:     pubkey,
			Identifier: "room-1",
			Room:       "R",
			Status:     SpaceStatusOpen,
			Service:    "wss://x",
			Providers:  []Participant{{Pubkey: pubkey, Role: RoleHost, Proof: proof}},
		})
		parsed, err := ParseMeetingSpace(space)
		if err != nil {
			t.Fatalf("ParseMeetingSpace: %v", err)
		}
		hosts := parsed.Hosts()
		if len(hosts) != 1 || hosts[0].Proof != proof {
			t.Fatalf("proof lost: %+v", hosts)
		}
	})
}

/////////////////////////////////////////////////////////////////////
// Signature-checking wrappers
/////////////////////////////////////////////////////////////////////

func TestValidateRejectsUnsignedEvents(t *testing.T) {
	pubkey := testPubkeyFor(t, testPrivKey)
	aTag, err := SpaceATag(pubkey, "room-1")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}

	unsigned := map[string]func() error{
		"space": func() error {
			return ValidateMeetingSpace(NewMeetingSpace(MeetingSpaceParams{Pubkey: pubkey, Identifier: "room-1", Room: "R", Status: SpaceStatusOpen, Service: "wss://x", Providers: []Participant{{Pubkey: pubkey, Role: RoleHost}}}))
		},
		"meeting": func() error {
			return ValidateMeetingRoomEvent(NewMeetingRoomEvent(MeetingRoomEventParams{Pubkey: pubkey, Identifier: "m", Space: aTag, Title: "T", Starts: 1, Status: StatusLive}))
		},
		"presence": func() error {
			return ValidateRoomPresence(NewRoomPresence(RoomPresenceParams{Pubkey: pubkey, Room: aTag}))
		},
		"chat": func() error {
			return ValidateLiveChatMessage(NewLiveChatMessage(LiveChatMessageParams{Pubkey: pubkey, Activity: aTag, Content: "hi"}))
		},
		"stream": func() error {
			return ValidateLiveStream(NewLiveStream(LiveStreamParams{Pubkey: pubkey, Identifier: "s"}))
		},
	}

	for name, validate := range unsigned {
		t.Run(name, func(t *testing.T) {
			if err := validate(); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("err = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestValidateAcceptsSignedEvent(t *testing.T) {
	pubkey := testPubkeyFor(t, testPrivKey)
	event := NewMeetingSpace(MeetingSpaceParams{
		Pubkey:     pubkey,
		Identifier: "room-1",
		Room:       "R",
		Status:     SpaceStatusOpen,
		Service:    "wss://x",
		Providers:  []Participant{{Pubkey: pubkey, Role: RoleHost}},
	})
	if err := event.Sign(testPrivKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := ValidateMeetingSpace(event); err != nil {
		t.Fatalf("ValidateMeetingSpace: %v", err)
	}
}

/////////////////////////////////////////////////////////////////////
// Status predicates
/////////////////////////////////////////////////////////////////////

func TestStatusPredicates(t *testing.T) {
	for _, s := range []string{StatusPlanned, StatusLive, StatusEnded} {
		if !IsValidStatus(s) {
			t.Errorf("IsValidStatus(%q) = false", s)
		}
		if IsValidSpaceStatus(s) {
			t.Errorf("IsValidSpaceStatus(%q) = true, activity statuses are a different set", s)
		}
	}
	for _, s := range []string{SpaceStatusOpen, SpaceStatusPrivate, SpaceStatusClosed} {
		if !IsValidSpaceStatus(s) {
			t.Errorf("IsValidSpaceStatus(%q) = false", s)
		}
	}
	for _, s := range []string{"", "LIVE", "Open", strings.ToUpper(StatusLive)} {
		if IsValidStatus(s) {
			t.Errorf("IsValidStatus(%q) = true, matching is case-sensitive", s)
		}
	}
}
