package nip71

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	testPubkeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHash    = "3093509d1e0bc604ff60cb9286f4cd7c781553bc8991937befaacfdc28ec5cdc"
	testPrivKey = "0acd1245d4b0e9cae1a3b0e1a1e0cf3d1e5b2a7c8d9e0f1a2b3c4d5e6f70268c"
)

func ev(kind int, tags ...[]string) *nip01.Event {
	return &nip01.Event{Kind: kind, PubKey: testPubkeyA, Tags: tags}
}

func u64Ptr(n uint64) *uint64 { return &n }

func TestKindPredicates(t *testing.T) {
	tests := []struct {
		kind        int
		video       bool
		short       bool
		addressable bool
	}{
		{kind: KindVideo, video: true},
		{kind: KindShortVideo, video: true, short: true},
		{kind: KindAddressableVideo, video: true, addressable: true},
		{kind: KindAddressableShortVideo, video: true, short: true, addressable: true},
		{kind: 1},
		{kind: 20},
		{kind: 23},
		{kind: 34234},
		{kind: 34237},
	}

	for _, tc := range tests {
		if got := IsVideoKind(tc.kind); got != tc.video {
			t.Errorf("IsVideoKind(%d) = %v, want %v", tc.kind, got, tc.video)
		}
		if got := IsShortVideoKind(tc.kind); got != tc.short {
			t.Errorf("IsShortVideoKind(%d) = %v, want %v", tc.kind, got, tc.short)
		}
		if got := IsAddressableVideoKind(tc.kind); got != tc.addressable {
			t.Errorf("IsAddressableVideoKind(%d) = %v, want %v", tc.kind, got, tc.addressable)
		}
	}
}

func TestParseVideoRequiredTags(t *testing.T) {
	tests := []struct {
		name      string
		kind      int
		tags      [][]string
		wantErrIs error
	}{
		{name: "regular video needs only a title", kind: KindVideo, tags: [][]string{{"title", "T"}}},
		{name: "short video needs only a title", kind: KindShortVideo, tags: [][]string{{"title", "T"}}},
		{name: "regular video without a title", kind: KindVideo, tags: [][]string{{"alt", "x"}}, wantErrIs: ErrMissingTitle},
		{
			name:      "addressable video needs a d tag",
			kind:      KindAddressableVideo,
			tags:      [][]string{{"title", "T"}},
			wantErrIs: ErrMissingDTag,
		},
		{
			name: "addressable video with a d tag",
			kind: KindAddressableVideo,
			tags: [][]string{{"d", "v1"}, {"title", "T"}},
		},
		{
			name:      "addressable short video needs a d tag",
			kind:      KindAddressableShortVideo,
			tags:      [][]string{{"title", "T"}},
			wantErrIs: ErrMissingDTag,
		},
		{
			name: "a d tag on a regular video is harmless",
			kind: KindVideo,
			tags: [][]string{{"d", "ignored"}, {"title", "T"}},
		},
		{name: "wrong kind", kind: 1, tags: [][]string{{"title", "T"}}, wantErrIs: ErrWrongKind},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseVideo(ev(tc.kind, tc.tags...))
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseVideoImeta(t *testing.T) {
	// The spec's own imeta example, plus the properties this NIP adds.
	video, err := ParseVideo(ev(KindVideo,
		[]string{"title", "Hive Mind"},
		[]string{
			ImetaTagName,
			"dim 1920x1080",
			"url https://myvideo.com/1080/12345.mp4",
			"x " + testHash,
			"m video/mp4",
			"image https://myvideo.com/1080/12345.jpg",
			"fallback https://backup.com/1080/12345.mp4",
			"service nip96",
			"duration 12.5",
			"bitrate 4200000",
			"ov en",
			"newproperty somevalue",
		},
		[]string{ImetaTagName, "url https://myvideo.com/audio-en.m4a", "m audio/mp4", "waveform 0 7 35 8"},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(video.Variants) != 2 {
		t.Fatalf("variants = %d, want 2", len(video.Variants))
	}

	v := video.Variants[0]
	if v.Dim != "1920x1080" || v.MimeType != "video/mp4" || v.Hash != testHash {
		t.Errorf("variant = %+v", v)
	}
	if v.Duration != 12.5 || !v.DurationSet {
		t.Errorf("duration = %v/%v", v.Duration, v.DurationSet)
	}
	if v.Bitrate != 4200000 || !v.BitrateSet {
		t.Errorf("bitrate = %v/%v", v.Bitrate, v.BitrateSet)
	}
	if v.Service != "nip96" {
		t.Errorf("service = %q", v.Service)
	}
	if v.OriginalVersion != "en" || !v.OriginalVersionSet {
		t.Errorf("ov = %q/%v", v.OriginalVersion, v.OriginalVersionSet)
	}
	if len(v.Images) != 1 || len(v.Fallbacks) != 1 {
		t.Errorf("images = %v fallbacks = %v", v.Images, v.Fallbacks)
	}
	// url and fallback are weighted equally, so both are offered.
	if got := v.URLs(); len(got) != 2 {
		t.Errorf("URLs() = %v, want the url plus its fallback", got)
	}
	// An unmodelled imeta property must survive rather than vanish.
	if got := v.Extra["newproperty"]; len(got) != 1 || got[0] != "somevalue" {
		t.Errorf("Extra = %v", v.Extra)
	}

	if len(video.Variants[1].Waveform) != 4 {
		t.Errorf("audio waveform = %v", video.Variants[1].Waveform)
	}
	if !video.HasPlayableVariant() {
		t.Error("HasPlayableVariant() = false")
	}
}

func TestParseVideoImetaErrors(t *testing.T) {
	tests := []struct {
		name      string
		imeta     []string
		wantErrIs error
	}{
		{name: "non-numeric duration", imeta: []string{"duration soon"}, wantErrIs: ErrInvalidDuration},
		{name: "non-numeric bitrate", imeta: []string{"bitrate fast"}, wantErrIs: ErrInvalidBitrate},
		{name: "negative bitrate", imeta: []string{"bitrate -1"}, wantErrIs: ErrInvalidBitrate},
		{name: "non-integer waveform", imeta: []string{"waveform 0 loud"}, wantErrIs: ErrInvalidWaveform},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tag := append([]string{ImetaTagName}, tc.imeta...)
			_, err := ParseVideo(ev(KindVideo, []string{"title", "T"}, tag))
			if !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
			}
		})
	}
}

func TestParseVideoSupportingTags(t *testing.T) {
	video, err := ParseVideo(ev(KindVideo,
		[]string{"title", "Hive Mind"},
		[]string{"published_at", "1700000000"},
		[]string{"alt", "a talking bee"},
		[]string{"content-warning", "loud"},
		[]string{"t", "nostr"},
		[]string{"t", "bees"},
		[]string{"r", "https://example.com/notes"},
		[]string{"p", testPubkeyA, "wss://relay.example"},
		[]string{"text-track", "https://x/captions.vtt", "captions", "en"},
		[]string{"segment", "00:00:00.000", "00:01:30.500", "Intro", "https://x/thumb.jpg"},
		[]string{"origin", "youtube", "abc123", "https://youtu.be/abc123", "extra"},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if video.PublishedAt == nil || *video.PublishedAt != 1700000000 {
		t.Errorf("PublishedAt = %v", video.PublishedAt)
	}
	if video.Alt != "a talking bee" {
		t.Errorf("Alt = %q", video.Alt)
	}
	if !video.HasContentWarning || video.ContentWarning != "loud" {
		t.Errorf("content warning = %v/%q", video.HasContentWarning, video.ContentWarning)
	}
	if len(video.Hashtags) != 2 || len(video.References) != 1 {
		t.Errorf("hashtags = %v references = %v", video.Hashtags, video.References)
	}
	if len(video.Participants) != 1 || video.Participants[0].RelayURL != "wss://relay.example" {
		t.Errorf("participants = %+v", video.Participants)
	}
	if len(video.TextTracks) != 1 || video.TextTracks[0].Language != "en" {
		t.Errorf("text tracks = %+v", video.TextTracks)
	}
	if len(video.Segments) != 1 || video.Segments[0].Title != "Intro" {
		t.Errorf("segments = %+v", video.Segments)
	}
	if video.Origin == nil || video.Origin.Platform != "youtube" || video.Origin.ExternalID != "abc123" {
		t.Errorf("origin = %+v", video.Origin)
	}
}

func TestParseVideoSupportingTagErrors(t *testing.T) {
	tests := []struct {
		name      string
		tag       []string
		wantErrIs error
	}{
		{name: "bad published_at", tag: []string{"published_at", "yesterday"}, wantErrIs: ErrInvalidTimestamp},
		{name: "bad participant pubkey", tag: []string{"p", "nope"}, wantErrIs: ErrInvalidPubkey},
		{name: "segment without an end", tag: []string{"segment", "00:00:00.000"}, wantErrIs: ErrInvalidSegment},
		{name: "segment start not a timecode", tag: []string{"segment", "0", "00:01:00.000"}, wantErrIs: ErrInvalidTimecode},
		{name: "segment end not a timecode", tag: []string{"segment", "00:00:00.000", "90s"}, wantErrIs: ErrInvalidTimecode},
		{name: "segment missing millis", tag: []string{"segment", "00:00:00", "00:01:00.000"}, wantErrIs: ErrInvalidTimecode},
		{name: "origin without an external id", tag: []string{"origin", "youtube"}, wantErrIs: ErrInvalidOrigin},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseVideo(ev(KindVideo, []string{"title", "T"}, tc.tag))
			if !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErrIs)
			}
		})
	}
}

func TestContentWarningPresenceIsTheWarning(t *testing.T) {
	// A bare ["content-warning"] with no reason still warns.
	video, err := ParseVideo(ev(KindVideo, []string{"title", "T"}, []string{"content-warning"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !video.HasContentWarning || video.ContentWarning != "" {
		t.Errorf("content warning = %v/%q", video.HasContentWarning, video.ContentWarning)
	}

	none, err := ParseVideo(ev(KindVideo, []string{"title", "T"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if none.HasContentWarning {
		t.Error("absent content-warning must not warn")
	}
}

func TestVideoWithoutPlayableVariantStillParses(t *testing.T) {
	// The spec calls imeta the primary source of video information but never
	// makes it a MUST, so this parses -- callers check HasPlayableVariant.
	video, err := ParseVideo(ev(KindVideo, []string{"title", "T"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if video.HasPlayableVariant() {
		t.Error("HasPlayableVariant() = true with no variants")
	}

	noURL, err := ParseVideo(ev(KindVideo, []string{"title", "T"}, []string{ImetaTagName, "m video/mp4"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if noURL.HasPlayableVariant() {
		t.Error("a variant with no url is not playable")
	}
}

func TestNewVideoRoundTrip(t *testing.T) {
	for _, kind := range []int{KindVideo, KindShortVideo, KindAddressableVideo, KindAddressableShortVideo} {
		built := NewVideo(VideoParams{
			Pubkey:            testPubkeyA,
			Kind:              kind,
			Identifier:        "v1",
			Title:             "Hive Mind",
			Summary:           "a description",
			PublishedAt:       u64Ptr(1700000000),
			Alt:               "alt text",
			HasContentWarning: true,
			ContentWarning:    "loud",
			Hashtags:          []string{"nostr"},
			References:        []string{"https://example.com"},
			Participants:      []Participant{{Pubkey: testPubkeyA, RelayURL: "wss://r.example"}},
			TextTracks:        []TextTrack{{URL: "https://x/c.vtt", Type: "captions", Language: "en"}},
			Segments:          []Segment{{Start: "00:00:00.000", End: "00:01:30.500", Title: "Intro", Thumbnail: "https://x/t.jpg"}},
			Origin:            &Origin{Platform: "youtube", ExternalID: "abc", URL: "https://youtu.be/abc", Metadata: "m"},
			Variants: []Variant{{
				Dim: "1920x1080", URL: "https://x/v.mp4", MimeType: "video/mp4", Hash: testHash,
				Images: []string{"https://x/p.jpg"}, Fallbacks: []string{"https://y/v.mp4"},
				Duration: 12.5, DurationSet: true, Bitrate: 4200000, BitrateSet: true,
				OriginalVersion: "en", OriginalVersionSet: true,
				Extra: map[string][]string{"newproperty": {"somevalue"}},
			}},
		})

		video, err := ParseVideo(built)
		if err != nil {
			t.Fatalf("kind %d round-trip failed: %v", kind, err)
		}
		if video.Title != "Hive Mind" || video.Summary != "a description" {
			t.Errorf("kind %d: %+v", kind, video)
		}
		if video.IsAddressable() != IsAddressableVideoKind(kind) {
			t.Errorf("kind %d: IsAddressable = %v", kind, video.IsAddressable())
		}
		if video.IsShort() != IsShortVideoKind(kind) {
			t.Errorf("kind %d: IsShort = %v", kind, video.IsShort())
		}
		if len(video.Variants) != 1 {
			t.Fatalf("kind %d: variants = %d", kind, len(video.Variants))
		}
		v := video.Variants[0]
		if v.Duration != 12.5 || v.Bitrate != 4200000 || v.OriginalVersion != "en" {
			t.Errorf("kind %d: variant lost fields: %+v", kind, v)
		}
		if got := v.Extra["newproperty"]; len(got) != 1 {
			t.Errorf("kind %d: Extra lost: %v", kind, v.Extra)
		}
		if len(video.Segments) != 1 || video.Segments[0].Thumbnail != "https://x/t.jpg" {
			t.Errorf("kind %d: segments = %+v", kind, video.Segments)
		}
		if video.Origin == nil || video.Origin.Metadata != "m" {
			t.Errorf("kind %d: origin = %+v", kind, video.Origin)
		}
		if !video.HasContentWarning {
			t.Errorf("kind %d: content warning lost", kind)
		}
	}
}

func TestNewVideoOmitsDTagForRegularKinds(t *testing.T) {
	built := NewVideo(VideoParams{Pubkey: testPubkeyA, Kind: KindVideo, Identifier: "unused", Title: "T"})
	for _, tag := range built.Tags {
		if len(tag) >= 1 && tag[0] == "d" {
			t.Fatalf("a regular video should carry no d tag: %v", tag)
		}
	}
}

func TestVideoATag(t *testing.T) {
	addr, err := VideoATag(KindAddressableVideo, testPubkeyA, "v1")
	if err != nil {
		t.Fatalf("VideoATag: %v", err)
	}
	kind, pubkey, identifier, err := utils.ParseATag(addr)
	if err != nil {
		t.Fatalf("ParseATag: %v", err)
	}
	if kind != KindAddressableVideo || pubkey != testPubkeyA || identifier != "v1" {
		t.Errorf("round trip gave %d/%s/%s", kind, pubkey, identifier)
	}

	for _, kind := range []int{KindVideo, KindShortVideo, 1} {
		if _, err := VideoATag(kind, testPubkeyA, "v1"); !errors.Is(err, ErrWrongKind) {
			t.Errorf("VideoATag(%d) err = %v, want ErrWrongKind", kind, err)
		}
	}
}

func TestValidateVideo(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	t.Run("unsigned is rejected", func(t *testing.T) {
		built := NewVideo(VideoParams{Pubkey: pubkey, Kind: KindVideo, Title: "T"})
		if err := ValidateVideo(built); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("err = %v, want ErrInvalidSignature", err)
		}
	})

	t.Run("signed is accepted", func(t *testing.T) {
		built := NewVideo(VideoParams{Pubkey: pubkey, Kind: KindVideo, Title: "T"})
		if err := built.Sign(testPrivKey); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := ValidateVideo(built); err != nil {
			t.Fatalf("ValidateVideo: %v", err)
		}
	})

	t.Run("signed but titleless is rejected", func(t *testing.T) {
		built := NewVideo(VideoParams{Pubkey: pubkey, Kind: KindVideo})
		if err := built.Sign(testPrivKey); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := ValidateVideo(built); !errors.Is(err, ErrMissingTitle) {
			t.Fatalf("err = %v, want ErrMissingTitle", err)
		}
	})
}

func TestValidTimecode(t *testing.T) {
	valid := []string{"00:00:00.000", "01:23:45.678", "99:59:59.999"}
	for _, s := range valid {
		if !validTimecode(s) {
			t.Errorf("validTimecode(%q) = false", s)
		}
	}
	invalid := []string{"", "0:00:00.000", "00:00:00", "00:00:00.00", "00:00:00.0000", "aa:bb:cc.ddd", "00:00.000", "00:00:00:000"}
	for _, s := range invalid {
		if validTimecode(s) {
			t.Errorf("validTimecode(%q) = true", s)
		}
	}
}
