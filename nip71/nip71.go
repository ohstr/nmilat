// Package nip71 implements NIP-71: Video Events -- normal and short video
// events, their addressable counterparts, and the NIP-92 "imeta" variants that
// carry the actual video and audio tracks. This package is a pure protocol
// library (parsing, structural validation, and event construction); it has no
// dependency on relay/.
package nip71

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	// KindVideo is a normal (usually landscape, longer) video event.
	KindVideo = 21
	// KindShortVideo is a short-form (usually portrait) video event.
	KindShortVideo = 22
	// KindAddressableVideo is a normal video that can be edited after
	// publication, identified by its "d" tag.
	KindAddressableVideo = 34235
	// KindAddressableShortVideo is a short video that can be edited after
	// publication, identified by its "d" tag.
	KindAddressableShortVideo = 34236
)

// ImetaTagName is the NIP-92 tag carrying one video/audio variant.
const ImetaTagName = "imeta"

// RecommendedMaxWaveformValues is how many waveform samples the spec suggests
// suffice for an audio preview. Advice, not a limit.
const RecommendedMaxWaveformValues = 100

// Failure modes, for callers that need to distinguish them (e.g. via
// errors.Is) rather than match on message text.
var (
	ErrWrongKind        = errors.New("nip71: wrong kind")
	ErrMissingTitle     = errors.New("nip71: missing title tag")
	ErrMissingDTag      = errors.New("nip71: missing d tag (required for addressable video kinds)")
	ErrInvalidTimestamp = errors.New("nip71: invalid published_at timestamp")
	ErrInvalidDuration  = errors.New("nip71: imeta duration must be a number")
	ErrInvalidBitrate   = errors.New("nip71: imeta bitrate must be a non-negative integer")
	ErrInvalidWaveform  = errors.New("nip71: imeta waveform values must be integers")
	ErrInvalidPubkey    = errors.New("nip71: invalid participant pubkey")
	ErrInvalidSegment   = errors.New("nip71: segment needs start and end timestamps")
	ErrInvalidTimecode  = errors.New("nip71: segment timestamp must be HH:MM:SS.sss")
	ErrInvalidOrigin    = errors.New("nip71: origin needs a platform and an external id")
	ErrInvalidSignature = errors.New("nip71: invalid signature")
)

/////////////////////////////////////////////////////////////////////
// Kind predicates
/////////////////////////////////////////////////////////////////////

// IsVideoKind reports whether kind is any of the four video kinds.
func IsVideoKind(kind int) bool {
	switch kind {
	case KindVideo, KindShortVideo, KindAddressableVideo, KindAddressableShortVideo:
		return true
	default:
		return false
	}
}

// IsShortVideoKind reports whether kind is one of the short-form kinds. The
// spec is clear this is a stylistic distinction, not a size limit: nothing
// stops a "short" video being long.
func IsShortVideoKind(kind int) bool {
	return kind == KindShortVideo || kind == KindAddressableShortVideo
}

// IsAddressableVideoKind reports whether kind is one of the addressable kinds,
// which carry a "d" tag and may be edited after publication.
func IsAddressableVideoKind(kind int) bool {
	return kind == KindAddressableVideo || kind == KindAddressableShortVideo
}

/////////////////////////////////////////////////////////////////////
// imeta variants
/////////////////////////////////////////////////////////////////////

// Variant is one "imeta" tag: a single video or audio rendition. URL and
// Fallbacks are weighted equally per spec -- a client may use any of them.
//
// Extra keeps any imeta property this package does not model (NIP-92 and NIP-94
// define more), so round-tripping an event never silently drops information.
type Variant struct {
	Dim                string
	URL                string
	Fallbacks          []string
	Hash               string
	MimeType           string
	Images             []string
	Service            string
	Duration           float64
	DurationSet        bool
	Bitrate            int
	BitrateSet         bool
	Waveform           []int
	OriginalVersion    string
	OriginalVersionSet bool
	Extra              map[string][]string
}

// URLs returns the primary url followed by its fallbacks, which is the set a
// client may pick from.
func (v Variant) URLs() []string {
	var out []string
	if v.URL != "" {
		out = append(out, v.URL)
	}
	return append(out, v.Fallbacks...)
}

func parseVariant(fields []string) (Variant, error) {
	variant := Variant{}
	for _, field := range fields {
		key, value, ok := strings.Cut(strings.TrimSpace(field), " ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "dim":
			variant.Dim = value
		case "url":
			variant.URL = value
		case "fallback":
			variant.Fallbacks = append(variant.Fallbacks, value)
		case "x":
			variant.Hash = value
		case "m":
			variant.MimeType = value
		case "image":
			variant.Images = append(variant.Images, value)
		case "service":
			variant.Service = value
		case "duration":
			n, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return variant, fmt.Errorf("%w: %q", ErrInvalidDuration, value)
			}
			variant.Duration, variant.DurationSet = n, true
		case "bitrate":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return variant, fmt.Errorf("%w: %q", ErrInvalidBitrate, value)
			}
			variant.Bitrate, variant.BitrateSet = n, true
		case "waveform":
			for _, raw := range strings.Fields(value) {
				n, err := strconv.Atoi(raw)
				if err != nil {
					return variant, fmt.Errorf("%w: %q", ErrInvalidWaveform, raw)
				}
				variant.Waveform = append(variant.Waveform, n)
			}
		case "ov":
			variant.OriginalVersion, variant.OriginalVersionSet = value, true
		default:
			if variant.Extra == nil {
				variant.Extra = map[string][]string{}
			}
			variant.Extra[key] = append(variant.Extra[key], value)
		}
	}
	return variant, nil
}

func variantTag(v Variant) []string {
	fields := []string{ImetaTagName}
	appendField := func(key, value string) {
		if value != "" {
			fields = append(fields, key+" "+value)
		}
	}
	appendField("dim", v.Dim)
	appendField("url", v.URL)
	appendField("x", v.Hash)
	appendField("m", v.MimeType)
	for _, image := range v.Images {
		appendField("image", image)
	}
	for _, fallback := range v.Fallbacks {
		appendField("fallback", fallback)
	}
	appendField("service", v.Service)
	if v.DurationSet {
		fields = append(fields, "duration "+strconv.FormatFloat(v.Duration, 'f', -1, 64))
	}
	if v.BitrateSet {
		fields = append(fields, "bitrate "+strconv.Itoa(v.Bitrate))
	}
	if len(v.Waveform) > 0 {
		values := make([]string, len(v.Waveform))
		for i, n := range v.Waveform {
			values[i] = strconv.Itoa(n)
		}
		fields = append(fields, "waveform "+strings.Join(values, " "))
	}
	if v.OriginalVersionSet {
		fields = append(fields, strings.TrimSpace("ov "+v.OriginalVersion))
	}
	for key, values := range v.Extra {
		for _, value := range values {
			appendField(key, value)
		}
	}
	return fields
}

/////////////////////////////////////////////////////////////////////
// Supporting tag types
/////////////////////////////////////////////////////////////////////

// TextTrack is a "text-track" tag: a WebVTT file plus what kind of
// supplementary information it holds and, optionally, its language.
type TextTrack struct {
	URL      string
	Type     string
	Language string
}

// Segment is a "segment" tag: a chapter of the video, bounded by two
// HH:MM:SS.sss timestamps, with a title and an optional thumbnail.
type Segment struct {
	Start     string
	End       string
	Title     string
	Thumbnail string
}

// Participant is a "p" tag: someone appearing in the video, with an optional
// recommended relay.
type Participant struct {
	Pubkey   string
	RelayURL string
}

// Origin is the "origin" tag imported content carries, tracking the platform
// and id the video came from.
type Origin struct {
	Platform   string
	ExternalID string
	URL        string
	Metadata   string
}

// validTimecode reports whether s looks like the HH:MM:SS.sss form the spec
// requires of segment boundaries.
func validTimecode(s string) bool {
	clock, millis, ok := strings.Cut(s, ".")
	if !ok || len(millis) != 3 || !allDigits(millis) {
		return false
	}
	parts := strings.Split(clock, ":")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 || !allDigits(part) {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

/////////////////////////////////////////////////////////////////////
// Video events (kinds 21, 22, 34235, 34236)
/////////////////////////////////////////////////////////////////////

// Video is a parsed video event. Summary is the event's content, which per
// spec is a summary or description of the video rather than the video itself --
// the video lives in the imeta Variants.
//
// Identifier is only meaningful for the addressable kinds. HasContentWarning
// separates an absent content-warning from one present with an empty reason,
// since the tag's presence is itself the warning.
type Video struct {
	Kind              int
	Identifier        string
	Title             string
	Summary           string
	PublishedAt       *uint64
	ContentWarning    string
	HasContentWarning bool
	Alt               string
	Hashtags          []string
	References        []string
	Participants      []Participant
	TextTracks        []TextTrack
	Segments          []Segment
	Origin            *Origin
	Variants          []Variant
}

// IsShort reports whether this is one of the short-form kinds.
func (v *Video) IsShort() bool { return IsShortVideoKind(v.Kind) }

// IsAddressable reports whether this video can be edited after publication.
func (v *Video) IsAddressable() bool { return IsAddressableVideoKind(v.Kind) }

// HasPlayableVariant reports whether any variant carries a url a client could
// actually play. The spec calls imeta "the primary source of video
// information" but never states it as a MUST, so ParseVideo does not reject a
// video without one -- callers that need something playable ask here.
func (v *Video) HasPlayableVariant() bool {
	for _, variant := range v.Variants {
		if len(variant.URLs()) > 0 {
			return true
		}
	}
	return false
}

// ParseVideo parses and structurally validates any of the four video kinds.
// It enforces the spec's two required tags: title always, and d for the
// addressable kinds.
func ParseVideo(event *nip01.Event) (*Video, error) {
	if !IsVideoKind(event.Kind) {
		return nil, fmt.Errorf("%w: got %d, want %d, %d, %d or %d", ErrWrongKind,
			event.Kind, KindVideo, KindShortVideo, KindAddressableVideo, KindAddressableShortVideo)
	}

	video := &Video{Kind: event.Kind, Summary: event.Content}
	haveD := false
	for _, tag := range event.Tags {
		if len(tag) < 1 {
			continue
		}
		if tag[0] == "content-warning" {
			video.HasContentWarning = true
			if len(tag) >= 2 {
				video.ContentWarning = tag[1]
			}
			continue
		}
		if tag[0] == ImetaTagName {
			variant, err := parseVariant(tag[1:])
			if err != nil {
				return nil, err
			}
			video.Variants = append(video.Variants, variant)
			continue
		}
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "d":
			video.Identifier = tag[1]
			haveD = true
		case "title":
			video.Title = tag[1]
		case "alt":
			video.Alt = tag[1]
		case "t":
			video.Hashtags = append(video.Hashtags, tag[1])
		case "r":
			video.References = append(video.References, tag[1])
		case "published_at":
			n, err := strconv.ParseUint(tag[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: %q", ErrInvalidTimestamp, tag[1])
			}
			video.PublishedAt = &n
		case "p":
			if err := utils.Validate32Key(tag[1]); err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPubkey, tag[1], err)
			}
			participant := Participant{Pubkey: tag[1]}
			if len(tag) >= 3 {
				participant.RelayURL = tag[2]
			}
			video.Participants = append(video.Participants, participant)
		case "text-track":
			track := TextTrack{URL: tag[1]}
			if len(tag) >= 3 {
				track.Type = tag[2]
			}
			if len(tag) >= 4 {
				track.Language = tag[3]
			}
			video.TextTracks = append(video.TextTracks, track)
		case "segment":
			if len(tag) < 3 {
				return nil, ErrInvalidSegment
			}
			if !validTimecode(tag[1]) {
				return nil, fmt.Errorf("%w: %q", ErrInvalidTimecode, tag[1])
			}
			if !validTimecode(tag[2]) {
				return nil, fmt.Errorf("%w: %q", ErrInvalidTimecode, tag[2])
			}
			segment := Segment{Start: tag[1], End: tag[2]}
			if len(tag) >= 4 {
				segment.Title = tag[3]
			}
			if len(tag) >= 5 {
				segment.Thumbnail = tag[4]
			}
			video.Segments = append(video.Segments, segment)
		case "origin":
			if len(tag) < 3 {
				return nil, ErrInvalidOrigin
			}
			origin := &Origin{Platform: tag[1], ExternalID: tag[2]}
			if len(tag) >= 4 {
				origin.URL = tag[3]
			}
			if len(tag) >= 5 {
				origin.Metadata = tag[4]
			}
			video.Origin = origin
		}
	}

	if video.Title == "" {
		return nil, ErrMissingTitle
	}
	if IsAddressableVideoKind(event.Kind) && !haveD {
		return nil, ErrMissingDTag
	}
	return video, nil
}

// ValidateVideo checks the signature and structure of a video event.
func ValidateVideo(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseVideo(event)
	return err
}

// VideoParams describes a video event to build. Pubkey, Kind and Title are
// required; Identifier is additionally required for the addressable kinds.
type VideoParams struct {
	Pubkey            string
	Kind              int
	Identifier        string
	Title             string
	Summary           string
	PublishedAt       *uint64
	ContentWarning    string
	HasContentWarning bool
	Alt               string
	Hashtags          []string
	References        []string
	Participants      []Participant
	TextTracks        []TextTrack
	Segments          []Segment
	Origin            *Origin
	Variants          []Variant
}

// NewVideo builds an unsigned video event of the kind given in p. It does not
// enforce the required fields -- build it and then ParseVideo if you want them
// checked.
func NewVideo(p VideoParams) *nip01.Event {
	var tags [][]string
	if IsAddressableVideoKind(p.Kind) {
		tags = append(tags, []string{"d", p.Identifier})
	}
	tags = append(tags, []string{"title", p.Title})
	if p.PublishedAt != nil {
		tags = append(tags, []string{"published_at", strconv.FormatUint(*p.PublishedAt, 10)})
	}
	for _, variant := range p.Variants {
		tags = append(tags, variantTag(variant))
	}
	if p.Alt != "" {
		tags = append(tags, []string{"alt", p.Alt})
	}
	if p.HasContentWarning {
		tags = append(tags, []string{"content-warning", p.ContentWarning})
	}
	for _, track := range p.TextTracks {
		tag := []string{"text-track", track.URL}
		if track.Type != "" || track.Language != "" {
			tag = append(tag, track.Type)
		}
		if track.Language != "" {
			tag = append(tag, track.Language)
		}
		tags = append(tags, tag)
	}
	for _, segment := range p.Segments {
		tag := []string{"segment", segment.Start, segment.End}
		if segment.Title != "" || segment.Thumbnail != "" {
			tag = append(tag, segment.Title)
		}
		if segment.Thumbnail != "" {
			tag = append(tag, segment.Thumbnail)
		}
		tags = append(tags, tag)
	}
	for _, hashtag := range p.Hashtags {
		tags = append(tags, []string{"t", hashtag})
	}
	for _, participant := range p.Participants {
		tag := []string{"p", participant.Pubkey}
		if participant.RelayURL != "" {
			tag = append(tag, participant.RelayURL)
		}
		tags = append(tags, tag)
	}
	for _, reference := range p.References {
		tags = append(tags, []string{"r", reference})
	}
	if p.Origin != nil {
		tag := []string{"origin", p.Origin.Platform, p.Origin.ExternalID}
		if p.Origin.URL != "" || p.Origin.Metadata != "" {
			tag = append(tag, p.Origin.URL)
		}
		if p.Origin.Metadata != "" {
			tag = append(tag, p.Origin.Metadata)
		}
		tags = append(tags, tag)
	}
	return nip01.NewUnsignedEvent(p.Kind, p.Pubkey, p.Summary, tags...)
}

// VideoATag renders the "a" tag value addressing an addressable video, for
// referencing it from a NIP-53 recording or anywhere else.
func VideoATag(kind int, pubkey, identifier string) (string, error) {
	if !IsAddressableVideoKind(kind) {
		return "", fmt.Errorf("%w: %d is not an addressable video kind", ErrWrongKind, kind)
	}
	return utils.FormatATag(kind, pubkey, identifier)
}
