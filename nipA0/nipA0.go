// Package nipA0 implements NIP-A0: Voice Messages -- short voice notes
// published as a bare audio URL, with an optional NIP-92 "imeta" tag carrying
// a waveform and duration so a client can draw a preview without downloading
// the audio first. This package is a pure protocol library (parsing,
// structural validation, and event construction); it has no dependency on
// relay/.
package nipA0

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip22"
)

const (
	// KindVoiceMessage is a root voice message.
	KindVoiceMessage = 1222
	// KindVoiceMessageReply is a voice message posted as a reply. Per spec it
	// MUST follow NIP-22's comment structure, so its root/parent scopes are
	// the uppercase/lowercase tag pairs NIP-22 defines.
	KindVoiceMessageReply = 1244
)

// RecommendedMaxDuration is the length the spec says a voice message SHOULD
// stay under. Clients publishing one SHOULD enforce it or warn -- it is not a
// hard protocol limit, so this package surfaces an overrun rather than
// rejecting the event.
const RecommendedMaxDuration = 60

// RecommendedMaxWaveformValues is how many waveform samples the spec suggests
// suffice to draw a nice preview ("less than 100 values should be enough").
// Advice, not a limit.
const RecommendedMaxWaveformValues = 100

// ImetaTagName is the NIP-92 tag carrying the inline media metadata.
const ImetaTagName = "imeta"

// Failure modes, for callers that need to distinguish them (e.g. via
// errors.Is) rather than match on message text.
var (
	ErrWrongKind        = errors.New("nipA0: wrong kind")
	ErrMissingURL       = errors.New("nipA0: content must be a url to an audio file")
	ErrInvalidWaveform  = errors.New("nipA0: waveform values must be integers")
	ErrInvalidDuration  = errors.New("nipA0: duration must be a non-negative integer")
	ErrInvalidSignature = errors.New("nipA0: invalid signature")
)

// IsVoiceMessageKind reports whether kind is one of the two voice-message
// kinds.
func IsVoiceMessageKind(kind int) bool {
	return kind == KindVoiceMessage || kind == KindVoiceMessageReply
}

// VoiceMessage is a parsed kind:1222 or kind:1244 event. URL is the event's
// content, which per spec is the bare audio URL and nothing else.
//
// Waveform and Duration come from the optional "imeta" tag. DurationSet
// distinguishes an absent duration from a zero-second one, and Waveform is nil
// when no waveform was advertised.
type VoiceMessage struct {
	Kind        int
	URL         string
	MediaURL    string
	Waveform    []int
	Duration    int
	DurationSet bool
}

// IsReply reports whether this is a reply rather than a root voice message.
func (v *VoiceMessage) IsReply() bool { return v.Kind == KindVoiceMessageReply }

// ExceedsRecommendedDuration reports whether an advertised duration runs past
// what the spec recommends. A client publishing one SHOULD warn; a relay has
// no business rejecting it, which is why this is a query and not an error.
func (v *VoiceMessage) ExceedsRecommendedDuration() bool {
	return v.DurationSet && v.Duration > RecommendedMaxDuration
}

// ParseVoiceMessage parses and structurally validates a kind:1222 or
// kind:1244 event.
func ParseVoiceMessage(event *nip01.Event) (*VoiceMessage, error) {
	if !IsVoiceMessageKind(event.Kind) {
		return nil, fmt.Errorf("%w: got %d, want %d or %d", ErrWrongKind, event.Kind, KindVoiceMessage, KindVoiceMessageReply)
	}

	url := strings.TrimSpace(event.Content)
	if !looksLikeURL(url) {
		return nil, fmt.Errorf("%w: %q", ErrMissingURL, event.Content)
	}

	msg := &VoiceMessage{Kind: event.Kind, URL: url}
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != ImetaTagName {
			continue
		}
		for _, field := range tag[1:] {
			key, value, ok := splitImetaField(field)
			if !ok {
				continue
			}
			switch key {
			case "url":
				msg.MediaURL = value
			case "waveform":
				waveform, err := parseWaveform(value)
				if err != nil {
					return nil, err
				}
				msg.Waveform = waveform
			case "duration":
				duration, err := strconv.Atoi(value)
				if err != nil || duration < 0 {
					return nil, fmt.Errorf("%w: %q", ErrInvalidDuration, value)
				}
				msg.Duration = duration
				msg.DurationSet = true
			}
		}
	}
	return msg, nil
}

// ValidateVoiceMessage checks the signature and structure of a voice message.
func ValidateVoiceMessage(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseVoiceMessage(event)
	return err
}

// ReplyScopes returns the NIP-22 root and parent scopes of a kind:1244 reply.
// The spec requires a reply to follow NIP-22's structure, so rather than
// reimplement that parsing this delegates to nip22 against a kind-swapped
// shallow copy -- nip22.ParseComment accepts only its own kind:1111.
func ReplyScopes(event *nip01.Event) (root, parent nip22.Scope, err error) {
	if event.Kind != KindVoiceMessageReply {
		return root, parent, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindVoiceMessageReply)
	}
	asComment := *event
	asComment.Kind = nip22.KindComment
	comment, err := nip22.ParseComment(&asComment)
	if err != nil {
		return root, parent, err
	}
	return comment.Root, comment.Parent, nil
}

// VoiceMessageParams describes a voice message to build. Pubkey and URL are
// required; the imeta preview fields are optional.
type VoiceMessageParams struct {
	Pubkey      string
	URL         string
	Waveform    []int
	Duration    int
	DurationSet bool
	ExtraTags   [][]string
}

// NewVoiceMessage builds an unsigned kind:1222 root voice message.
func NewVoiceMessage(p VoiceMessageParams) *nip01.Event {
	return nip01.NewUnsignedEvent(KindVoiceMessage, p.Pubkey, p.URL, imetaTags(p)...)
}

// NewVoiceMessageReply builds an unsigned kind:1244 reply. The NIP-22 tag
// structure is produced by nip22.NewComment and the kind then swapped, so the
// pointer-tag rules live in one place rather than being duplicated here.
func NewVoiceMessageReply(p VoiceMessageParams, scopes nip22.CommentParams) (*nip01.Event, error) {
	scopes.Pubkey = p.Pubkey
	scopes.Content = p.URL
	event, err := nip22.NewComment(scopes)
	if err != nil {
		return nil, err
	}
	event.Kind = KindVoiceMessageReply
	event.Tags = append(event.Tags, imetaTags(p)...)
	return event, nil
}

// imetaTags renders the optional NIP-92 preview tag, omitting it entirely when
// there is nothing to preview.
func imetaTags(p VoiceMessageParams) [][]string {
	fields := []string{ImetaTagName}
	if p.URL != "" {
		fields = append(fields, "url "+p.URL)
	}
	if len(p.Waveform) > 0 {
		values := make([]string, len(p.Waveform))
		for i, v := range p.Waveform {
			values[i] = strconv.Itoa(v)
		}
		fields = append(fields, "waveform "+strings.Join(values, " "))
	}
	if p.DurationSet {
		fields = append(fields, "duration "+strconv.Itoa(p.Duration))
	}

	var tags [][]string
	if len(fields) > 1 {
		tags = append(tags, fields)
	}
	return append(tags, p.ExtraTags...)
}

// splitImetaField splits one NIP-92 "key value" field. The value may itself
// contain spaces, as a waveform does, so only the first space separates them.
func splitImetaField(field string) (key, value string, ok bool) {
	key, value, ok = strings.Cut(strings.TrimSpace(field), " ")
	if !ok {
		return "", "", false
	}
	return key, strings.TrimSpace(value), true
}

func parseWaveform(value string) ([]int, error) {
	var waveform []int
	for _, raw := range strings.Fields(value) {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrInvalidWaveform, raw)
		}
		waveform = append(waveform, n)
	}
	return waveform, nil
}

// looksLikeURL is a deliberately shallow check: the spec requires content to
// be "a URL pointing directly to an audio file", but validating the media type
// means fetching it, which a protocol library has no business doing.
func looksLikeURL(s string) bool {
	if strings.ContainsAny(s, " \t\n") {
		return false
	}
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
