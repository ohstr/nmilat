// Package nip88 implements NIP-88: Polls, allowing clients to publish
// single- or multiple-choice polls (kind 1068) and votes on them
// (kind 1018).
package nip88

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	KindPoll         = 1068
	KindPollResponse = 1018
)

// Failure modes for ParsePoll/ValidatePoll/ParsePollResponse/
// ValidatePollResponse, for callers that need to distinguish them (e.g. via
// errors.Is) rather than match on message text.
var (
	ErrWrongKind          = errors.New("nip88: wrong kind")
	ErrInvalidOptionTag   = errors.New("nip88: invalid option tag")
	ErrDuplicateOptionID  = errors.New("nip88: duplicate option id")
	ErrInvalidPollType    = errors.New("nip88: invalid polltype")
	ErrInvalidRelayURL    = errors.New("nip88: invalid relay url")
	ErrInvalidRelayScheme = errors.New("nip88: relay url must use ws or wss scheme")
	ErrInvalidEndsAt      = errors.New("nip88: invalid endsAt tag")
	ErrTooFewOptions      = errors.New("nip88: poll must have at least 2 options")
	ErrInvalidSignature   = errors.New("nip88: invalid signature")
	ErrMissingEventTag    = errors.New("nip88: missing or invalid e tag")
	ErrNoResponseTags     = errors.New("nip88: response must have at least one response tag")
	ErrWrongPoll          = errors.New("nip88: response references a different poll")
	ErrTooManyResponses   = errors.New("nip88: singlechoice poll response must have exactly one response tag")
	ErrUnknownOption      = errors.New("nip88: response option is not valid for this poll")
)

// Poll types, set via the "polltype" tag. Per spec, absence of the tag
// defaults to PollTypeSingle.
const (
	PollTypeSingle   = "singlechoice"
	PollTypeMultiple = "multiplechoice"
)

// PollOption is one selectable answer in a poll, from an
// ["option", <id>, <label>] tag.
type PollOption struct {
	ID    string
	Label string
}

// Poll is a parsed kind:1068 poll event.
type Poll struct {
	*nip01.Event
	Question string
	Options  []PollOption
	PollType string
	Relays   []string
	EndsAt   *time.Time
}

// ParsePoll parses and structurally validates a kind:1068 poll event.
func ParsePoll(event *nip01.Event) (*Poll, error) {
	if event.Kind != KindPoll {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindPoll)
	}

	p := &Poll{Event: event, Question: event.Content, PollType: PollTypeSingle}
	seenOptions := make(map[string]bool)

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "option":
			if len(tag) < 3 {
				return nil, fmt.Errorf("%w: expected [\"option\", id, label], got %v", ErrInvalidOptionTag, tag)
			}
			if seenOptions[tag[1]] {
				return nil, fmt.Errorf("%w: %q", ErrDuplicateOptionID, tag[1])
			}
			seenOptions[tag[1]] = true
			p.Options = append(p.Options, PollOption{ID: tag[1], Label: tag[2]})
		case "polltype":
			if tag[1] != PollTypeSingle && tag[1] != PollTypeMultiple {
				return nil, fmt.Errorf("%w: %q, must be %q or %q", ErrInvalidPollType, tag[1], PollTypeSingle, PollTypeMultiple)
			}
			p.PollType = tag[1]
		case "relay":
			u, err := url.ParseRequestURI(tag[1])
			if err != nil {
				return nil, fmt.Errorf("%w %q: %w", ErrInvalidRelayURL, tag[1], err)
			}
			if u.Scheme != "wss" && u.Scheme != "ws" {
				return nil, fmt.Errorf("%w: %q has scheme %q", ErrInvalidRelayScheme, tag[1], u.Scheme)
			}
			p.Relays = append(p.Relays, tag[1])
		case "endsAt":
			sec, err := strconv.ParseInt(tag[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidEndsAt, tag[1], err)
			}
			t := time.Unix(sec, 0)
			p.EndsAt = &t
		}
	}

	if len(p.Options) < 2 {
		return nil, fmt.Errorf("%w, got %d", ErrTooFewOptions, len(p.Options))
	}

	return p, nil
}

// ValidatePoll checks the signature and structure of a poll event.
func ValidatePoll(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParsePoll(event)
	return err
}

// PollParams describes a NIP-88 poll. Pubkey, Question, and Options are
// required; PollType, Relays, and EndsAt are optional.
type PollParams struct {
	Pubkey   string
	Question string
	Options  []PollOption
	// PollType is PollTypeSingle or PollTypeMultiple. Per spec, an empty
	// value defaults to PollTypeSingle — the "polltype" tag is then omitted
	// rather than written out explicitly.
	PollType string
	Relays   []string
	EndsAt   *time.Time
}

// NewPoll builds an unsigned kind:1068 poll event. Caller must sign it.
func NewPoll(p PollParams) *nip01.Event {
	var tags [][]string
	for _, o := range p.Options {
		tags = append(tags, []string{"option", o.ID, o.Label})
	}
	if p.PollType != "" {
		tags = append(tags, []string{"polltype", p.PollType})
	}
	for _, r := range p.Relays {
		tags = append(tags, []string{"relay", r})
	}
	if p.EndsAt != nil {
		tags = append(tags, []string{"endsAt", strconv.FormatInt(p.EndsAt.Unix(), 10)})
	}

	return nip01.NewUnsignedEvent(KindPoll, p.Pubkey, p.Question, tags...)
}

// PollResponse is a parsed kind:1018 vote event.
type PollResponse struct {
	*nip01.Event
	PollEventID string
	OptionIDs   []string
}

// ParsePollResponse structurally parses a kind:1018 response event. It does
// not check the response against the poll's actual options — that requires
// the original Poll and is done separately by ValidatePollResponse.
func ParsePollResponse(event *nip01.Event) (*PollResponse, error) {
	if event.Kind != KindPollResponse {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindPollResponse)
	}

	eTag, err := utils.FindUniqueEventTagValue(event.Tags, "e")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMissingEventTag, err)
	}
	if err := utils.Validate32Key(eTag); err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrMissingEventTag, eTag, err)
	}

	pr := &PollResponse{Event: event, PollEventID: eTag}
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "response" {
			pr.OptionIDs = append(pr.OptionIDs, tag[1])
		}
	}

	if len(pr.OptionIDs) == 0 {
		return nil, ErrNoResponseTags
	}

	return pr, nil
}

// ValidatePollResponse checks the signature and structure of a response
// event. If poll is non-nil, it additionally verifies every selected option
// exists on the poll and that single-choice polls have exactly one
// response tag.
func ValidatePollResponse(event *nip01.Event, poll *Poll) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	pr, err := ParsePollResponse(event)
	if err != nil {
		return err
	}

	if poll == nil {
		return nil
	}

	if poll.ID != pr.PollEventID {
		return fmt.Errorf("%w: response references %q, expected %q", ErrWrongPoll, pr.PollEventID, poll.ID)
	}

	if poll.PollType == PollTypeSingle && len(pr.OptionIDs) != 1 {
		return fmt.Errorf("%w, got %d", ErrTooManyResponses, len(pr.OptionIDs))
	}

	valid := make(map[string]bool, len(poll.Options))
	for _, o := range poll.Options {
		valid[o.ID] = true
	}
	for _, id := range pr.OptionIDs {
		if !valid[id] {
			return fmt.Errorf("%w: %q", ErrUnknownOption, id)
		}
	}

	return nil
}

// PollResponseParams describes a NIP-88 poll response (vote). All fields
// are required except Relays.
type PollResponseParams struct {
	Pubkey      string
	PollEventID string
	OptionIDs   []string
	Relays      []string
}

// NewPollResponse builds an unsigned kind:1018 response event. Caller must
// sign it.
func NewPollResponse(p PollResponseParams) *nip01.Event {
	tags := [][]string{{"e", p.PollEventID}}
	for _, id := range p.OptionIDs {
		tags = append(tags, []string{"response", id})
	}
	for _, r := range p.Relays {
		tags = append(tags, []string{"relay", r})
	}

	return nip01.NewUnsignedEvent(KindPollResponse, p.Pubkey, "", tags...)
}
