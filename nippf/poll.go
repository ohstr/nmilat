package nippf

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip88"
)

// PollExtras are what NIP-PF adds to a NIP-88 poll: the recommended options
// and the reason, the options that require a note, the expiration. They
// never change how nip88 selects and counts votes.
type PollExtras struct {
	Rec          []string `json:"rec,omitempty"`
	NoteRequired []string `json:"note_required,omitempty"`
	// Why: the poll's one why tag; with more than one, none is read.
	Why        string `json:"why,omitempty"`
	Expiration int64  `json:"expiration,omitempty"`
}

// ParsePollExtras reads a parsed poll's extras; rec and noteRequired tags
// naming no option of the poll are ignored.
func ParsePollExtras(p *nip88.Poll) PollExtras {
	var x PollExtras
	has := func(id string) bool {
		return slices.ContainsFunc(p.Options, func(o nip88.PollOption) bool { return o.ID == id })
	}
	var whys []string
	for _, t := range p.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "rec":
			if has(t[1]) && !slices.Contains(x.Rec, t[1]) {
				x.Rec = append(x.Rec, t[1])
			}
		case "noteRequired":
			if has(t[1]) && !slices.Contains(x.NoteRequired, t[1]) {
				x.NoteRequired = append(x.NoteRequired, t[1])
			}
		case "why":
			whys = append(whys, t[1])
		case "expiration":
			if x.Expiration == 0 {
				x.Expiration, _ = parseUnix(t[1])
			}
		}
	}
	if len(whys) == 1 {
		x.Why = whys[0]
	}
	return x
}

// Tags: the extras as tags, to append to nip88.NewPoll's event.
func (x PollExtras) Tags() [][]string {
	var tags [][]string
	for _, id := range x.Rec {
		tags = append(tags, []string{"rec", id})
	}
	for _, id := range x.NoteRequired {
		tags = append(tags, []string{"noteRequired", id})
	}
	if x.Why != "" {
		tags = append(tags, []string{"why", x.Why})
	}
	if x.Expiration > 0 {
		tags = append(tags, []string{"expiration", strconv.FormatInt(x.Expiration, 10)})
	}
	return tags
}

// VoteNotes: a vote's notes by option id, read from its response tags (the
// ones nip88 counts); notes are never counted.
func VoteNotes(vote *nip01.Event) map[string]string {
	notes := map[string]string{}
	for _, t := range vote.Tags {
		if len(t) >= 3 && t[0] == "response" {
			if n := noteOf(t, 2); n != "" {
				notes[t[1]] = n
			}
		}
	}
	return notes
}

// CheckPollResult reports whether r is a valid result closing the poll: it
// names the poll; decided names existing options, each once, exactly one for
// a singlechoice poll, and no answer; cancelled has no outcome; default isn't
// a poll's.
func CheckPollResult(p *nip88.Poll, r *Result) error {
	if p.ID != "" && r.Form != p.ID {
		return invalidResult("it closes %s, not this poll %s", r.Form, p.ID)
	}
	switch r.Status {
	case StatusDecided:
		if len(r.Answers) > 0 || len(r.Choices) == 0 {
			return invalidResult("a poll's decided result names options, and no answer")
		}
		if p.PollType != nip88.PollTypeMultiple && len(r.Choices) != 1 {
			return invalidResult("a singlechoice poll's result names one option, not %d", len(r.Choices))
		}
		var seen []string
		for _, c := range r.Choices {
			if !slices.ContainsFunc(p.Options, func(o nip88.PollOption) bool { return o.ID == c.Option }) {
				return invalidResult("no option %q in the poll", c.Option)
			}
			if slices.Contains(seen, c.Option) {
				return invalidResult("option %q twice", c.Option)
			}
			seen = append(seen, c.Option)
		}
	case StatusCancelled:
		if len(r.Choices) > 0 || len(r.Answers) > 0 {
			return invalidResult("a cancelled result has no outcome")
		}
	default:
		return invalidResult("a poll's result is decided or cancelled, not %q", r.Status)
	}
	return nil
}

// pollReplyTags: e (the poll), and the poll's expiration and group h tag.
func pollReplyTags(p *nip88.Poll) [][]string {
	tags := [][]string{{"e", p.ID}}
	if x := ParsePollExtras(p); x.Expiration > 0 {
		tags = append(tags, []string{"expiration", strconv.FormatInt(x.Expiration, 10)})
	}
	for _, t := range p.Tags {
		if len(t) >= 2 && t[0] == "h" {
			tags = append(tags, []string{"h", t[1]})
			break
		}
	}
	return tags
}

// NewVote builds author's unsigned NIP-88 vote (kind 1018) on the poll, its
// choices' notes at position 2 of their response tags, with the poll's
// expiration and group. It refuses what nip88 refuses (an unknown option, not
// exactly one for a singlechoice poll), an option twice, and a noteRequired
// option without a note.
func NewVote(p *nip88.Poll, author string, createdAt int64, choices []Choice) (*nip01.Event, error) {
	if !hex64Re.MatchString(p.ID) {
		return nil, fmt.Errorf("%w: the poll has no id", nip88.ErrMissingEventTag)
	}
	x := ParsePollExtras(p)
	var seen []string
	tags := pollReplyTags(p)
	for _, c := range choices {
		if slices.Contains(seen, c.Option) {
			return nil, fmt.Errorf("%w: option %q twice", nip88.ErrUnknownOption, c.Option)
		}
		seen = append(seen, c.Option)
		note := noteOf([]string{c.Note}, 0)
		if note == "" && slices.Contains(x.NoteRequired, c.Option) {
			return nil, fmt.Errorf("nippf: option %q requires a note", c.Option)
		}
		if note != "" {
			tags = append(tags, []string{"response", c.Option, note})
		} else {
			tags = append(tags, []string{"response", c.Option})
		}
	}
	ev := nip01.NewUnsignedEvent(KindVote, author, "", tags...)
	ev.CreatedAt = uint64(createdAt)
	pr, err := nip88.ParsePollResponse(ev)
	if err != nil {
		return nil, err
	}
	if pr.PollEventID != p.ID {
		return nil, nip88.ErrWrongPoll
	}
	if p.PollType == nip88.PollTypeSingle && len(pr.OptionIDs) != 1 {
		return nil, nip88.ErrTooManyResponses
	}
	for _, id := range pr.OptionIDs {
		if !slices.ContainsFunc(p.Options, func(o nip88.PollOption) bool { return o.ID == id }) {
			return nil, fmt.Errorf("%w: %q", nip88.ErrUnknownOption, id)
		}
	}
	return ev, nil
}

// NewPollResult builds the poll author's unsigned result closing it: e, the
// poll's expiration and group, the status and the options. It is read back
// and checked before it is returned.
func NewPollResult(p *nip88.Poll, createdAt int64, status, content string, options []string) (*nip01.Event, error) {
	if !hex64Re.MatchString(p.ID) {
		return nil, invalidResult("the poll has no id")
	}
	tags := pollReplyTags(p)
	tags = append(tags, []string{"status", status})
	for _, id := range options {
		tags = append(tags, []string{"response", id})
	}
	ev := nip01.NewUnsignedEvent(KindResult, p.PubKey, content, tags...)
	ev.CreatedAt = uint64(createdAt)
	r, err := ParseResult(ev)
	if err != nil {
		return nil, err
	}
	if err := CheckPollResult(p, r); err != nil {
		return nil, err
	}
	return ev, nil
}

// ClosingPollResult: the poll's closing result — the earliest valid result by
// the poll's author, ties to the lowest id; nil when there is none.
func ClosingPollResult(p *nip88.Poll, results []*Result) *Result {
	return earliest(results, p.PubKey, func(r *Result) bool { return CheckPollResult(p, r) == nil })
}

// PollState: the poll's state at now, given its closing result.
func PollState(p *nip88.Poll, closing *Result, now int64) State {
	var ends int64
	if p.EndsAt != nil {
		ends = p.EndsAt.Unix()
	}
	return StateAt(ends, ParsePollExtras(p).Expiration, closing, now)
}
