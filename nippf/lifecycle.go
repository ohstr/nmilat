package nippf

import "sort"

// State of a form or a poll.
type State string

// States.
const (
	StateOpen      State = "open"
	StateEnded     State = "ended"
	StateDecided   State = "decided"
	StateDefault   State = "default"
	StateCancelled State = "cancelled"
	StateExpired   State = "expired"
)

// Closed reports whether a client shows the form as closed: ended, or closed
// by a result (decided, default, cancelled).
func (s State) Closed() bool { return s != StateOpen && s != StateExpired }

// StateAt: the state at now (unix seconds) of a form or poll with these
// endsAt and expiration (0: absent) and its closing result (nil: none).
// expired overrides the others; a time "passes" once now is after it.
func StateAt(endsAt, expiration int64, closing *Result, now int64) State {
	switch {
	case expiration > 0 && now > expiration:
		return StateExpired
	case closing != nil:
		return State(closing.Status)
	case endsAt > 0 && now > endsAt:
		return StateEnded
	}
	return StateOpen
}

// State: the form's state at now, given its closing result (Closing).
func (f *Form) State(closing *Result, now int64) State {
	return StateAt(f.EndsAt, f.Expiration, closing, now)
}

// Select: the response kept per pubkey the form allows — of its valid
// responses and withdrawals created not later than endsAt and the closing
// result's created_at, the one with the largest created_at (ties to the
// lowest id); a pubkey whose kept one is a withdrawal has no response.
// Responses must be authentic (a signature verified, or a rumor from Open);
// invalid ones and other forms' are ignored. The result is ordered by
// created_at, then id.
func (f *Form) Select(responses []*Response, closing *Result) []*Response {
	kept := map[string]*Response{}
	for _, r := range responses {
		if r == nil || !f.Allowed(r.Author) || f.Check(r) != nil {
			continue
		}
		if f.EndsAt > 0 && r.CreatedAt > f.EndsAt {
			continue
		}
		if closing != nil && r.CreatedAt > closing.CreatedAt {
			continue
		}
		k := kept[r.Author]
		if k == nil || r.CreatedAt > k.CreatedAt || (r.CreatedAt == k.CreatedAt && r.ID < k.ID) {
			kept[r.Author] = r
		}
	}
	out := make([]*Response, 0, len(kept))
	for _, r := range kept {
		if !r.Withdrawal() {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Note is a note by a responder.
type Note struct {
	PubKey string `json:"pubkey"`
	Text   string `json:"text"`
}

// AnswerBy is an answer by a responder.
type AnswerBy struct {
	PubKey string `json:"pubkey"`
	Value  string `json:"value"`
	Note   string `json:"note,omitempty"`
}

// QuestionTally is one question's tally: the selected responses per option
// (every option listed, 0 included), the notes per option, the answers.
type QuestionTally struct {
	Index   int               `json:"index"`
	Counts  map[string]int    `json:"counts,omitempty"`
	Notes   map[string][]Note `json:"notes,omitempty"`
	Answers []AnswerBy        `json:"answers,omitempty"`
}

// Tally of a form's selected responses.
type Tally struct {
	// Responses: how many pubkeys have a selected response.
	Responses int             `json:"responses"`
	Questions []QuestionTally `json:"questions"`
	// QuorumMet: Responses reaches the form's quorum (always, without one).
	QuorumMet bool `json:"quorum_met"`
}

// Tally counts the selected responses (Select's) per question.
func (f *Form) Tally(selected []*Response) *Tally {
	t := &Tally{Responses: len(selected), QuorumMet: len(selected) >= f.Quorum}
	byIndex := map[int]*QuestionTally{}
	for _, q := range f.Questions {
		qt := QuestionTally{Index: q.Index}
		if len(q.Options) > 0 {
			qt.Counts = map[string]int{}
			for _, o := range q.Options {
				qt.Counts[o.ID] = 0
			}
		}
		t.Questions = append(t.Questions, qt)
	}
	for i := range t.Questions {
		byIndex[t.Questions[i].Index] = &t.Questions[i]
	}
	for _, r := range selected {
		for _, c := range r.Choices {
			_, q, ok := f.Option(c.Option)
			if !ok {
				continue
			}
			qt := byIndex[q.Index]
			qt.Counts[c.Option]++
			if c.Note != "" {
				if qt.Notes == nil {
					qt.Notes = map[string][]Note{}
				}
				qt.Notes[c.Option] = append(qt.Notes[c.Option], Note{PubKey: r.Author, Text: c.Note})
			}
		}
		for _, a := range r.Answers {
			if qt := byIndex[a.Question]; qt != nil {
				qt.Answers = append(qt.Answers, AnswerBy{PubKey: r.Author, Value: a.Value, Note: a.Note})
			}
		}
	}
	return t
}
