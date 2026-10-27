package nipcw

import (
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// KindFollowSet is NIP-51's follow set, the follow_set policy's membership source.
const KindFollowSet = 30000

// followSetFuture is how far ahead of now a version may be dated: 15 minutes.
const followSetFuture = 900

// FollowSetAddress names a follow set: its author (the provider) and its d.
type FollowSetAddress struct{ Provider, D string }

// Resolution is a successful resolution of a follow set: the winning version and
// the members it names. Title is the version's title, display-only: never read
// for membership or terms, only offered as the default circlehub1 label.
type Resolution struct {
	EventID   string
	CreatedAt int64
	Members   map[string]bool
	Title     string
}

// ResolveFollowSet resolves addr from fetched events (NIP-CW §Membership). Only a
// kind-30000 event by addr.Provider whose first d tag is addr.D and whose
// signature verifies counts; one dated more than 15 minutes after now is
// ignored. The highest created_at wins, a tie going to the lowest id.
//
// Members are the public p tags holding 64 lowercase hex, plus each hidden_p
// entry that decrypts under one of inboxPrivs (current and retired inbox keys)
// to 64 lowercase hex; nothing else is read, a relay hint in a p tag included.
// A deletion (kind 5) and every other kind are ignored.
//
// It returns (resolution, true) on success. With no eligible version, or with a
// newest version older than last (Q21), the refresh failed: it returns (last,
// false), last staying in force. A resolved set with no members is empty, not
// unresolved.
func ResolveFollowSet(events []*nip01.Event, addr FollowSetAddress, inboxPrivs []string, now time.Time, last *Resolution) (*Resolution, bool) {
	var win *nip01.Event
	limit := now.Unix() + followSetFuture
	for _, ev := range events {
		if ev == nil || ev.Kind != KindFollowSet || ev.PubKey != addr.Provider || int64(ev.CreatedAt) > limit || ev.CreatedAt > 1<<62 {
			continue
		}
		if d := tagValues(ev, "d"); len(d) == 0 || d[0] != addr.D {
			continue
		}
		if ev.Verify(nip01.WithoutPowCheck()) != nil {
			continue
		}
		if win == nil || ev.CreatedAt > win.CreatedAt || (ev.CreatedAt == win.CreatedAt && ev.ID < win.ID) {
			win = ev
		}
	}
	if win == nil {
		return last, false
	}
	if last != nil {
		if int64(win.CreatedAt) < last.CreatedAt {
			return last, false
		}
		if int64(win.CreatedAt) == last.CreatedAt && last.EventID != "" && last.EventID < win.ID {
			return last, true
		}
	}
	r := &Resolution{EventID: win.ID, CreatedAt: int64(win.CreatedAt), Members: map[string]bool{}}
	if t := tagValues(win, "title"); len(t) > 0 {
		r.Title = t[0]
	}
	for _, p := range tagValues(win, "p") {
		if isLowerHex64(p) {
			r.Members[p] = true
		}
	}
	for _, payload := range tagValues(win, "hidden_p") {
		for _, inbox := range inboxPrivs {
			if m, err := DecryptHiddenMember(inbox, addr.Provider, payload); err == nil {
				r.Members[m] = true
				break
			}
		}
	}
	return r, true
}
