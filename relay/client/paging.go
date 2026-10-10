package client

import (
	"context"
	"errors"
	"net/url"

	"github.com/ohstr/nmilat/nip01"
)

// defaultPageSize is the page size when a caller passes none.
const defaultPageSize = 500

// ReadAllEventsFromRelay reads every event matching filter, newest first,
// in pages of pageSize, walking back with until. Each page resumes after
// the last event of the one before: nmilat relays honor BeforeID, so
// events sharing a second are never skipped; on other relays a page that
// brings nothing new steps until back one second, which can skip events
// tied on that second beyond one page. Events are deduplicated by id.
// signer answers NIP-42 AUTH; nil reads anonymously. restricted reports a
// relay that refused a page for want of authentication; what was read
// before it is returned. filter's own Until and Limit are a starting point
// and a total cap.
func ReadAllEventsFromRelay(ctx context.Context, relayURL *url.URL, filter *nip01.SubscriptionFilter, pageSize int, signer Signer) (events []*nip01.Event, restricted bool, err error) {
	if filter == nil {
		return nil, false, errors.New("paging: filter is required")
	}
	pg := newPager(filter, pageSize)
	for f := pg.next(); f != nil; f = pg.next() {
		got, restricted, err := ReadEventsFromRelayWithSigner(ctx, relayURL, nip01.NewSubscriptionFilterGroup(f), signer)
		if err != nil || restricted {
			return events, restricted, err
		}
		events = append(events, pg.feed(got)...)
	}
	return events, false, nil
}

// pager walks one filter back page by page; see ReadAllEventsFromRelay
// for the cursor rules.
type pager struct {
	page     nip01.SubscriptionFilter
	total    int
	pageSize int
	seen     map[string]bool
	count    int
	stepped  bool
	done     bool
}

func newPager(filter *nip01.SubscriptionFilter, pageSize int) *pager {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	page := *filter
	page.BeforeID = ""
	return &pager{page: page, total: filter.Limit, pageSize: pageSize, seen: map[string]bool{}}
}

// next returns the filter for the next page, or nil once the walk is done.
func (p *pager) next() *nip01.SubscriptionFilter {
	if p.done {
		return nil
	}
	f := p.page
	f.Limit = p.pageSize
	if p.total > 0 {
		remaining := p.total - p.count
		if remaining <= 0 {
			p.done = true
			return nil
		}
		f.Limit = min(p.pageSize, remaining)
	}
	return &f
}

// feed takes one page as the relay sent it, newest first, moves the
// cursor, and returns the events not seen before.
func (p *pager) feed(got []*nip01.Event) []*nip01.Event {
	if len(got) == 0 {
		p.done = true
		return nil
	}
	var fresh []*nip01.Event
	for _, ev := range got {
		if p.seen[ev.ID] {
			continue
		}
		p.seen[ev.ID] = true
		fresh = append(fresh, ev)
	}
	p.count += len(fresh)

	last := got[len(got)-1]
	if len(fresh) == 0 {
		// The relay ignored BeforeID and served the same tie again.
		if p.stepped || last.CreatedAt == 0 {
			p.done = true
			return nil
		}
		p.page.Until, p.page.BeforeID = last.CreatedAt-1, ""
		p.stepped = true
		return nil
	}
	p.stepped = false
	p.page.Until, p.page.BeforeID = last.CreatedAt, last.ID
	return fresh
}
