package client

import (
	"context"
	"errors"
	"net/url"

	"github.com/ohstr/nmilat/nip01"
)

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
	if pageSize <= 0 {
		pageSize = 500
	}
	total := filter.Limit
	seen := map[string]bool{}
	page := *filter
	page.BeforeID = ""
	stepped := false

	for {
		if total > 0 {
			remaining := total - len(events)
			if remaining <= 0 {
				return events, false, nil
			}
			page.Limit = min(pageSize, remaining)
		} else {
			page.Limit = pageSize
		}
		f := page
		got, restricted, err := ReadEventsFromRelayWithSigner(ctx, relayURL, nip01.NewSubscriptionFilterGroup(&f), signer)
		if err != nil || restricted {
			return events, restricted, err
		}
		if len(got) == 0 {
			return events, false, nil
		}

		fresh := 0
		for _, ev := range got {
			if seen[ev.ID] {
				continue
			}
			seen[ev.ID] = true
			events = append(events, ev)
			fresh++
		}

		// Relays send newest first, so the last event is the cursor.
		last := got[len(got)-1]
		if fresh == 0 {
			// The relay ignored BeforeID and served the same tie again.
			if stepped || last.CreatedAt == 0 {
				return events, false, nil
			}
			page.Until, page.BeforeID = last.CreatedAt-1, ""
			stepped = true
			continue
		}
		stepped = false
		page.Until, page.BeforeID = last.CreatedAt, last.ID
	}
}
