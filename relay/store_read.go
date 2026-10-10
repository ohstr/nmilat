package relay

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
)

// ReadEventsFromStore opens the event store at path and returns every
// stored event matching filters.
func ReadEventsFromStore(parent context.Context, path string, filters *nip01.SubscriptionFilterGroup) ([]*nip01.Event, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	store, err := NewEventStore(path, &nip11.Limitation{})
	if err != nil {
		return nil, err
	}
	defer store.Close()

	query, err := NewStoreQuery(store, filters)
	if err != nil {
		return nil, err
	}

	var events []*nip01.Event
	var wg sync.WaitGroup
	sub, eventsCh, errorsCh, eose := NewSubscription(uuid.NewString(), query)
	go sub.Start(ctx, &wg)
	for {
		select {
		case pe := <-eventsCh:
			event, err := store.FindEvent(pe.Evsid)
			if err != nil {
				return nil, err
			}
			events = append(events, event)
			wg.Done()

		case err := <-errorsCh:
			return nil, err

		case <-eose:
			return events, nil
		}
	}
}
