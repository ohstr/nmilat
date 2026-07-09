package client

import (
	"context"
	"net/url"
	"sync"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/wire"
)

func ReadEventsFromStore(parent context.Context, path string, filters *nip01.SubscriptionFilterGroup) ([]*nip01.Event, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	store, err := relay.NewEventStore(path, &nip11.Limitation{})
	if err != nil {
		return nil, err
	}
	defer store.Close()

	query, err := relay.NewStoreQuery(store, filters)
	if err != nil {
		return nil, err
	}

	var events []*nip01.Event
	var wg sync.WaitGroup
	sub, eventsCh, errorsCh, eose := relay.NewSubscription(uuid.NewString(), query)
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

func ReadEventsFromRelay(parent context.Context, relayURL *url.URL, filters *nip01.SubscriptionFilterGroup) ([]*nip01.Event, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	conn, err := Connect(ctx, relayURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, eventsCh, _ := conn.Subscribe(filters)
	var events []*nip01.Event

	for {
		select {
		case ev, ok := <-eventsCh:
			if !ok {
				return events, nil
			}
			events = append(events, ev.Event)

		case err := <-conn.errors:
			return nil, err
		}
	}
}

// PublishEventToRelay dials relayURL, publishes ev, and waits for the
// relay's OK response, closing the connection afterward. This is the
// one-shot form for a single publish; for multiple publishes over one
// connection, dial with NewConnection and call Publish directly.
func PublishEventToRelay(ctx context.Context, relayURL *url.URL, ev *nip01.Event) (*wire.OkSubscriptionResponse, error) {
	conn, err := Connect(ctx, relayURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.Publish(ctx, ev)
}
