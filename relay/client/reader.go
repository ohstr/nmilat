package client

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

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

		case <-ctx.Done():
			// Without this case, a relay that accepts the REQ but never
			// sends EOSE or an error hangs this call forever: parent's
			// cancellation only reached here indirectly before, via
			// Connection.handle's write goroutine closing the socket and
			// turning that into a conn.errors send -- a round trip through
			// a forced disconnect instead of an immediate return.
			return nil, ctx.Err()
		}
	}
}

// authRetryWindow bounds how long ReadEventsFromRelayWithAuth waits for a
// NIP-42 handshake to resolve before retrying a subscription the relay
// closed as restricted. It only ever comes into play after an actual
// "restricted: ..." CLOSED (this relay's own wording for its NIP-42/
// NIP-43 gates, in processRequest) -- an open relay's calls never hit it.
// A var, not a const, so tests can shrink it instead of waiting out the
// real window.
var authRetryWindow = 5 * time.Second

// restrictedClosePrefix is the message prefix this relay's processRequest
// uses for every CLOSED it sends for an auth/membership/group-privacy
// gate -- see relay/packet.go's processRequest and
// deniedPrivateGroupFilter. Matched as a prefix, not an exact restriction
// list, so this stays correct if the relay adds another gate under the
// same convention without this package needing to know its exact wording.
const restrictedClosePrefix = "restricted:"

// ReadEventsFromRelayWithAuth is ReadEventsFromRelay's counterpart for a
// caller that has (or might have) an identity to authenticate with.
// signingKeyHex empty behaves exactly like ReadEventsFromRelay -- no
// behavior change for a caller that passes no identity.
//
// Given a key, the connection answers a NIP-42 challenge on its own
// (ConnectionConfig.SigningKeyHex). The very first subscription attempt is
// usually sent before that handshake's own round trip finishes -- REQ and
// the relay's AUTH challenge cross on the wire independently -- so a
// restricted relay's expected response to that first attempt is its own
// "restricted: ..." CLOSED, not a silent empty result. Only on exactly
// that response does this wait (bounded by authRetryWindow) for the
// handshake to settle and retry the same filters once. An open relay never
// sends that CLOSED, so it never waits at all, identity configured or not.
//
// A real relay has been observed sending a WS close frame while this wait
// is in flight (root cause not pinned down -- a session-cleanup race on
// the relay's side is one candidate, but it doesn't matter here: the
// client has to cope with it regardless of origin). Earlier, nothing read
// Connection.Errors()/Closed() during the wait, so handle()'s read loop
// sat blocked trying to report the close (its errors<- send has no other
// escape hatch once ctx isn't done and nobody's listening), and the
// connection surfaced as already-dead only once the retry's own
// subscribeOnce ran into it -- every authenticated read of a
// private/restricted target failed this way, deterministically, since
// the retry had no fallback for a connection that died instead of a
// handshake that simply never resolved. Watching for it here instead
// redials and re-authenticates once before retrying, the same way the
// restricted-CLOSED case above gets one retry rather than being treated
// as terminal.
//
// restricted reports whether the final attempt -- whichever one actually
// produced events/err -- ended via a "restricted: ..." CLOSED rather than
// a normal EOSE, so a caller can tell "nothing matched" apart from "the
// relay refused this query" instead of both reading as an empty result.
// signingKeyHex == "" delegates straight to ReadEventsFromRelay, which
// has no such signal to report, so restricted is always false there.
func ReadEventsFromRelayWithAuth(parent context.Context, relayURL *url.URL, filters *nip01.SubscriptionFilterGroup, signingKeyHex string) (events []*nip01.Event, restricted bool, err error) {
	if signingKeyHex == "" {
		events, err = ReadEventsFromRelay(parent, relayURL, filters)
		return events, false, err
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	conn, err := NewConnection(ctx, relayURL, &ConnectionConfig{SigningKeyHex: signingKeyHex})
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()

	events, restricted, err = subscribeOnce(ctx, conn, filters)
	if err != nil || !restricted {
		return events, restricted, err
	}

	select {
	case <-conn.AuthSettled():
	case <-time.After(authRetryWindow):
	case <-conn.Errors():
		conn, err = redialAndWaitForAuth(ctx, relayURL, signingKeyHex)
		if err != nil {
			return nil, false, err
		}
		defer conn.Close()
	case <-conn.Closed():
		conn, err = redialAndWaitForAuth(ctx, relayURL, signingKeyHex)
		if err != nil {
			return nil, false, err
		}
		defer conn.Close()
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}

	events, restricted, err = subscribeOnce(ctx, conn, filters)
	return events, restricted, err
}

// redialAndWaitForAuth dials relayURL fresh and waits out authRetryWindow
// for its own handshake to settle -- for ReadEventsFromRelayWithAuth to
// call once it notices its original connection died mid-wait. Dialing
// fresh re-runs the whole handshake from scratch, which a dead connection
// needs regardless of why it died; the caller is responsible for closing
// the connection this returns (on success, it's a live connection the
// caller still needs for its own retry).
func redialAndWaitForAuth(ctx context.Context, relayURL *url.URL, signingKeyHex string) (*Connection, error) {
	conn, err := NewConnection(ctx, relayURL, &ConnectionConfig{SigningKeyHex: signingKeyHex})
	if err != nil {
		return nil, err
	}

	select {
	case <-conn.AuthSettled():
	case <-time.After(authRetryWindow):
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}

	return conn, nil
}

// subscribeOnce drives one REQ/EOSE round trip over conn (already dialed)
// and reports whether it ended via a CLOSED citing a restriction rather
// than a normal EOSE or a connection close -- the signal
// ReadEventsFromRelayWithAuth retries on.
func subscribeOnce(ctx context.Context, conn *Connection, filters *nip01.SubscriptionFilterGroup) (events []*nip01.Event, restricted bool, err error) {
	subID := uuid.NewString()
	if !conn.SubscribeWithID(subID, filters) {
		return nil, false, ErrConnectionClosed
	}
	defer conn.CloseSubscription(subID)

	for {
		select {
		case res, ok := <-conn.Read():
			if !ok {
				return events, false, nil
			}
			switch m := res.(type) {
			case *wire.EventSubscriptionResponse:
				if m.SubscriptionID == subID {
					events = append(events, m.Event)
				}
			case *wire.EOSESubscriptionResponse:
				if m.SubscriptionID == subID {
					return events, false, nil
				}
			case *wire.ClosedSubscriptionResponse:
				if m.SubscriptionID == subID {
					return events, strings.HasPrefix(m.Message, restrictedClosePrefix), nil
				}
			}

		case err := <-conn.errors:
			return nil, false, err

		case <-ctx.Done():
			return nil, false, ctx.Err()
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
