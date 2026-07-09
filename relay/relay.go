// Package relay is an embeddable Nostr relay engine: event storage
// (EventStore), WebSocket session handling (SessionHandler), NIP-11
// negotiation, and a plugin registration mechanism (RegisterNIP /
// RegisterEventValidator) that NIP packages use to declare relay support
// without the relay package needing to import them. relay/client provides
// the corresponding client-side connection.
package relay

import (
	"net/http"

	"github.com/ohstr/nmilat/nip11"
)

// defaultVerificationWorkerCount is the number of concurrent NIP-05/LUD-16
// verification workers New starts. Profile verification makes outbound HTTP
// calls, so this is kept modest rather than scaling with CPU count.
const defaultVerificationWorkerCount = 4

// New opens an event store at path and returns a ready-to-serve relay
// (NIP-11 negotiation included, search disabled). This is the fast path for
// "just run a relay" — for storage tuning, a search service, or session
// options, build the store and handler directly with NewEventStore and
// NewSessionHandler.
func New(path string, metadata *nip11.Metadata) (*Relay, error) {
	store, err := NewEventStore(path, &metadata.Limitation)
	if err != nil {
		return nil, err
	}

	handler := NewSessionHandler(store, metadata, nil)
	handler.VerificationWorker.Start(defaultVerificationWorkerCount)

	return &Relay{store: store, handler: handler}, nil
}

// Relay is an http.Handler; pass it straight to http.ListenAndServe.
type Relay struct {
	store   *EventStore
	handler *SessionHandler
}

func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.handler.ServeHTTP(w, req)
}

// Close stops the verification worker and closes the underlying event store.
func (r *Relay) Close() error {
	r.handler.VerificationWorker.Stop()
	r.store.Close()
	return nil
}
