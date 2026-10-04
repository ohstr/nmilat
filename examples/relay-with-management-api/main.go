// Command relay-with-management-api shows the pattern this SDK is built
// around: nmilat ships independent http.Handlers (relay.SessionHandler,
// nip86.Handler, relay.NewQueryHandler, huddle/wsaudio's handler) and
// leaves composing them to the embedder -- there is no router or mux
// inside nmilat itself. ncli does exactly this internally to serve both
// the Nostr relay socket and its NIP-86 relay-management API from one
// process; this is that pattern as a standalone, copyable example.
//
// All three handlers share the same *relay.EventStore, mounted at
// different paths on one http.ServeMux:
//   - "/"       -- the Nostr relay: NIP-11 info document and WebSocket upgrade
//   - "/admin"  -- the NIP-86 relay management API, NIP-98-authenticated
//   - "/query"  -- a NIP-98-authenticated HTTP bridge: POST a JSON array of
//     NIP-01 filters, get back the matching events as a flat JSON array --
//     a one-shot alternative to a WebSocket REQ/EOSE round trip
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip86"
	"github.com/ohstr/nmilat/relay"
)

// adminPubkey is the one pubkey allowed to call the management API below.
// nip86.Handler refuses everyone if this list is empty, rather than
// defaulting to open -- an operator who configures no admin gets a closed
// endpoint, not an accidental one.
const adminPubkey = "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"

func main() {
	metadata := &nip11.Metadata{
		Name:       "my-relay",
		Limitation: nip11.Limitation{MaxLimit: 1000, MaxMessageLength: 1024 * 1024},
	}

	store, err := relay.NewEventStore("relay.db", &metadata.Limitation)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	relayHandler := relay.NewSessionHandler(store, metadata, nil)
	relayHandler.VerificationWorker.Start(4)
	defer relayHandler.VerificationWorker.Stop()

	router := nip86.NewRouter()
	router.Handle(nip86.MethodSupportedMethods, func(_ context.Context, caller string, _ nip86.Request) (any, error) {
		return router.MethodsFor(caller), nil
	})

	adminHandler := nip86.NewHandler(nip86.Config{
		Router:         router,
		AllowedPubkeys: []string{adminPubkey},
	})

	mux := http.NewServeMux()
	mux.Handle("/", relayHandler)
	mux.Handle("/admin", adminHandler)
	mux.Handle("/query", relay.NewQueryHandler(store))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
