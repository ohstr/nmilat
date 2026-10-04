// Command full-relay is the "build it yourself" path relay.New's one-liner
// doesn't expose: a store and a session handler built directly from
// relay.NewEventStore / relay.NewSessionHandler, tuned with functional
// options, logging to stderr instead of the silent default (relay never
// logs to a package-global logger -- nothing is written anywhere unless an
// embedder opts in via WithLogger/WithEventStoreLogger).
//
// Reach for this over examples/basic-relay when the embedder needs control
// relay.New doesn't give it: a CORS allowlist, more/fewer store workers,
// NIP-AA agent auth, or (as in examples/relay-with-management-api) a
// second http.Handler sharing the same *relay.EventStore.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay"

	_ "github.com/ohstr/nmilat/nip29/relayreg"
	_ "github.com/ohstr/nmilat/nip57/relayreg"
)

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()

	metadata := &nip11.Metadata{
		Name:       "my-relay",
		Limitation: nip11.Limitation{MaxLimit: 1000, MaxMessageLength: 1024 * 1024},
	}

	store, err := relay.NewEventStore("relay.db", &metadata.Limitation,
		relay.WithEventStoreLogger(logger),
		relay.WithEventStoreWorkerCount(8),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	handler := relay.NewSessionHandler(store, metadata, nil,
		relay.WithLogger(logger),
		relay.WithSessionAllowedOrigins("https://my-client.example"),
		relay.WithSessionAgentAuth(true, 5*time.Minute, true),
	)
	handler.VerificationWorker.Start(4)
	defer handler.VerificationWorker.Stop()

	log.Fatal(http.ListenAndServe(":8080", handler))
}
