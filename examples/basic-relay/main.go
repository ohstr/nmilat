// Command basic-relay is the minimal way to embed nmilat: relay.New opens
// an event store, wires up a session handler with NIP-11 negotiation, and
// starts profile verification -- search stays disabled. relay.Relay is
// just an http.Handler, so the embedder owns the listener.
//
// Blank-importing a relayreg subpackage is how an optional NIP declares
// itself: without the two imports below, this relay still works, it just
// won't advertise or validate zap/relay-list events. Core NIP-01 handling
// (NIP-09/16/33/40/77) and anything that turns on from SessionConfig
// (NIP-42/43/AA/26/50) need no relayreg import at all.
package main

import (
	"log"
	"net/http"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay"

	_ "github.com/ohstr/nmilat/nip57/relayreg"
	_ "github.com/ohstr/nmilat/nip65/relayreg"
)

func main() {
	metadata := &nip11.Metadata{
		Name:       "my-relay",
		Limitation: nip11.Limitation{MaxLimit: 1000, MaxMessageLength: 1024 * 1024},
	}

	rl, err := relay.New("relay.db", metadata)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = rl.Close() }()

	log.Fatal(http.ListenAndServe(":8080", rl))
}
