// Package relayreg declares NIP-47 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-47 auto-declared in its
// NIP-11 document:
//
//	import _ "github.com/ohstr/nmilat/nip47/relayreg"
//
// nip47 itself has no dependency on relay, so pure clients that only
// build/parse NWC events don't pay for relay's bbolt/websocket dependency.
package relayreg

import "github.com/ohstr/nmilat/relay"

func init() {
	relay.RegisterNIP(47)
}
