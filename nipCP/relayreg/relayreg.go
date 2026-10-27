// Package relayreg declares NIP-CP (Cash Pocket) support to a relay engine and
// refuses every kind 9525 event at ingest: a Pocket Entry is a rumor, never
// signed, and travels only inside a seal and gift wrap, so a 9525 offered to a
// relay is one leaked outside it. Blank-import it from a relay-embedding binary:
//
//	import _ "github.com/ohstr/nmilat/nipCP/relayreg"
//
// nipCP itself has no dependency on relay.
package relayreg

import (
	"context"
	"errors"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCP"
	"github.com/ohstr/nmilat/relay"
)

// ErrBareEntry is the refusal of a kind 9525 offered to the relay.
var ErrBareEntry = errors.New("kind 9525 travels only inside a gift wrap")

func init() {
	relay.RegisterLetteredNIP("CP")
	relay.RegisterEventValidator(nipCP.KindPocketEntry, func(context.Context, *nip01.Event) error {
		return ErrBareEntry
	})
}
