// Package relayreg declares NIP-90 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-90 auto-declared in its
// NIP-11 document and job-feedback events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip90/relayreg"
//
// nip90 itself has no dependency on relay, so pure clients that only
// build/parse DVM job events don't pay for relay's bbolt/websocket
// dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip90"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(90)

	// KindJobRequest/KindJobResult denote ranges (5000-5999/6000-6999),
	// which relay.RegisterEventValidator cannot express (it validates one
	// kind at a time). Only the single fixed feedback kind is registered
	// here; callers invoke nip90.ParseJobRequest/ValidateJobRequest and
	// nip90.ParseJobResult/ValidateJobResult directly for the ranged kinds.
	relay.RegisterEventValidator(nip90.KindJobFeedback, func(_ context.Context, event *nip01.Event) error {
		return nip90.ValidateJobFeedback(event)
	})
}
