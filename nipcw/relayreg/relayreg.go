// Package relayreg declares NIP-CW (Circle Wallet) support to a relay engine
// and refuses, at ingest, a kind 30000 follow set dated more than 15 minutes
// in the future (NIP-CW §Membership: a Hub ignores such a version, and its
// relays should reject one). It applies to every kind 30000, since a relay
// cannot tell which follow sets a Hub reads. Blank-import it from a
// relay-embedding binary:
//
//	import _ "github.com/ohstr/nmilat/nipcw/relayreg"
//
// nipcw itself has no dependency on relay.
package relayreg

import (
	"context"
	"errors"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/relay"
)

// ErrFutureFollowSet is the refusal of a kind 30000 dated more than
// nipcw.FollowSetMaxFuture seconds ahead, answered "invalid: created_at too
// far in the future".
var ErrFutureFollowSet = errors.New("created_at too far in the future")

func init() {
	relay.RegisterLetteredNIP("CW")
	relay.RegisterEventValidator(nipcw.KindFollowSet, func(_ context.Context, ev *nip01.Event) error {
		return validate(ev, time.Now())
	})
}

// validate refuses ev when its created_at is after now + FollowSetMaxFuture.
func validate(ev *nip01.Event, now time.Time) error {
	if ev == nil || ev.Kind != nipcw.KindFollowSet {
		return nil
	}
	if ev.CreatedAt > uint64(now.Unix())+nipcw.FollowSetMaxFuture {
		return ErrFutureFollowSet
	}
	return nil
}
