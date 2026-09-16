// Package relayreg declares NIP-34 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-34 auto-declared in its
// NIP-11 document and repository/patch/PR/issue/status/grasp-list events
// auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip34/relayreg"
//
// nip34 itself has no dependency on relay, so pure clients that only
// build/parse git-collaboration events don't pay for relay's bbolt/
// websocket dependency. Replies use NIP-22's kind:1111 comment shape,
// which isn't NIP-34-specific -- blank-import nip22/relayreg alongside
// this package too if the relay should also validate those.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip34"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(34)

	relay.RegisterEventValidator(nip34.KindRepositoryAnnouncement, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidateRepositoryAnnouncement(event)
	})
	relay.RegisterEventValidator(nip34.KindRepositoryState, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidateRepositoryState(event)
	})
	relay.RegisterEventValidator(nip34.KindPatch, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidatePatch(event)
	})
	relay.RegisterEventValidator(nip34.KindPullRequest, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidatePullRequest(event)
	})
	relay.RegisterEventValidator(nip34.KindPullRequestUpdate, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidatePullRequestUpdate(event)
	})
	relay.RegisterEventValidator(nip34.KindIssue, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidateIssue(event)
	})
	relay.RegisterEventValidator(nip34.KindStatusOpen, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidateStatus(event)
	})
	relay.RegisterEventValidator(nip34.KindStatusApplied, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidateStatus(event)
	})
	relay.RegisterEventValidator(nip34.KindStatusClosed, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidateStatus(event)
	})
	relay.RegisterEventValidator(nip34.KindStatusDraft, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidateStatus(event)
	})
	relay.RegisterEventValidator(nip34.KindGraspServerList, func(_ context.Context, event *nip01.Event) error {
		return nip34.ValidateGraspServerList(event)
	})
}
