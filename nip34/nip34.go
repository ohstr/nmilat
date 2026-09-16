// Package nip34 implements NIP-34: git stuff — code collaboration over
// Nostr, covering:
//
//   - Repository announcements (kind 30617) and repository state (kind
//     30618), both addressable events (repository.go)
//   - Patches (kind 1617) (patch.go)
//   - Pull requests (kind 1618) and PR updates (kind 1619) (pullrequest.go)
//   - Issues (kind 1621) (issue.go)
//   - Replies to issues/patches/PRs, which follow NIP-22's kind:1111
//     comment shape (reply.go, built on the nip22 package)
//   - Status events for patches/PRs/issues (kind 1630-1633), including
//     ResolveStatus and ResolveRevisionStatus, which implement the spec's
//     status-resolution rules (status.go)
//   - User grasp lists (kind 10317) (graspset.go)
//   - The "nostr://" git clone URL scheme (clone_url.go)
//
// This package is a pure protocol library: event/type construction,
// parsing, and validation, with no relay or network dependency of its own.
// Publishing/subscribing is left to the generic nip01/relay-client
// plumbing already in this SDK — there is no nip34/client subpackage,
// since (unlike e.g. nipB7's Blossom HTTP servers) NIP-34 has no second
// transport of its own to dial out to. For declaring NIP-34 support to
// nmilat's relay engine, see the nip34/relayreg subpackage.
package nip34

import "errors"

const (
	KindRepositoryAnnouncement = 30617
	KindRepositoryState        = 30618
	KindPatch                  = 1617
	KindPullRequest            = 1618
	KindPullRequestUpdate      = 1619
	KindIssue                  = 1621
	KindStatusOpen             = 1630 // default status for a root patch/PR/issue
	KindStatusApplied          = 1631 // Applied/Merged for patches/PRs; Resolved for issues
	KindStatusClosed           = 1632
	KindStatusDraft            = 1633
	KindGraspServerList        = 10317
)

// IsStatusKind reports whether kind is one of the four NIP-34 status kinds
// (1630-1633).
func IsStatusKind(kind int) bool {
	switch kind {
	case KindStatusOpen, KindStatusApplied, KindStatusClosed, KindStatusDraft:
		return true
	default:
		return false
	}
}

// Failure modes shared by more than one file in this package, for callers
// that need to distinguish them (e.g. via errors.Is) rather than match on
// message text. Failure modes specific to a single event type are declared
// alongside that type instead.
var (
	ErrWrongKind          = errors.New("nip34: wrong kind")
	ErrInvalidSignature   = errors.New("nip34: invalid signature")
	ErrMissingIdentifier  = errors.New("nip34: missing d tag identifier")
	ErrInvalidRepoAddress = errors.New("nip34: invalid a tag repository address")
	ErrInvalidPubkeyTag   = errors.New("nip34: invalid pubkey tag")
	ErrInvalidEventTag    = errors.New("nip34: invalid event id tag")
)
