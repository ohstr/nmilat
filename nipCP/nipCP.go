// Package nipCP implements NIP-CP (Cash Pocket): the cash tokens a wallet holds,
// and the bill-creating calls it has in flight, kept as kind 9525 rumors
// gift-wrapped to the user's own pubkey.
//
// An Entry is one rumor. Seal wraps it under a wrap key generated first and
// recorded in the entry; Open unwraps one, keeping only the user's own 9525s.
// Resolve picks the current entry per w; Balance sums the live ones per chain.
//
// Writing follows NIP-CP §Writing: PendingEntry is the entry written ahead of a
// call (PocketJournal does it for nipcash/client, reading it back before the
// call is sent); ApplyResult, ApplyLookup, ApplyOrder and ApplyWithdraw turn a
// reply or lookup into the entries to write and the batch that closes the call;
// Close, WithdrawDoneRewrite and DeletionFor close, trim and supersede entries. MapStatus maps a status answer to a
// state, final only when the answer is definitive.
//
// Spec: https://github.com/ohstr/nips/blob/main/NIP-CP.md
package nipCP

import "errors"

// KindPocketEntry is a Pocket Entry. It is a rumor: never signed, and published
// only inside a seal and gift wrap.
const KindPocketEntry = 9525

var (
	// ErrEntry is an entry, or a 9525 rumor, that breaks NIP-CP §Kind 9525.
	ErrEntry = errors.New("nipCP: malformed pocket entry")
	// ErrNotEntry is a wrap that is not one of the user's own pocket entries (a
	// DM, another key's seal, a signed or foreign 9525). A sync discards it.
	ErrNotEntry = errors.New("nipCP: not one of the user's pocket entries")
	// ErrMethod is a call PendingEntry cannot write ahead.
	ErrMethod = errors.New("nipCP: no pending entry for this method")
	// ErrNotPending is an operation that needs an open pending entry.
	ErrNotPending = errors.New("nipCP: the entry is not an open pending entry")
	// ErrLookup is an outcome that leaves the call pending: look it up with
	// cash_lookup, and never resend it.
	ErrLookup = errors.New("nipCP: the call stays pending; look it up")
	// ErrNotStored is a wrap fewer relays returned than Store requires.
	ErrNotStored = errors.New("nipCP: the wrap was not read back from enough relays")
)
