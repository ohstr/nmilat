package nipCP

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/utils"
)

// PocketJournal writes calls ahead into the user's Cash Pocket: it implements
// nipcash/client.Journal (NIP-CP §Writing, write ahead). WriteAhead seals each
// call's pending entry, stores it on the wrap relays and reads it back before
// returning; a call written again (the send path rewrites it with its exact
// deadline) is a change: the next rev, then a deletion of the previous wrap.
// The derived-id record is the DeviceStore's.
type PocketJournal struct {
	UserPriv string
	Relays   []string
	IO       Relays
	Device   DeviceStore
	// Chain fills a call's chain when the call carries none.
	Chain string
	// Entries are the entries the last sync found (for the next rev of a w).
	Entries []Entry

	mu      sync.Mutex
	written map[string]Entry
	pending []*nip01.Event
}

var _ client.Journal = (*PocketJournal)(nil)

// WriteAhead stores each call's pending entry and reads it back. Nothing
// returns nil until every entry is stored; on error the call is not sent.
func (j *PocketJournal) WriteAhead(ctx context.Context, calls []nipcash.PendingCall) error {
	if j.IO == nil || j.Device == nil {
		return errors.New("nipCP: PocketJournal needs IO and Device")
	}
	if _, err := utils.GetPublicKey(j.UserPriv); err != nil {
		return fmt.Errorf("nipCP: user key: %w", err)
	}
	dev, err := j.Device.DeviceID(ctx)
	if err != nil {
		return fmt.Errorf("nipCP: device id: %w", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.written == nil {
		j.written = map[string]Entry{}
	}
	for _, pc := range calls {
		if pc.Device == "" {
			pc.Device = dev
		}
		if pc.Chain == "" {
			pc.Chain = j.Chain
		}
		e, err := PendingEntry(pc)
		if err != nil {
			return err
		}
		prev, had := j.written[e.W]
		all := j.Entries
		if had {
			all = append(append([]Entry(nil), all...), prev)
		}
		e.Rev = NextVersion(all, e.W)
		wrap, sealed, err := Seal(e, j.UserPriv)
		if err != nil {
			return err
		}
		if _, err := Store(ctx, j.IO, j.Relays, wrap); err != nil {
			return err
		}
		j.written[e.W] = sealed
		if had {
			if del, err := DeletionFor(prev, nil); err == nil {
				j.pending = append(j.pending, del)
			}
		}
	}
	j.flushDeletions(ctx)
	return nil
}

// flushDeletions publishes queued deletions, best effort: a stale wrap left
// behind is resolved away by its lower rev.
func (j *PocketJournal) flushDeletions(ctx context.Context) {
	var keep []*nip01.Event
	for _, d := range j.pending {
		ok := false
		for _, r := range j.Relays {
			if j.IO.Publish(ctx, r, d) == nil {
				ok = true
			}
		}
		if !ok {
			keep = append(keep, d)
		}
	}
	j.pending = keep
}

// Written is the entry this journal last stored for w.
func (j *PocketJournal) Written(w string) (Entry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.written[w]
	return e, ok
}

// RecordDerived records a derived id on this device.
func (j *PocketJournal) RecordDerived(ctx context.Context, id string, keepUntil int64) error {
	if j.Device == nil {
		return errors.New("nipCP: PocketJournal needs a Device")
	}
	return j.Device.RecordDerived(ctx, id, keepUntil)
}

// DerivedPlaced reports a derived id this device already placed.
func (j *PocketJournal) DerivedPlaced(ctx context.Context, id string) (bool, error) {
	if j.Device == nil {
		return false, errors.New("nipCP: PocketJournal needs a Device")
	}
	return j.Device.DerivedPlaced(ctx, id)
}

// DerivedEntryExists syncs the pocket in full and reports an entry with w = id
// in any state (use it as client.ReplaceOptions.DerivedEntryExists).
func (j *PocketJournal) DerivedEntryExists(ctx context.Context, id string) (bool, error) {
	user, err := utils.GetPublicKey(j.UserPriv)
	if err != nil {
		return false, fmt.Errorf("nipCP: user key: %w", err)
	}
	s, err := Sync(ctx, j.IO, j.Relays, j.UserPriv, FullSyncFilter(user), nil)
	if err != nil {
		return false, err
	}
	return DerivedEntryExists(s.Entries, id), nil
}
