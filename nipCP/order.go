package nipCP

import (
	"errors"

	"github.com/ohstr/nmilat/nipCO"
	coclient "github.com/ohstr/nmilat/nipCO/client"
	"github.com/ohstr/nmilat/nipcash"
)

// OrderOption tunes ApplyOrder.
type OrderOption func(*orderConfig)

type orderConfig struct {
	held      []Entry
	identity  *EntryIdentity
	unpaid    bool
	progress  bool
	unpaidNow int64
	at        int64
}

// OrderHeld gives the pocket's entries: a bill whose w already has an entry is
// held, and gets no new one.
func OrderHeld(all []Entry) OrderOption {
	return func(c *orderConfig) { c.held = all }
}

// OrderIdentity is the identity the order's bills were made for, from the
// client's local order record (the recipient is stored locally, never read from
// the reply). It is required when keeps is true for a pubkey or connection_key
// recipient; a cash recipient's bills are cash.
func OrderIdentity(id EntryIdentity) OrderOption {
	return func(c *orderConfig) { c.identity = &id }
}

// OrderEndedUnpaid asks ApplyOrder to close the entry when the order reads as
// ended unpaid (nipCO/client.EndedUnpaid with sawProgress and now): pass it only
// once a lookup sent after pay_by was answered.
func OrderEndedUnpaid(sawProgress bool, now int64) OrderOption {
	return func(c *orderConfig) { c.unpaid, c.progress, c.unpaidNow = true, sawProgress, now }
}

// OrderAt sets the check time written (default: now).
func OrderAt(at int64) OrderOption {
	return func(c *orderConfig) { c.at = at }
}

// ErrOrderIdentity is a kept pubkey or connection_key order without
// OrderIdentity.
var ErrOrderIdentity = errors.New("nipCP: a kept order needs the identity its bills were made for")

// ApplyOrder applies one answer about a cash_order (the reply, or a lookup's
// done result) to its pending entry (NIP-CP §Writing, Orders).
//
// keeps comes from the client's local order record: true when the recipient is
// the user's own identity, or a cash recipient whose secret the client keeps;
// false for a gift. Only when keeps, writes holds one entry per bill not yet
// held: live with its token and amount and no expires_at, a cash bill carrying
// the entry's secret; a tombstone in place of a token gives an entry without
// cash in its mapped final state.
//
// done is the entry at its next rev in state done, only once the order is
// finished (nipCO/client.Finished: Lightning minted or expired, on-chain
// expired or closed) or, with OrderEndedUnpaid, ended unpaid. It keeps
// request_id, target, notify and order_key or secret, so a closed on-chain order
// can be read again; an entry already done is given no second done, and still
// gains the bills a later read shows.
func ApplyOrder(entry Entry, order *nipCO.Order, keeps bool, opts ...OrderOption) (writes []Entry, done *Entry, err error) {
	if !entry.IsCall() || entry.Notify == "" || (entry.State != StatePending && entry.State != StateDone) {
		return nil, nil, ErrNotPending
	}
	if order == nil {
		return nil, nil, bad("no order")
	}
	var c orderConfig
	for _, o := range opts {
		o(&c)
	}
	at := c.at
	if at == 0 {
		at = now()
	}
	if keeps {
		id, secrets, err := orderIdentity(entry, c)
		if err != nil {
			return nil, nil, err
		}
		for _, b := range order.Bills {
			if DerivedEntryExists(c.held, b.WalletPubkey) || DerivedEntryExists(writes, b.WalletPubkey) {
				continue
			}
			e := Entry{W: b.WalletPubkey, Rev: 1, Amount: b.AmountMillis, Chain: entry.Chain, Identity: id, CheckedAt: at}
			if b.Token.Tombstone != nil {
				e.State, _ = MapStatus(StatusInput{Tombstone: b.Token.Tombstone})
			} else {
				e.Cash, e.State = b.Token.Token, StateLive
				e.Secrets = append([]nipcash.PendingSecret(nil), secrets...)
			}
			if err := e.Validate(); err != nil {
				return nil, nil, err
			}
			writes = append(writes, e)
		}
	}
	if entry.State == StatePending &&
		(coclient.Finished(order) || (c.unpaid && coclient.EndedUnpaid(order, c.progress, c.unpaidNow))) {
		d := WithState(entry, StateDone, at)
		if c.held != nil {
			d.Rev = NextVersion(append(c.held, entry), entry.W)
		}
		done = &d
	}
	return writes, done, nil
}

// orderIdentity is the identity and secrets of a kept order's bills.
func orderIdentity(entry Entry, c orderConfig) (EntryIdentity, []nipcash.PendingSecret, error) {
	for _, s := range entry.Secrets {
		if s.Role == "" {
			return EntryIdentity{Type: IdentityCash}, []nipcash.PendingSecret{{Secret: s.Secret}}, nil
		}
	}
	if c.identity == nil || !c.identity.valid() || c.identity.Type == IdentityCash {
		return EntryIdentity{}, nil, ErrOrderIdentity
	}
	return *c.identity, nil, nil
}
