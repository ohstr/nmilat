package nipCP

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
)

// State is an entry's state (NIP-CP §Kind 9525 `state`).
type State string

const (
	StateLive      State = "live"
	StatePending   State = "pending"
	StateSpent     State = "spent"
	StateExpired   State = "expired"
	StateReclaimed State = "reclaimed"
	StateDone      State = "done"
	StateUnknown   State = "unknown"
)

// Known reports one of the seven states.
func (s State) Known() bool {
	switch s {
	case StateLive, StatePending, StateSpent, StateExpired, StateReclaimed, StateDone, StateUnknown:
		return true
	}
	return false
}

// Final reports spent, expired, reclaimed and done.
func (s State) Final() bool {
	switch s {
	case StateSpent, StateExpired, StateReclaimed, StateDone:
		return true
	}
	return false
}

// Identity types of an entry's `identity` tag.
const (
	IdentityPubkey        = "pubkey"
	IdentityConnectionKey = "connection_key"
	IdentityCash          = "cash"
)

// SecretRoleRemainder marks the secret of a split's remainder.
const SecretRoleRemainder = "remainder"

// SecretRoleRemint marks, on a cash_withdraw pending entry, the secret behind
// its remint_commitment: the bill a cancelled payout re-mints.
const SecretRoleRemint = nipcash.SecretRoleRemint

// EntryIdentity is who can claim a bill: pubkey <Value>, connection_key <Value>
// <IA>, or cash (no value). The zero value is "no identity tag".
type EntryIdentity struct {
	Type, Value, IA string
}

func (id EntryIdentity) tag() []string {
	switch id.Type {
	case IdentityCash:
		return []string{"identity", IdentityCash}
	case IdentityConnectionKey:
		return []string{"identity", id.Type, id.Value, id.IA}
	}
	return []string{"identity", id.Type, id.Value}
}

func (id EntryIdentity) valid() bool {
	switch id.Type {
	case IdentityPubkey:
		return lowerHex(id.Value, 64) && id.IA == ""
	case IdentityConnectionKey:
		return lowerHex(id.Value, 64) && lowerHex(id.IA, 64)
	case IdentityCash:
		return id.Value == "" && id.IA == ""
	}
	return false
}

// Entry is one Pocket Entry. W is the token's wallet pubkey, or the request_id
// for a pending entry and the done entry that closes it.
//
// A held token carries Cash and Identity; an entry written from a tombstone
// carries Identity and no Cash, in a final state; a pending (or done) entry
// carries RequestID, Deadline, Target and Device, and neither Cash, Identity nor
// ExpiresAt. OrderKey and Notify are a cash_order's; Notify, Address, Quote
// and Receipt a cash_withdraw's (Quote and Receipt the events as JSON strings,
// Receipt once received).
//
// RumorID, RumorCreatedAt, WrapID and RawState are read, never written:
// RawState is the state as found, set (and State left empty) when this reader
// does not recognise it.
type Entry struct {
	W         string
	Rev       uint64
	Cash      string
	Amount    uint64
	Chain     string
	Identity  EntryIdentity
	State     State
	CheckedAt int64
	WrapKey   string
	ExpiresAt *int64
	Mint      string
	Source    string
	Secrets   []nipcash.PendingSecret
	RequestID string
	Deadline  int64
	Target    string
	Device    string
	OrderKey  string
	Notify    string
	Address   string
	Quote     string
	Receipt   string

	RumorID        string
	RumorCreatedAt int64
	WrapID         string
	RawState       string
}

// IsCall reports a pending entry or the done entry closing one.
func (e Entry) IsCall() bool { return e.RequestID != "" }

// Recognised reports an entry whose state this reader knows.
func (e Entry) Recognised() bool { return e.State.Known() }

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrEntry}, a...)...)
}

// Validate checks e against NIP-CP §Kind 9525 for writing. WrapKey is checked
// when set (Seal sets it).
func (e Entry) Validate() error {
	switch {
	case !lowerHex(e.W, 0):
		return bad("w must be lowercase hex")
	case e.Rev == 0:
		return bad("rev starts at 1")
	case !e.State.Known():
		return bad("state %q", e.State)
	case e.CheckedAt <= 0:
		return bad("state needs its check time")
	case e.Amount == 0:
		return bad("amount")
	case e.Chain == "":
		return bad("chain")
	case e.WrapKey != "" && !lowerHex(e.WrapKey, 64):
		return bad("wrap_key")
	case e.ExpiresAt != nil && *e.ExpiresAt <= 0:
		return bad("expires_at 0 means never and is not stored")
	case e.Mint != "" && !lowerHex(e.Mint, 66):
		return bad("mint is a 66-hex compressed pubkey")
	case e.Source != "" && !lowerHex(e.Source, 64):
		return bad("source")
	}
	for _, s := range e.Secrets {
		if !nipcash.ValidCashSecret(s.Secret) {
			return bad("secret")
		}
		switch s.Role {
		case "", SecretRoleRemainder:
		case SecretRoleRemint:
			if !e.IsCall() {
				return bad("a remint secret is a cash_withdraw pending entry's")
			}
		default:
			return bad("secret role %q", s.Role)
		}
	}
	if e.IsCall() {
		switch {
		case e.W != e.RequestID || !nipcash.ValidRequestID(e.RequestID):
			return bad("a pending entry's w is its request_id")
		case e.State != StatePending && e.State != StateDone:
			return bad("a pending entry is pending or done, not %q", e.State)
		case e.Deadline <= 0:
			return bad("deadline")
		case !lowerHex(e.Target, 64):
			return bad("target")
		case !lowerHex(e.Device, 0):
			return bad("device")
		case e.Cash != "" || e.Identity.Type != "" || e.ExpiresAt != nil:
			return bad("a pending entry has no cash, identity or expires_at")
		case e.OrderKey != "" && !lowerHex(e.OrderKey, 64):
			return bad("order_key")
		case e.Notify != "" && !lowerHex(e.Notify, 64):
			return bad("notify")
		case (e.Address == "") != (e.Quote == ""):
			return bad("a cash_withdraw entry has both address and quote, or neither once rewritten")
		case e.Quote != "" && e.Notify == "":
			return bad("a cash_withdraw entry keeps its notify")
		case e.Receipt != "" && e.Quote == "":
			return bad("a receipt is kept with its quote")
		}
		return nil
	}
	switch {
	case e.Deadline != 0 || e.Target != "" || e.Device != "" || e.OrderKey != "" || e.Notify != "" ||
		e.Address != "" || e.Quote != "" || e.Receipt != "":
		return bad("only a pending entry has deadline, target, device, order_key, notify, address, quote or receipt")
	case e.State == StatePending || e.State == StateDone:
		return bad("a bill entry is never %q", e.State)
	case !e.Identity.valid():
		return bad("identity")
	case !lowerHex(e.W, 64):
		return bad("a bill's w is its 64-hex wallet pubkey")
	case e.Cash == "" && !e.State.Final():
		return bad("an entry without cash is always in a final state")
	}
	return nil
}

// Rumor is e as an unsigned kind 9525 rumor by user, created at now, with its id
// set. e must Validate and carry its WrapKey.
func (e Entry) Rumor(user string, now int64) (*nip01.Event, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if e.WrapKey == "" {
		return nil, bad("no wrap_key: Seal generates it")
	}
	u := func(n uint64) string { return strconv.FormatUint(n, 10) }
	i := func(n int64) string { return strconv.FormatInt(n, 10) }
	tags := [][]string{{"w", e.W}, {"rev", u(e.Rev)}}
	if e.Cash != "" {
		tags = append(tags, []string{"cash", e.Cash})
	}
	tags = append(tags, []string{"amount", u(e.Amount)}, []string{"chain", e.Chain})
	if e.Identity.Type != "" {
		tags = append(tags, e.Identity.tag())
	}
	tags = append(tags, []string{"state", string(e.State), i(e.CheckedAt)})
	if e.Mint != "" {
		tags = append(tags, []string{"mint", e.Mint})
	}
	if e.ExpiresAt != nil {
		tags = append(tags, []string{"expires_at", i(*e.ExpiresAt)})
	}
	if e.Source != "" {
		tags = append(tags, []string{"source", e.Source})
	}
	if e.IsCall() {
		tags = append(tags, []string{"request_id", e.RequestID}, []string{"deadline", i(e.Deadline)},
			[]string{"target", e.Target}, []string{"device", e.Device})
	}
	for _, s := range e.Secrets {
		if s.Role == "" {
			tags = append(tags, []string{"secret", s.Secret})
		} else {
			tags = append(tags, []string{"secret", s.Secret, s.Role})
		}
	}
	if e.OrderKey != "" {
		tags = append(tags, []string{"order_key", e.OrderKey})
	}
	if e.Notify != "" {
		tags = append(tags, []string{"notify", e.Notify})
	}
	for _, t := range [][2]string{{"address", e.Address}, {"quote", e.Quote}, {"receipt", e.Receipt}} {
		if t[1] != "" {
			tags = append(tags, []string{t[0], t[1]})
		}
	}
	tags = append(tags, []string{"wrap_key", e.WrapKey})
	ev := nip01.NewUnsignedEvent(KindPocketEntry, user, "", tags...)
	ev.CreatedAt = uint64(now)
	id, err := ev.HashID()
	if err != nil {
		return nil, err
	}
	ev.ID = hex.EncodeToString(id)
	return ev, nil
}

// ParseRumor reads a kind 9525 rumor strictly (NIP-CP §Encodings): integers
// unsigned decimal without leading zeros, hex lowercase, mint 66 hex, each
// single tag at most once, rev required (a `v` tag does not stand for it). A
// signed event is refused. Unknown tags are ignored. An entry whose state this
// reader does not recognise is returned with RawState set and State empty,
// checked only for w and rev, for the derived-id check; Resolve ignores it.
func ParseRumor(ev *nip01.Event) (Entry, error) {
	if ev == nil || ev.Kind != KindPocketEntry {
		return Entry{}, bad("not a kind %d rumor", KindPocketEntry)
	}
	if ev.Sig != "" {
		return Entry{}, bad("a pocket entry is never signed")
	}
	id, err := ev.HashID()
	if err != nil {
		return Entry{}, bad("rumor id: %v", err)
	}
	if ev.ID != "" && ev.ID != hex.EncodeToString(id) {
		return Entry{}, bad("rumor id does not match its content")
	}
	e := Entry{RumorID: hex.EncodeToString(id), RumorCreatedAt: int64(ev.CreatedAt)}
	seen := map[string]bool{}
	single := func(t []string, n int) ([]string, error) {
		if seen[t[0]] {
			return nil, bad("two %q tags", t[0])
		}
		seen[t[0]] = true
		if len(t) < n {
			return nil, bad("%q tag is short", t[0])
		}
		return t, nil
	}
	var stateTag []string
	for _, t := range ev.Tags {
		if len(t) == 0 {
			continue
		}
		var v []string
		switch t[0] {
		case "w", "rev", "cash", "amount", "chain", "mint", "expires_at", "source", "request_id",
			"deadline", "target", "device", "order_key", "notify", "address", "quote", "receipt", "wrap_key":
			if v, err = single(t, 2); err != nil {
				return Entry{}, err
			}
		case "identity", "state":
			if v, err = single(t, 2); err != nil {
				return Entry{}, err
			}
		case "secret":
			if len(t) < 2 {
				return Entry{}, bad("secret tag is short")
			}
			s := nipcash.PendingSecret{Secret: t[1]}
			if len(t) > 2 {
				s.Role = t[2]
			}
			e.Secrets = append(e.Secrets, s)
			continue
		default:
			continue
		}
		switch t[0] {
		case "w":
			e.W = v[1]
		case "rev":
			if e.Rev, err = parseUint(v[1]); err != nil {
				return Entry{}, bad("rev: %v", err)
			}
		case "cash":
			e.Cash = v[1]
		case "amount":
			if e.Amount, err = parseUint(v[1]); err != nil {
				return Entry{}, bad("amount: %v", err)
			}
		case "chain":
			e.Chain = v[1]
		case "identity":
			e.Identity.Type = v[1]
			if len(v) > 2 {
				e.Identity.Value = v[2]
			}
			if len(v) > 3 {
				e.Identity.IA = v[3]
			}
		case "state":
			stateTag = v
		case "mint":
			e.Mint = v[1]
		case "expires_at":
			n, err := parseInt(v[1])
			if err != nil {
				return Entry{}, bad("expires_at: %v", err)
			}
			e.ExpiresAt = &n
		case "source":
			e.Source = v[1]
		case "request_id":
			e.RequestID = v[1]
		case "deadline":
			if e.Deadline, err = parseInt(v[1]); err != nil {
				return Entry{}, bad("deadline: %v", err)
			}
		case "target":
			e.Target = v[1]
		case "device":
			e.Device = v[1]
		case "order_key":
			e.OrderKey = v[1]
		case "notify":
			e.Notify = v[1]
		case "address":
			e.Address = v[1]
		case "quote":
			e.Quote = v[1]
		case "receipt":
			e.Receipt = v[1]
		case "wrap_key":
			e.WrapKey = v[1]
		}
	}
	if e.W == "" || !seen["rev"] || stateTag == nil {
		return Entry{}, bad("w, rev and state are required")
	}
	if !lowerHex(e.W, 0) || e.Rev == 0 {
		return Entry{}, bad("w or rev")
	}
	if !State(stateTag[1]).Known() {
		e.RawState = stateTag[1]
		return e, nil
	}
	e.State = State(stateTag[1])
	if len(stateTag) < 3 {
		return Entry{}, bad("state needs its check time")
	}
	if e.CheckedAt, err = parseInt(stateTag[2]); err != nil {
		return Entry{}, bad("state check time: %v", err)
	}
	if !seen["amount"] || !seen["chain"] || e.WrapKey == "" {
		return Entry{}, bad("amount, chain and wrap_key are required")
	}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// parseUint reads an unsigned decimal with no sign and no leading zeros.
func parseUint(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("%q is not a canonical unsigned integer", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%q is not a canonical unsigned integer", s)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

func parseInt(s string) (int64, error) {
	n, err := parseUint(s)
	if err != nil {
		return 0, err
	}
	if n > 1<<62 {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return int64(n), nil
}

// lowerHex reports lowercase hex of n characters (any even length when n is 0).
func lowerHex(s string, n int) bool {
	if s == "" || (n > 0 && len(s) != n) || (n == 0 && len(s)%2 != 0) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
