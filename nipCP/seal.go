package nipCP

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip59"
	"github.com/ohstr/nmilat/utils"
)

// now is the clock Seal and the entry builders read; tests swap it.
var now = func() int64 { return time.Now().Unix() }

// Seal writes e as the user's rumor and gift-wraps it to the user (NIP-CP
// §Wrapping): the wrap key is generated first and recorded in the entry's
// wrap_key, the seal is signed by the user, the wrap's p is the user. It returns
// the wrap and the entry as written (WrapKey, RumorID, RumorCreatedAt, WrapID
// set). Every call generates a new wrap key: a change is always a new wrap.
func Seal(e Entry, userPriv string, opts ...nip59.WrapOption) (*nip01.Event, Entry, error) {
	user, err := utils.GetPublicKey(userPriv)
	if err != nil {
		return nil, Entry{}, fmt.Errorf("nipCP: user key: %w", err)
	}
	k, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, Entry{}, fmt.Errorf("nipCP: wrap key: %w", err)
	}
	e.WrapKey = hex.EncodeToString(k.Serialize())
	e.RawState = ""
	created := now()
	rumor, err := e.Rumor(user, created)
	if err != nil {
		return nil, Entry{}, err
	}
	wrap, err := nip59.WrapWithKey(rumor, userPriv, user, e.WrapKey, opts...)
	if err != nil {
		return nil, Entry{}, err
	}
	e.RumorID, e.RumorCreatedAt, e.WrapID = rumor.ID, created, wrap.ID
	return wrap, e, nil
}

// Open reads one wrap of the user's (NIP-CP §Reading): it keeps a kind 9525
// rumor whose seal and rumor pubkey are both the user, unsigned and well formed.
// Anything else (a DM, another key's seal, a signed or malformed 9525) is
// ErrNotEntry, which a sync discards without failing.
func Open(wrap *nip01.Event, userPriv string) (Entry, error) {
	user, err := utils.GetPublicKey(userPriv)
	if err != nil {
		return Entry{}, fmt.Errorf("nipCP: user key: %w", err)
	}
	rumor, signer, err := nip59.UnwrapWithKey(wrap, userPriv)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrNotEntry, err)
	}
	if rumor.Kind != KindPocketEntry {
		return Entry{}, fmt.Errorf("%w: kind %d", ErrNotEntry, rumor.Kind)
	}
	if signer != user || rumor.PubKey != user {
		return Entry{}, fmt.Errorf("%w: sealed by another key", ErrNotEntry)
	}
	e, err := ParseRumor(rumor)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrNotEntry, err)
	}
	e.WrapID = wrap.ID
	return e, nil
}

// OpenAll opens wraps and keeps the user's entries, discarding every wrap Open
// refuses. It fails only on a bad user key.
func OpenAll(wraps []*nip01.Event, userPriv string) ([]Entry, error) {
	if _, err := utils.GetPublicKey(userPriv); err != nil {
		return nil, fmt.Errorf("nipCP: user key: %w", err)
	}
	var out []Entry
	for _, w := range wraps {
		e, err := Open(w, userPriv)
		if errors.Is(err, ErrNotEntry) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// maxBackdate is the window a deletion's created_at is randomized over, the
// same as a wrap's (NIP-59: up to two days in the past).
const maxBackdate = 2 * 24 * 60 * 60

// DeletionFor is the NIP-09 kind 5 deleting old's wrap (NIP-CP §Writing,
// Change): signed by old's wrap_key, naming the wrap by e and k 1059, its
// created_at randomized over the last two days from rnd (crypto/rand when nil).
func DeletionFor(old Entry, rnd io.Reader) (*nip01.Event, error) {
	if !lowerHex(old.WrapID, 64) || !lowerHex(old.WrapKey, 64) {
		return nil, bad("deleting a wrap needs its id and wrap_key")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	var b [8]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return nil, fmt.Errorf("nipCP: deletion time: %w", err)
	}
	ev := nip01.NewEvent(5, "", []string{"e", old.WrapID}, []string{"k", strconv.Itoa(nip59.KindGiftWrap)})
	ev.CreatedAt = uint64(now() - int64(binary.BigEndian.Uint64(b[:])%maxBackdate))
	if err := ev.Sign(old.WrapKey); err != nil {
		return nil, fmt.Errorf("nipCP: sign deletion: %w", err)
	}
	return ev, nil
}
