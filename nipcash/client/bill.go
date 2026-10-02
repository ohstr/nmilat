package client

import (
	"fmt"

	"github.com/ohstr/nmilat/nipcash"
)

// Bill identifies the bill one batch item acts on: which bill, and the secret that
// proves the sender holds it.
//
// A single field, with unexported members and no usable zero value, because the two
// halves are not independent. Both come from one token — the wallet pubkey is what
// the item targets, the connection secret is what signs its kind-23193 bill proof
// (§Bill Proofs) — and an item carrying one without the other cannot be served.
//
// They were two plain string fields, and that was a live trap on a money path: a
// struct literal naming only Target compiled perfectly and failed at runtime, and the
// hub's answer to such an item is an OMISSION, which is information-free, so a caller
// could not learn why. Making the pair unconstructible-by-halves is worth more than
// diagnosing it after the fact — the same argument nipcash's own buildItem makes about
// deriving everything from one source rather than accepting it from a caller.
type Bill struct {
	target     string
	connSecret string
}

// BillFor is the normal constructor: everything it needs is in the bill's own token,
// so there is nothing for a caller to pair up wrongly.
func BillFor(tok nipcash.Token) (Bill, error) {
	return BillFromParts(tok.WalletPubkey, tok.Secret)
}

// BillFromParts is for a caller holding the bill's pairing data rather than an encoded
// token — a connection dialled from a raw pairing URI, which carries the same wallet
// pubkey and secret but no token envelope around them.
//
// Both are required. An empty secret is refused HERE, where the caller can be told
// which bill is wrong, rather than deeper down where the only available answer is an
// omission.
func BillFromParts(walletPubkey, connSecret string) (Bill, error) {
	if walletPubkey == "" {
		return Bill{}, fmt.Errorf("nipcash/client: a batch item needs the bill's wallet pubkey")
	}
	if connSecret == "" {
		return Bill{}, fmt.Errorf("nipcash/client: bill %s needs its connection secret, which signs the proof that you hold it", walletPubkey)
	}
	return Bill{target: walletPubkey, connSecret: connSecret}, nil
}

// Target is the bill's wallet pubkey, for a caller correlating outcomes with its own
// records. Read-only: the pair is set once, at construction.
func (b Bill) Target() string { return b.target }

// ok reports whether b was constructed rather than zero-valued. Checked once on the
// send path so a zero Bill is a named error instead of an item the hub omits.
func (b Bill) ok() bool { return b.target != "" && b.connSecret != "" }
