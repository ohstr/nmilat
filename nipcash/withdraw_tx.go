package nipcash

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/flokiorg/go-flokicoin/wire"
)

// ErrPayoutTx is a payout's tx that does not pay what the receipt says.
var ErrPayoutTx = errors.New("nipcash: the payout transaction does not match")

// VerifyPayoutTx checks a payout's raw transaction (NIP-CASH §Response): its id
// is txid, and its output vout pays exactly payoutMillis ÷ 1000 base units to
// address's witness script. hrp "" decodes the address under its own HRP (the
// one the Hub accepted and signed into the quote).
func VerifyPayoutTx(txHex, txid string, vout uint32, address, hrp string, payoutMillis uint64) error {
	raw, err := hex.DecodeString(txHex)
	if err != nil {
		return fmt.Errorf("%w: tx is not hex", ErrPayoutTx)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("%w: tx does not decode", ErrPayoutTx)
	}
	if tx.TxHash().String() != txid {
		return fmt.Errorf("%w: txid", ErrPayoutTx)
	}
	if int(vout) >= len(tx.TxOut) {
		return fmt.Errorf("%w: vout", ErrPayoutTx)
	}
	if payoutMillis%1000 != 0 {
		return fmt.Errorf("%w: payout is not whole base units", ErrPayoutTx)
	}
	v, prog, err := DecodeWitnessAddress(address, hrp)
	if err != nil {
		return fmt.Errorf("%w: address", ErrPayoutTx)
	}
	out := tx.TxOut[vout]
	if !bytes.Equal(out.PkScript, WitnessScript(v, prog)) {
		return fmt.Errorf("%w: script", ErrPayoutTx)
	}
	if out.Value < 0 || uint64(out.Value) != payoutMillis/1000 {
		return fmt.Errorf("%w: value", ErrPayoutTx)
	}
	return nil
}
