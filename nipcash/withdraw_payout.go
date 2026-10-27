package nipcash

import (
	"encoding/json"
	"errors"
	"fmt"
)

// PayoutState is a payout's state (NIP-CASH §Payout States).
type PayoutState string

// The five payout states.
const (
	PayoutQueued    PayoutState = "queued"
	PayoutBroadcast PayoutState = "broadcast"
	PayoutConfirmed PayoutState = "confirmed"
	PayoutFinal     PayoutState = "final"
	PayoutCancelled PayoutState = "cancelled"
)

// Known reports one of the five states.
func (s PayoutState) Known() bool {
	switch s {
	case PayoutQueued, PayoutBroadcast, PayoutConfirmed, PayoutFinal, PayoutCancelled:
		return true
	}
	return false
}

// Payout is cash_withdraw's answer: the reply, every lookup done and every
// cancel answer (NIP-CASH §Response). Tx is set from the first signature;
// Txid, Vout and Depth from the first broadcast; none of them under cancelled,
// which carries NewWalletPubkey and NewWalletToken instead.
type Payout struct {
	State           PayoutState      `json:"state"`
	Address         string           `json:"address"`
	AmountMillis    uint64           `json:"amount_millis"`
	FeeMillis       uint64           `json:"fee_millis"`
	PayoutMillis    uint64           `json:"payout_millis"`
	SentBy          int64            `json:"sent_by"`
	FinalDepth      uint32           `json:"final_depth"`
	Signed          bool             `json:"signed"`
	Receipt         string           `json:"receipt"`
	Tx              string           `json:"tx,omitempty"`
	Txid            string           `json:"txid,omitempty"`
	Vout            *uint32          `json:"vout,omitempty"`
	Depth           *uint32          `json:"depth,omitempty"`
	NewWalletPubkey string           `json:"new_wallet_pubkey,omitempty"`
	NewWalletToken  TokenOrTombstone `json:"new_wallet_token,omitempty"`
	// TxErr is set by the client when Tx fails VerifyPayoutTx. It is a
	// warning beside the payout and never changes State.
	TxErr error `json:"-"`
}

// MarshalJSON omits new_wallet_token when there is none.
func (p Payout) MarshalJSON() ([]byte, error) {
	type wire Payout
	w := struct {
		wire
		NewWalletToken *TokenOrTombstone `json:"new_wallet_token,omitempty"`
	}{wire: wire(p)}
	if p.NewWalletToken.Token != "" || p.NewWalletToken.Tombstone != nil {
		w.NewWalletToken = &p.NewWalletToken
	}
	return json.Marshal(w)
}

// ErrPayoutMalformed is a payout answer without the spec's shape.
var ErrPayoutMalformed = errors.New("nipcash: malformed payout")

// ParsePayout reads a payout strictly: a tombstone is *BillGone; a known state;
// every required field present; receipt always; tx, txid, vout and depth never
// under cancelled or queued (txid, vout, depth) and always from broadcast on;
// tx only once signed; new_wallet_pubkey and new_wallet_token only, and always,
// under cancelled; fee + payout = amount.
func ParsePayout(data []byte) (*Payout, error) {
	if err := goneIf(MethodCashWithdraw, data); err != nil {
		return nil, err
	}
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrPayoutMalformed, why) }
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, bad("not an object")
	}
	for _, k := range []string{"state", "address", "amount_millis", "fee_millis", "payout_millis", "sent_by", "final_depth", "signed", "receipt"} {
		if v, ok := fields[k]; !ok || string(v) == "null" {
			return nil, bad("no " + k)
		}
	}
	var p Payout
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, bad("field types")
	}
	has := func(k string) bool { v, ok := fields[k]; return ok && string(v) != "null" }
	onChain := has("txid") || has("vout") || has("depth")
	switch {
	case !p.State.Known():
		return nil, bad("unknown state")
	case p.Address == "", p.Receipt == "":
		return nil, bad("empty address or receipt")
	case p.FeeMillis > p.AmountMillis || p.AmountMillis-p.FeeMillis != p.PayoutMillis:
		return nil, bad("fee and payout do not add up to the amount")
	case p.State == PayoutCancelled && (has("tx") || onChain):
		return nil, bad("cancelled carries a transaction")
	case p.State == PayoutCancelled && (p.NewWalletPubkey == "" || !has("new_wallet_token")):
		return nil, bad("cancelled without its re-minted bill")
	case p.State != PayoutCancelled && (has("new_wallet_pubkey") || has("new_wallet_token")):
		return nil, bad("a re-minted bill outside cancelled")
	case p.State == PayoutQueued && onChain:
		return nil, bad("queued carries a broadcast")
	case (p.State == PayoutBroadcast || p.State == PayoutConfirmed || p.State == PayoutFinal) &&
		(!isLowerHex64(p.Txid) || p.Vout == nil || p.Depth == nil):
		return nil, bad("a broadcast payout needs txid, vout and depth")
	case has("tx") && (!p.Signed || p.Tx == "" || !isLowerHex(p.Tx)):
		return nil, bad("tx")
	case p.NewWalletPubkey != "" && !isLowerHex64(p.NewWalletPubkey):
		return nil, bad("new_wallet_pubkey")
	}
	return &p, nil
}

// ParseLookupResult reads a lookup's done result for this withdrawal: the
// payout's current state, its re-minted bill's token (under cancelled)
// decrypted with p.Credential as a spin-off's (a cash-mode bill's arrives in
// the clear).
func (p CashWithdrawParams) ParseLookupResult(data []byte) (*Payout, error) {
	out, err := ParsePayout(data)
	if err != nil {
		return nil, err
	}
	if out.NewWalletToken.Token != "" {
		if p.Credential == nil {
			return nil, errors.New("nipcash: a re-minted token needs the call's credential to decrypt")
		}
		tok, err := p.Credential.decryptDelivery(out.NewWalletPubkey, out.NewWalletToken.Token)
		if err != nil {
			return nil, err
		}
		out.NewWalletToken.Token = tok
	}
	return out, nil
}
