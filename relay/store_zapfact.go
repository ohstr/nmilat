package relay

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/utils"
)

// zapFact is what the indexes keep about one zap receipt.
type zapFact struct {
	Receiver string // hex pubkey credited
	Sender   string // hex pubkey (or ConnectionKey) that paid; "" if unknown
	Signer   string // receipt signer: the recipient's LNURL server
	Amount   uint64 // milli-units, from the invoice when it has one
	// PaymentHash identifies the payment, so duplicate receipts count once.
	PaymentHash string
	// Valid: the receipt passed NIP-57/NIP-AZ validation (signatures,
	// invoice/request binding). Whether its signer is the recipient's
	// LNURL server is checked when it's counted.
	Valid bool
}

// parseZapFact extracts a zap receipt's receiver, sender, amount and
// payment hash. A receipt with no receiver or amount is an error.
func parseZapFact(ev *nip01.Event) (*zapFact, error) {
	receiver, err := zapReceiver(ev)
	if err != nil {
		return nil, err
	}
	f := &zapFact{Receiver: receiver, Signer: ev.PubKey}

	var bolt11, description, senderTag, resolvedSender, amountTag string
	for _, tag := range ev.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "bolt11":
			bolt11 = tag[1]
		case "description":
			description = tag[1]
		case "P":
			if senderTag == "" && (len(tag) < 3 || tag[2] == "" || tag[2] == "nostr") {
				senderTag = tag[1]
			}
		case "R":
			resolvedSender = tag[1]
		case "amount":
			amountTag = tag[1]
		}
	}

	var request struct {
		Kind   int        `json:"kind"`
		PubKey string     `json:"pubkey"`
		Tags   [][]string `json:"tags"`
	}
	_ = json.Unmarshal([]byte(description), &request)

	// The sender: NIP-AZ's resolved sender, then the P tag, then the
	// request's signer. A 9523 request is signed by a proxy, so only its
	// P tag names the sender.
	for _, candidate := range []string{resolvedSender, senderTag} {
		if utils.Validate32Key(candidate) == nil {
			f.Sender = candidate
			break
		}
	}
	if f.Sender == "" && request.Kind != nipAZ.KindAltZapOnBehalfRequest && utils.Validate32Key(request.PubKey) == nil {
		f.Sender = request.PubKey
	}

	if invoice, err := nip57.DecodeBolt11(bolt11); err == nil {
		f.PaymentHash = invoice.PaymentHash
		if invoice.AmountMloki > 0 {
			f.Amount = uint64(invoice.AmountMloki)
		}
	}
	if f.Amount == 0 {
		f.Amount, _ = strconv.ParseUint(amountTag, 10, 64)
	}
	if f.Amount == 0 {
		for _, tag := range request.Tags {
			if len(tag) >= 2 && tag[0] == "amount" {
				f.Amount, _ = strconv.ParseUint(tag[1], 10, 64)
				break
			}
		}
	}
	if f.Amount == 0 {
		return nil, fmt.Errorf("zap receipt %s has no amount", ev.ID)
	}

	switch ev.Kind {
	case nip57.KindZapReceipt:
		f.Valid = nip57.ValidateZapReceiptForRelay(ev) == nil
	case nipAZ.KindAltZapReceipt:
		f.Valid = nipAZ.ValidateAltZapReceiptForRelay(ev) == nil
	}
	return f, nil
}

// zapReceiver is the pubkey a receipt credits: a resolved "r" pubkey, else
// a Nostr "p". A web identity with no resolved pubkey credits no one.
func zapReceiver(ev *nip01.Event) (string, error) {
	var p, provider, r string
	for _, tag := range ev.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			if p == "" {
				p = tag[1]
				if len(tag) >= 3 {
					provider = tag[2]
				}
			}
		case "r":
			if r == "" {
				r = tag[1]
			}
		}
	}
	if err := utils.Validate32Key(p); err != nil {
		return "", fmt.Errorf("no valid receiver p tag: %w", err)
	}
	switch {
	case utils.Validate32Key(r) == nil:
		return r, nil
	case provider == "" || provider == "nostr":
		return p, nil
	default:
		return "", fmt.Errorf("p tag references a non-nostr provider (%q) but no resolved pubkey was found in an r tag", provider)
	}
}

// zapEntry is a zap as stored in a social index: who the other party is
// (the sender in the receiver index and vice versa), who signed the
// receipt, the payment hash and whether the receipt validated.
type zapEntry struct {
	Amount      uint64
	Other       string
	Signer      string
	PaymentHash string
	Valid       bool
}

const zapEntryLen = 8 + 32 + 32 + 32 + 1

func (e zapEntry) encode() []byte {
	v := make([]byte, zapEntryLen)
	copy(v[:8], itob(e.Amount))
	putHex32(v[8:40], e.Other)
	putHex32(v[40:72], e.Signer)
	putHex32(v[72:104], e.PaymentHash)
	if e.Valid {
		v[104] = 1
	}
	return v
}

func decodeZapEntry(v []byte) (zapEntry, bool) {
	if len(v) < zapEntryLen {
		return zapEntry{}, false
	}
	return zapEntry{
		Amount:      btoi(v[:8]),
		Other:       hex32(v[8:40]),
		Signer:      hex32(v[40:72]),
		PaymentHash: hex32(v[72:104]),
		Valid:       v[104] == 1,
	}, true
}

// putHex32 writes a 64-char hex value into dst; anything else stays zero.
func putHex32(dst []byte, h string) {
	if b, err := hex.DecodeString(h); err == nil && len(b) == 32 {
		copy(dst, b)
	}
}

// hex32 is putHex32's inverse; all zeros reads as "".
func hex32(b []byte) string {
	for _, c := range b {
		if c != 0 {
			return hex.EncodeToString(b)
		}
	}
	return ""
}
