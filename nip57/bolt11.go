package nip57

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// Invoice represents decoded bolt11 data
type Invoice struct {
	// Currency is the BOLT11 currency prefix from the human-readable part,
	// e.g. "fc" (Flokicoin), "bc" (Bitcoin), "tb" (Bitcoin testnet).
	Currency        string
	AmountMloki     int64
	Description     string // the "d" field (payment memo), if present
	DescriptionHash string
	PaymentHash     string
	// Timestamp is the invoice's creation time, in unix seconds.
	Timestamp int64
	// Expiry is the "x" field in seconds, or 3600 when absent (BOLT11's
	// default).
	Expiry int64
}

// DefaultBolt11Expiry is the expiry BOLT11 gives an invoice with no "x" field.
const DefaultBolt11Expiry = 3600

// ExpiresAt is the unix time the invoice expires: Timestamp + Expiry.
func (i *Invoice) ExpiresAt() int64 { return i.Timestamp + i.Expiry }

// DecodeBolt11 decodes a bolt11 invoice string into its currency prefix,
// amount, memo, payment hash, and description hash — what NIP-57 needs to
// cross-check a zap receipt against the invoice it claims to have paid,
// plus what a caller needs to display it. The default implementation
// is a minimal, dependency-free BOLT11 parser (see bolt11.go) — swap this
// var for your own decoder (e.g. one backed by a full Lightning node
// library) if you need routing hints, the payee node ID, or node-signature
// verification beyond what nip57 itself requires.
var DecodeBolt11 = decodeBolt11

// bolt11 tagged-field type values are the bech32-charset index of their
// conventional letter, e.g. "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[1] == 'p', so
// payment_hash fields are tagged type 1; index 23 == 'h', so
// description_hash fields are tagged type 23. See BOLT11's "Tagged Fields"
// table (bolt11FieldsMatchCharset in bolt11_test.go checks this derivation
// against the charset directly).
const (
	bolt11FieldPaymentHash     = 1
	bolt11FieldDescription     = 13
	bolt11FieldDescriptionHash = 23
	bolt11FieldExpiry          = 6
)

const (
	bolt11TimestampWords = 7   // 35-bit creation timestamp
	bolt11SignatureWords = 104 // 520-bit (65-byte) node signature
	bolt11HashFieldWords = 52  // 260 bits -> 32 bytes once converted, 4 bits padding
)

// decodeBolt11 extracts the currency prefix, amount, memo, payment hash, and
// description hash from a BOLT11 invoice string — what nip57 needs to
// cross-check a zap receipt against the invoice it claims to have paid
// (NIP-57 Appendix F), plus what a caller needs to display it. It deliberately does not decode routing hints, the payee node ID, or
// any other tagged field, and does not verify the invoice's own node
// signature: nip57's caller already verified the zap receipt's Nostr
// signature, and the receipt/invoice cross-check here is a consistency
// check, not a Lightning-network payment verification.
func decodeBolt11(bolt11 string) (*Invoice, error) {
	hrp, words, err := bech32.DecodeNoLimit(bolt11)
	if err != nil {
		return nil, fmt.Errorf("invalid bolt11 encoding: %w", err)
	}

	currency, amountMloki, err := decodeBolt11HRP(hrp)
	if err != nil {
		return nil, err
	}

	if len(words) < bolt11TimestampWords+bolt11SignatureWords {
		return nil, fmt.Errorf("bolt11 data part too short (%d words)", len(words))
	}
	fields := words[bolt11TimestampWords : len(words)-bolt11SignatureWords]

	inv := &Invoice{Currency: currency, AmountMloki: amountMloki, Expiry: DefaultBolt11Expiry}
	for _, w := range words[:bolt11TimestampWords] {
		inv.Timestamp = inv.Timestamp<<5 | int64(w)
	}

	for i := 0; i+3 <= len(fields); {
		fieldType := int(fields[i])
		dataLen := int(fields[i+1])*32 + int(fields[i+2])
		i += 3
		if i+dataLen > len(fields) {
			return nil, fmt.Errorf("bolt11 tagged field (type %d) truncated", fieldType)
		}
		data := fields[i : i+dataLen]
		i += dataLen

		switch fieldType {
		case bolt11FieldPaymentHash:
			if h, err := bolt11HashHex(data); err == nil {
				inv.PaymentHash = h
			}
		case bolt11FieldDescription:
			if b, err := bech32.ConvertBits(data, 5, 8, false); err == nil {
				inv.Description = string(b)
			}
		case bolt11FieldDescriptionHash:
			if h, err := bolt11HashHex(data); err == nil {
				inv.DescriptionHash = h
			}
		case bolt11FieldExpiry:
			if len(data) > 0 && len(data) <= 12 {
				var x int64
				for _, w := range data {
					x = x<<5 | int64(w)
				}
				inv.Expiry = x
			}
		}
	}

	if inv.PaymentHash == "" {
		return nil, errors.New("bolt11 invoice has no payment_hash tag")
	}

	return inv, nil
}

// bolt11HashHex converts a 52-word (260-bit) tagged-field payload into its
// 32-byte hex-encoded value, per BOLT11's encoding of the payment_hash and
// description_hash fields (the trailing 4 padding bits are discarded).
func bolt11HashHex(words []byte) (string, error) {
	if len(words) != bolt11HashFieldWords {
		return "", fmt.Errorf("expected %d words for a 32-byte hash field, got %d", bolt11HashFieldWords, len(words))
	}
	b, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return hex.EncodeToString(b), nil
}

// decodeBolt11HRP splits a BOLT11 human-readable part into its currency
// prefix and amount: "lnfc50n" -> currency "fc", digits "50", multiplier
// nano -> 5000 mloki, per BOLT11's amount encoding. A hrp with no amount
// digits (an "any amount" invoice) returns amount 0.
func decodeBolt11HRP(hrp string) (string, int64, error) {
	if !strings.HasPrefix(hrp, "ln") {
		return "", 0, fmt.Errorf("not a lightning invoice hrp: %q", hrp)
	}

	rest := hrp[2:]
	digitStart := len(rest)
	for i, c := range rest {
		if c >= '0' && c <= '9' {
			digitStart = i
			break
		}
	}
	currency := rest[:digitStart]

	amount, err := decodeBolt11Amount(rest[digitStart:])
	return currency, amount, err
}

// decodeBolt11Amount parses BOLT11's amount+multiplier suffix (e.g. "50n"
// -> 5000 mloki). An empty suffix (an "any amount" invoice) returns 0.
func decodeBolt11Amount(amountPart string) (int64, error) {
	if amountPart == "" {
		return 0, nil
	}

	var multiplier byte
	digits := amountPart
	if last := amountPart[len(amountPart)-1]; last < '0' || last > '9' {
		multiplier = last
		digits = amountPart[:len(amountPart)-1]
	}

	if digits == "" {
		return 0, fmt.Errorf("invalid bolt11 amount %q", amountPart)
	}
	value, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bolt11 amount %q: %w", amountPart, err)
	}

	var mlokiPerUnit int64
	switch multiplier {
	case 0:
		mlokiPerUnit = 100_000_000_000 // whole currency units
	case 'm':
		mlokiPerUnit = 100_000_000
	case 'u':
		mlokiPerUnit = 100_000
	case 'n':
		mlokiPerUnit = 100
	case 'p':
		if value%10 != 0 {
			return 0, fmt.Errorf("invalid pico bolt11 amount %q: not a multiple of 10", amountPart)
		}
		return value / 10, nil
	default:
		return 0, fmt.Errorf("unknown bolt11 amount multiplier %q", string(multiplier))
	}
	// A wrapped product would pay a different amount than the invoice names.
	if value > math.MaxInt64/mlokiPerUnit {
		return 0, fmt.Errorf("invalid bolt11 amount %q: does not fit in int64 mloki", amountPart)
	}
	return value * mlokiPerUnit, nil
}
