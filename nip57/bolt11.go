package nip57

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// Invoice represents decoded bolt11 data
type Invoice struct {
	AmountMloki     int64
	DescriptionHash string
	PaymentHash     string
}

// DecodeBolt11 decodes a bolt11 invoice string into the amount, payment
// hash, and description hash NIP-57 needs to cross-check a zap receipt
// against the invoice it claims to have paid. The default implementation
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
	bolt11FieldDescriptionHash = 23
)

const (
	bolt11TimestampWords = 7   // 35-bit creation timestamp
	bolt11SignatureWords = 104 // 520-bit (65-byte) node signature
	bolt11HashFieldWords = 52  // 260 bits -> 32 bytes once converted, 4 bits padding
)

// decodeBolt11 extracts the amount, payment hash, and description hash from
// a BOLT11 invoice string — the only fields nip57 needs to cross-check a
// zap receipt against the invoice it claims to have paid (NIP-57 Appendix
// F). It deliberately does not decode routing hints, the payee node ID, or
// any other tagged field, and does not verify the invoice's own node
// signature: nip57's caller already verified the zap receipt's Nostr
// signature, and the receipt/invoice cross-check here is a consistency
// check, not a Lightning-network payment verification.
func decodeBolt11(bolt11 string) (*Invoice, error) {
	hrp, words, err := bech32.DecodeNoLimit(bolt11)
	if err != nil {
		return nil, fmt.Errorf("invalid bolt11 encoding: %w", err)
	}

	amountMloki, err := decodeBolt11Amount(hrp)
	if err != nil {
		return nil, err
	}

	if len(words) < bolt11TimestampWords+bolt11SignatureWords {
		return nil, fmt.Errorf("bolt11 data part too short (%d words)", len(words))
	}
	fields := words[bolt11TimestampWords : len(words)-bolt11SignatureWords]

	inv := &Invoice{AmountMloki: amountMloki}

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
		case bolt11FieldDescriptionHash:
			if h, err := bolt11HashHex(data); err == nil {
				inv.DescriptionHash = h
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

// decodeBolt11Amount parses the optional amount+multiplier suffix of a
// BOLT11 human-readable part (e.g. "lnfc50n" -> digits "50", multiplier
// nano -> 5000 mloki), per BOLT11's amount encoding. A hrp with no amount
// digits (an "any amount" invoice) returns 0.
func decodeBolt11Amount(hrp string) (int64, error) {
	if !strings.HasPrefix(hrp, "ln") {
		return 0, fmt.Errorf("not a lightning invoice hrp: %q", hrp)
	}

	rest := hrp[2:]
	digitStart := len(rest)
	for i, c := range rest {
		if c >= '0' && c <= '9' {
			digitStart = i
			break
		}
	}

	amountPart := rest[digitStart:]
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

	switch multiplier {
	case 0:
		return value * 100_000_000_000, nil // whole currency units -> mloki
	case 'm':
		return value * 100_000_000, nil
	case 'u':
		return value * 100_000, nil
	case 'n':
		return value * 100, nil
	case 'p':
		if value%10 != 0 {
			return 0, fmt.Errorf("invalid pico bolt11 amount %q: not a multiple of 10", amountPart)
		}
		return value / 10, nil
	default:
		return 0, fmt.Errorf("unknown bolt11 amount multiplier %q", string(multiplier))
	}
}
