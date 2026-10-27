package nipcash

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrBadCancel is a cash_withdraw cancel request whose shape is wrong (NIP-CASH
// §Cancelling a Payout): the Hub answers it BAD_REQUEST.
var ErrBadCancel = errors.New("nipcash: malformed cash_withdraw cancel request")

// ServingMethod is the method a Hub runs I2, I4, I6, I7 and I8 under: a
// cash_withdraw whose params carry cancel is a cancel request, served as the
// cash_lookup of that call (a malformed one is ErrBadCancel → BAD_REQUEST);
// anything else is served as its own method.
func ServingMethod(method string, params json.RawMessage) (string, error) {
	if method != "cash_withdraw" {
		return method, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(params, &fields); err != nil {
		return method, nil // not an object: the withdraw's own parser refuses it
	}
	cancel, ok := fields["cancel"]
	if !ok {
		return method, nil
	}
	if !bytes.Equal(bytes.TrimSpace(cancel), []byte("true")) {
		return "", fmt.Errorf("%w: cancel must be true", ErrBadCancel)
	}
	for k := range fields {
		switch k {
		case "cancel", "request_id", "cash_secret":
		default:
			return "", fmt.Errorf("%w: %q is not allowed", ErrBadCancel, k)
		}
	}
	var rid string
	if json.Unmarshal(fields["request_id"], &rid) != nil || !ValidRequestID(rid) {
		return "", fmt.Errorf("%w: request_id", ErrBadCancel)
	}
	return MethodCashLookup, nil
}

// MethodCashLookup is cash_lookup's method name.
const MethodCashLookup = "cash_lookup"

// ReuseCheckApplies is I7: the calls whose request_id is checked against the
// node's used marks — mint_cash, cash_withdraw, cash_transfer, cash_consolidate
// and cash_order. Never cash_lookup (nor a cancel request served as one).
func ReuseCheckApplies(method string) bool {
	switch method {
	case "mint_cash", "cash_withdraw", MethodCashTransfer, MethodCashConsolidate, "cash_order":
		return true
	}
	return false
}

// RequiresRequestID is I6: the methods refused BAD_REQUEST without a well-formed
// request_id on the private transport.
func RequiresRequestID(method string) bool {
	switch method {
	case "cash_withdraw", MethodCashTransfer, MethodCashConsolidate, "cash_order":
		return true
	}
	return false
}

// AnswersWithTombstone is I4: the methods answered with a destroyed bill's
// tombstone.
func AnswersWithTombstone(method string) bool {
	switch method {
	case MethodCashStatus, MethodCashRedeem, "cash_withdraw_quote", "cash_withdraw", MethodCashTransfer, MethodCashConsolidate:
		return true
	}
	return false
}
