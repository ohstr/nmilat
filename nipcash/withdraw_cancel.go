package nipcash

import (
	"bytes"
	"encoding/json"
)

// CashWithdrawCancelRequest is a cancel request (NIP-CASH §Cancelling a
// Payout): a cash_withdraw item naming the bill, served as the cash_lookup of
// the original call. CashSecret only for a call authorized by a cash
// commitment.
type CashWithdrawCancelRequest struct {
	Cancel     bool   `json:"cancel"`
	RequestID  string `json:"request_id"`
	CashSecret string `json:"cash_secret,omitempty"`
}

// ParseWithdrawCancel reads cash_withdraw params as a cancel request.
// isCancel is false (and err nil) when params carry no cancel key: a call.
// With one, exactly cancel = true, a valid request_id and an optional valid
// cash_secret are allowed; anything else is a *WithdrawError with BAD_REQUEST.
func ParseWithdrawCancel(params json.RawMessage) (req *CashWithdrawCancelRequest, isCancel bool, err error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(params, &fields) != nil {
		return nil, false, nil
	}
	cancel, ok := fields["cancel"]
	if !ok {
		return nil, false, nil
	}
	bad := func(reason string) error {
		return withdrawErr(ErrCodeBadRequest, "", 0, "malformed cancel request: "+reason)
	}
	if !bytes.Equal(bytes.TrimSpace(cancel), []byte("true")) {
		return nil, true, bad("cancel must be true")
	}
	r := &CashWithdrawCancelRequest{Cancel: true}
	// Checked in a fixed order, so the reason does not depend on map order: an
	// unknown field first, then request_id, then cash_secret.
	for k := range fields {
		switch k {
		case "cancel", "request_id", "cash_secret":
		default:
			return nil, true, bad("a field other than cancel, request_id and cash_secret")
		}
	}
	if v, ok := fields["request_id"]; ok {
		if json.Unmarshal(v, &r.RequestID) != nil || !ValidRequestID(r.RequestID) {
			return nil, true, bad("request_id")
		}
	}
	if v, ok := fields["cash_secret"]; ok {
		if json.Unmarshal(v, &r.CashSecret) != nil || !ValidCashSecret(r.CashSecret) {
			return nil, true, bad("cash_secret")
		}
	}
	if r.RequestID == "" {
		return nil, true, bad("request_id")
	}
	return r, true, nil
}
