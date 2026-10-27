package transport

// BearerShapeOK is the Hub's I8 check of an item's proof and cash_secret
// (NIP-CASH §Serving an Envelope):
//
//   - an item carrying both is refused, whatever its method;
//   - cash_redeem, cash_withdraw, cash_transfer and cash_consolidate need one;
//   - cash_order needs a proof;
//   - cash_status and cash_withdraw_quote never carry a cash_secret;
//   - a cash_status or cash_withdraw_quote with neither passes (served on its bill
//     proof alone when the slice is cash-mode).
//
// A cash_withdraw cancel request is checked as the cash_lookup it serves as
// (nipcash.ServingMethod).
func BearerShapeOK(method string, hasProof, hasSecret bool) bool {
	if hasProof && hasSecret {
		return false
	}
	switch method {
	case "cash_redeem", "cash_withdraw", "cash_transfer", "cash_consolidate":
		return hasProof || hasSecret
	case "cash_order":
		return hasProof
	case "cash_status", "cash_withdraw_quote":
		return !hasSecret
	}
	return true
}
