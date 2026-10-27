package nipCO

import (
	"fmt"
	"math/bits"

	"github.com/ohstr/nmilat/nipcash"
)

// OrderError is a Hub's refusal of an order: Code is BAD_REQUEST, RESTRICTED
// or QUOTA_EXCEEDED, Step the NIP-CO §Processing Algorithm step that refused it.
type OrderError struct {
	Code, Reason string
	Step         int
}

func (e *OrderError) Error() string {
	return fmt.Sprintf("nipCO: %s at step %d: %s", e.Code, e.Step, e.Reason)
}

func badRequest(reason string) *OrderError {
	return &OrderError{Code: nipcash.ErrCodeBadRequest, Reason: reason, Step: 3}
}

// PlacementInput is what a Hub knows when it places an order. IATrusted is
// whether the recipient's IA is trusted now (true when the recipient names
// none). OpenMillis and OpenOnchainCount are the open orders of the request's
// payment kind; OpenOnchainCeiling 0 means the Hub sets no count bound.
// LightningReceivable is whether the Hub can expect to receive a Lightning
// payment of the order's pay_millis.
type PlacementInput struct {
	Terms                                Terms
	Retired, IATrusted                   bool
	OpenMillis, OpenCeiling              uint64
	OpenOnchainCount, OpenOnchainCeiling uint64
	LightningReceivable                  bool
}

// CheckPlacement runs NIP-CO §Processing Algorithm steps 2 to 5 in order and
// returns the first refusal as an *OrderError: step 2, a retired connection or a
// payment kind the terms do not offer (RESTRICTED); step 3, the defect
// ParseCashOrderRequest recorded (BAD_REQUEST), then an untrusted IA
// (RESTRICTED); step 4, an amount outside min_millis..max_millis (RESTRICTED);
// step 5, the open-order ceiling of the kind, the open on-chain order count, or
// a Lightning order the Hub cannot expect to receive (QUOTA_EXCEEDED). nil
// places the order.
func CheckPlacement(req *CashOrderRequest, in PlacementInput) error {
	if req == nil {
		return badRequest("no request")
	}
	if in.Retired {
		return &OrderError{Code: nipcash.ErrCodeRestricted, Reason: "this Order connection is retired", Step: 2}
	}
	k := in.Terms.Kind(req.Payment)
	if (req.Payment == PaymentLightning || req.Payment == PaymentOnchain) && k == nil {
		return &OrderError{Code: nipcash.ErrCodeRestricted, Reason: req.Payment + " is not sold here", Step: 2}
	}
	if req.defect != nil {
		return req.defect
	}
	if k == nil {
		return badRequest("payment is not lightning or onchain")
	}
	if !in.IATrusted {
		return &OrderError{Code: nipcash.ErrCodeRestricted, Reason: "the recipient's IA is not trusted", Step: 3}
	}
	if req.AmountMillis < k.MinMillis || req.AmountMillis > k.MaxMillis {
		return &OrderError{Code: nipcash.ErrCodeRestricted, Step: 4,
			Reason: fmt.Sprintf("amount_millis outside %d..%d", k.MinMillis, k.MaxMillis)}
	}
	if total, carry := bits.Add64(in.OpenMillis, req.AmountMillis, 0); carry != 0 || total > in.OpenCeiling {
		return &OrderError{Code: nipcash.ErrCodeQuotaExceeded, Reason: "the open-order ceiling is reached", Step: 5}
	}
	if req.Payment == PaymentOnchain && in.OpenOnchainCeiling > 0 && in.OpenOnchainCount >= in.OpenOnchainCeiling {
		return &OrderError{Code: nipcash.ErrCodeQuotaExceeded, Reason: "too many open on-chain orders", Step: 5}
	}
	if req.Payment == PaymentLightning && !in.LightningReceivable {
		return &OrderError{Code: nipcash.ErrCodeQuotaExceeded, Reason: "the Hub cannot expect to receive this payment", Step: 5}
	}
	return nil
}
