package nipCO

import (
	"fmt"

	"github.com/ohstr/nmilat/nip57"
)

// CheckOrderInvoice is a client's check of a Lightning order reply's invoice
// (NIP-CO §Response): a decodable BOLT11 invoice whose amount is exactly
// pay_millis, else an error wrapping ErrOrderReply. An on-chain order passes.
func CheckOrderInvoice(o *Order) error {
	if o.Payment != PaymentLightning {
		return nil
	}
	inv, err := nip57.DecodeBolt11(o.Invoice)
	if err != nil {
		return fmt.Errorf("%w: invoice: %v", ErrOrderReply, err)
	}
	if inv.AmountMloki < 0 || uint64(inv.AmountMloki) != o.PayMillis {
		return fmt.Errorf("%w: the invoice is for %d, pay_millis is %d", ErrOrderReply, inv.AmountMloki, o.PayMillis)
	}
	return nil
}
