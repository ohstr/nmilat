package nipB7

import (
	"errors"
	"net/http"
)

// HTTP header names carrying payment details on a BUD-07 402 Payment
// Required response, and the payment proof a client echoes back on retry.
const (
	HeaderCashu     = "X-Cashu"
	HeaderLightning = "X-Lightning"
)

// Payment method names for PaymentRequest.SetProof.
const (
	PaymentMethodCashu     = "cashu"
	PaymentMethodLightning = "lightning"
)

// ErrUnsupportedPaymentMethod is returned by PaymentRequest.SetProof for any
// method other than PaymentMethodCashu/PaymentMethodLightning.
var ErrUnsupportedPaymentMethod = errors.New("nipB7: unsupported payment method")

// PaymentRequest is the payment information a server attaches to a 402
// Payment Required response (BUD-07). A server MAY offer more than one
// method at once; a zero value in either field means that method wasn't
// offered.
type PaymentRequest struct {
	Cashu     string // NUT-24 encoded token/quote
	Lightning string // BOLT-11 invoice
}

// ParsePaymentRequest reads the X-Cashu/X-Lightning headers from a 402
// response. ok is false if neither header is present.
func ParsePaymentRequest(h http.Header) (req PaymentRequest, ok bool) {
	req = PaymentRequest{Cashu: h.Get(HeaderCashu), Lightning: h.Get(HeaderLightning)}
	return req, req.Cashu != "" || req.Lightning != ""
}

// SetProof writes proof (a completed payment's serialized token or
// preimage) onto h under the header for method, so a retried request can
// present it as BUD-07 requires: "the same X-{payment_method} header that
// was chosen." method must be PaymentMethodCashu or PaymentMethodLightning.
func (p PaymentRequest) SetProof(h http.Header, method, proof string) error {
	switch method {
	case PaymentMethodCashu:
		h.Set(HeaderCashu, proof)
	case PaymentMethodLightning:
		h.Set(HeaderLightning, proof)
	default:
		return ErrUnsupportedPaymentMethod
	}
	return nil
}
