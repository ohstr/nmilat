package client

import (
	"fmt"
	"net/http"

	"github.com/ohstr/nmilat/nipB7"
)

// HTTPError is returned when a Blossom server responds with a 4xx/5xx
// status to a request that isn't more specifically classified (see
// PaymentRequiredError). Reason is the server's optional X-Reason
// diagnostic (BUD-01) — a human-readable message, never meant to drive
// control flow.
type HTTPError struct {
	Server     string
	StatusCode int
	Reason     string
}

func (e *HTTPError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("nipB7/client: %s: %d %s: %s", e.Server, e.StatusCode, http.StatusText(e.StatusCode), e.Reason)
	}
	return fmt.Sprintf("nipB7/client: %s: %d %s", e.Server, e.StatusCode, http.StatusText(e.StatusCode))
}

// PaymentRequiredError specializes HTTPError for BUD-07's 402 Payment
// Required response: Payment carries the parsed X-Cashu/X-Lightning
// headers so a caller can settle payment out of band and retry the request
// with proof attached via Payment.SetProof.
type PaymentRequiredError struct {
	HTTPError
	Payment nipB7.PaymentRequest
}

// newResponseError classifies a non-2xx response into the most specific
// error type available.
func newResponseError(server string, resp *http.Response) error {
	base := HTTPError{Server: server, StatusCode: resp.StatusCode, Reason: nipB7.ReasonFromResponse(resp.Header)}
	if resp.StatusCode == http.StatusPaymentRequired {
		if payment, ok := nipB7.ParsePaymentRequest(resp.Header); ok {
			return &PaymentRequiredError{HTTPError: base, Payment: payment}
		}
	}
	return &base
}
