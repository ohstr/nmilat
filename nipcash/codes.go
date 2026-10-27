package nipcash

// The error codes of NIP-CASH §Errors.
const (
	ErrCodeBadRequest          = "BAD_REQUEST"
	ErrCodeRequestReused       = "REQUEST_REUSED"
	ErrCodeRestricted          = "RESTRICTED"
	ErrCodeUnauthorized        = "UNAUTHORIZED"
	ErrCodeInsufficientBalance = "INSUFFICIENT_BALANCE"
	ErrCodeQuotaExceeded       = "QUOTA_EXCEEDED"
	ErrCodeRateLimited         = "RATE_LIMITED"
	ErrCodeNotFound            = "NOT_FOUND"
	ErrCodeNotImplemented      = "NOT_IMPLEMENTED"
	ErrCodePaymentFailed       = "PAYMENT_FAILED"
	ErrCodeInternal            = "INTERNAL"
)

// CodeRetryable follows the §Errors "retry?" column: UNAUTHORIZED (with a valid
// proof), INSUFFICIENT_BALANCE, QUOTA_EXCEEDED (with less), RATE_LIMITED,
// PAYMENT_FAILED and INTERNAL may be retried; the rest may not.
func CodeRetryable(code string) bool {
	switch code {
	case ErrCodeUnauthorized, ErrCodeInsufficientBalance, ErrCodeQuotaExceeded,
		ErrCodeRateLimited, ErrCodePaymentFailed, ErrCodeInternal:
		return true
	}
	return false
}

// FinalCode reports the one code that closes a call carrying a request_id as
// failed: BAD_REQUEST, item- or envelope-level. Any other code leaves the call
// open: the client keeps it pending and looks it up.
func FinalCode(code string) bool { return code == ErrCodeBadRequest }
