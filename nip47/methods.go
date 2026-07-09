package nip47

import "encoding/json"

// Standard NIP-47 method names, used as the "method" field of a Request and
// the "result_type" field of its Response.
const (
	MethodPayInvoice        = "pay_invoice"
	MethodMultiPayInvoice   = "multi_pay_invoice"
	MethodPayKeysend        = "pay_keysend"
	MethodMultiPayKeysend   = "multi_pay_keysend"
	MethodMakeInvoice       = "make_invoice"
	MethodMakeHoldInvoice   = "make_hold_invoice"
	MethodCancelHoldInvoice = "cancel_hold_invoice"
	MethodSettleHoldInvoice = "settle_hold_invoice"
	MethodLookupInvoice     = "lookup_invoice"
	MethodListTransactions  = "list_transactions"
	MethodGetBalance        = "get_balance"
	MethodGetInfo           = "get_info"
	MethodSignMessage       = "sign_message"
	// MethodGetBudget is not defined by the NIP-47 spec text, but like
	// MethodMultiPayInvoice/MethodMultiPayKeysend/MethodSignMessage it is a
	// widely-implemented extension method (alongside get_info) dispatched
	// through the same request/response envelope as any spec method.
	MethodGetBudget = "get_budget"
)

// NIP-47 error codes, used as the "code" field of a Response's Error.
const (
	ErrRateLimited           = "RATE_LIMITED"
	ErrNotImplemented        = "NOT_IMPLEMENTED"
	ErrInsufficientBalance   = "INSUFFICIENT_BALANCE"
	ErrQuotaExceeded         = "QUOTA_EXCEEDED"
	ErrRestricted            = "RESTRICTED"
	ErrUnauthorized          = "UNAUTHORIZED"
	ErrInternal              = "INTERNAL"
	ErrUnsupportedEncryption = "UNSUPPORTED_ENCRYPTION"
	ErrOther                 = "OTHER"
	ErrPaymentFailed         = "PAYMENT_FAILED"
	ErrNotFound              = "NOT_FOUND"
	ErrExpired               = "EXPIRED"
	ErrBadRequest            = "BAD_REQUEST"
)

// Notification type values, used as the "notification_type" field of a
// Notification.
const (
	NotificationPaymentReceived     = "payment_received"
	NotificationPaymentSent         = "payment_sent"
	NotificationHoldInvoiceAccepted = "hold_invoice_accepted"
)

// Request is the JSON shape of a decrypted request event's content.
type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Error is a NIP-47 response error object.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response is the JSON shape of a decrypted response event's content.
type Response struct {
	ResultType string          `json:"result_type"`
	Error      *Error          `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
}

// Notification is the JSON shape of a decrypted notification event's content.
type Notification struct {
	NotificationType string          `json:"notification_type"`
	Notification     json.RawMessage `json:"notification"`
}

// Transaction is the standard NIP-47 transaction object shape: used in
// make_invoice/make_hold_invoice/lookup_invoice results, list_transactions
// result items, and payment_received/payment_sent notification payloads.
type Transaction struct {
	Type            string          `json:"type"`
	State           string          `json:"state,omitempty"`
	Invoice         string          `json:"invoice,omitempty"`
	Description     string          `json:"description,omitempty"`
	DescriptionHash string          `json:"description_hash,omitempty"`
	Preimage        string          `json:"preimage,omitempty"`
	PaymentHash     string          `json:"payment_hash"`
	AmountMloki     int64           `json:"amount"`
	FeesPaidMloki   int64           `json:"fees_paid,omitempty"`
	CreatedAt       int64           `json:"created_at"`
	ExpiresAt       *int64          `json:"expires_at,omitempty"`
	SettledAt       *int64          `json:"settled_at,omitempty"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
}

// TLVRecord is a keysend custom TLV record.
type TLVRecord struct {
	Type  uint64 `json:"type"`
	Value string `json:"value"`
}

// PayInvoiceParams is the pay_invoice request payload.
type PayInvoiceParams struct {
	Invoice  string          `json:"invoice"`
	Amount   *int64          `json:"amount,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// PayInvoiceResult is the pay_invoice response payload.
type PayInvoiceResult struct {
	Preimage      string `json:"preimage"`
	FeesPaidMloki int64  `json:"fees_paid,omitempty"`
}

// PayKeysendParams is the pay_keysend request payload.
type PayKeysendParams struct {
	Amount     int64       `json:"amount"`
	Pubkey     string      `json:"pubkey"`
	Preimage   string      `json:"preimage,omitempty"`
	TLVRecords []TLVRecord `json:"tlv_records,omitempty"`
}

// PayKeysendResult is the pay_keysend response payload.
type PayKeysendResult struct {
	Preimage      string `json:"preimage"`
	FeesPaidMloki int64  `json:"fees_paid,omitempty"`
}

// MultiPayInvoiceItem is one sub-payment of a multi_pay_invoice request.
// multi_pay_invoice/multi_pay_keysend are extension methods observed in NWC
// implementations (Alby Hub and its derivatives) rather than defined by the
// NIP-47 spec text itself; each sub-payment gets its own response event,
// tagged with a "d" tag equal to the sub-payment's Id (see
// NewResponseEvent's extraTags parameter).
type MultiPayInvoiceItem struct {
	PayInvoiceParams
	Id string `json:"id,omitempty"`
}

// MultiPayInvoiceParams is the multi_pay_invoice request payload.
type MultiPayInvoiceParams struct {
	Invoices []MultiPayInvoiceItem `json:"invoices"`
}

// MultiPayKeysendItem is one sub-payment of a multi_pay_keysend request.
type MultiPayKeysendItem struct {
	PayKeysendParams
	Id string `json:"id,omitempty"`
}

// MultiPayKeysendParams is the multi_pay_keysend request payload.
type MultiPayKeysendParams struct {
	Keysends []MultiPayKeysendItem `json:"keysends"`
}

// MakeInvoiceParams is the make_invoice request payload.
type MakeInvoiceParams struct {
	Amount          int64           `json:"amount"`
	Description     string          `json:"description,omitempty"`
	DescriptionHash string          `json:"description_hash,omitempty"`
	Expiry          *int64          `json:"expiry,omitempty"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
}

// MakeHoldInvoiceParams is the make_hold_invoice request payload.
type MakeHoldInvoiceParams struct {
	Amount             int64  `json:"amount"`
	Description        string `json:"description,omitempty"`
	DescriptionHash    string `json:"description_hash,omitempty"`
	Expiry             *int64 `json:"expiry,omitempty"`
	PaymentHash        string `json:"payment_hash"`
	MinCltvExpiryDelta *int64 `json:"min_cltv_expiry_delta,omitempty"`
}

// CancelHoldInvoiceParams is the cancel_hold_invoice request payload.
type CancelHoldInvoiceParams struct {
	PaymentHash string `json:"payment_hash"`
}

// SettleHoldInvoiceParams is the settle_hold_invoice request payload.
type SettleHoldInvoiceParams struct {
	Preimage string `json:"preimage"`
}

// LookupInvoiceParams is the lookup_invoice request payload. Exactly one of
// PaymentHash or Invoice should be set.
type LookupInvoiceParams struct {
	PaymentHash string `json:"payment_hash,omitempty"`
	Invoice     string `json:"invoice,omitempty"`
}

// ListTransactionsParams is the list_transactions request payload.
type ListTransactionsParams struct {
	From   *int64 `json:"from,omitempty"`
	Until  *int64 `json:"until,omitempty"`
	Limit  *int64 `json:"limit,omitempty"`
	Offset *int64 `json:"offset,omitempty"`
	Unpaid bool   `json:"unpaid,omitempty"`
	Type   string `json:"type,omitempty"`
}

// ListTransactionsResult is the list_transactions response payload.
type ListTransactionsResult struct {
	Transactions []Transaction `json:"transactions"`
}

// GetBalanceResult is the get_balance response payload.
type GetBalanceResult struct {
	BalanceMloki int64 `json:"balance"`
}

// GetBudgetResult is the get_budget response payload. Like MethodGetBudget
// itself, this is an extension not defined by the NIP-47 spec text. It
// takes no params, like get_balance/get_info.
type GetBudgetResult struct {
	UsedBudgetMloki  int64  `json:"used_budget"`
	TotalBudgetMloki int64  `json:"total_budget"`
	RenewsAt         *int64 `json:"renews_at,omitempty"`
	RenewalPeriod    string `json:"renewal_period"`
}

// GetInfoResult is the get_info response payload.
type GetInfoResult struct {
	Alias         string   `json:"alias,omitempty"`
	Color         string   `json:"color,omitempty"`
	Pubkey        string   `json:"pubkey,omitempty"`
	Network       string   `json:"network,omitempty"`
	BlockHeight   int64    `json:"block_height,omitempty"`
	BlockHash     string   `json:"block_hash,omitempty"`
	Methods       []string `json:"methods"`
	Notifications []string `json:"notifications,omitempty"`
}

// SignMessageParams is the sign_message request payload. Like
// multi_pay_invoice, sign_message is not defined by the NIP-47 spec text but
// is present in the reference info-event example and widely implemented.
type SignMessageParams struct {
	Message string `json:"message"`
}

// SignMessageResult is the sign_message response payload.
type SignMessageResult struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}
