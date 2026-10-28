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
	// The codes NIP-CASH and NIP-CW add.
	ErrRequestReused        = "REQUEST_REUSED"
	ErrLimitExceeded        = "LIMIT_EXCEEDED"
	ErrInsufficientCapacity = "INSUFFICIENT_CAPACITY"
	ErrRotationPending      = "ROTATION_PENDING"
	ErrFrozen               = "FROZEN"
	ErrNotReady             = "NOT_READY"
	ErrWalletExists         = "WALLET_EXISTS"
)

// Notification type values, used as the "notification_type" field of a
// Notification.
const (
	NotificationPaymentReceived     = "payment_received"
	NotificationPaymentSent         = "payment_sent"
	NotificationHoldInvoiceAccepted = "hold_invoice_accepted"
	// NIP-CW connection-key rotation and freeze notifications.
	NotificationRotationPending   = "rotation_pending"
	NotificationRotationCancelled = "rotation_cancelled"
	NotificationRotationCompleted = "rotation_completed"
	NotificationWalletFrozen      = "wallet_frozen"
)

// MethodDeleteCircleWallet is NIP-CW's member wallet deletion.
const MethodDeleteCircleWallet = "delete_circle_wallet"

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
	Type            string `json:"type"`
	State           string `json:"state,omitempty"`
	Invoice         string `json:"invoice,omitempty"`
	Description     string `json:"description,omitempty"`
	DescriptionHash string `json:"description_hash,omitempty"`
	Preimage        string `json:"preimage,omitempty"`
	PaymentHash     string `json:"payment_hash"`
	AmountMloki     int64  `json:"amount"`
	FeesPaidMloki   int64  `json:"fees_paid,omitempty"`
	// FeeSkimMloki is a circle_hub's forwarding-fee cut (CircleHubConfig.
	// FeesPpm) debited from a circle_wallet's own outgoing payment, on top of
	// FeesPaidMloki (the real Lightning routing fee) — present only for a
	// circle_wallet's own outgoing, non-self payments (see lokihub's
	// transactions_service.go validateCanPay/nip47/controllers/models.go
	// payResponse.FeeSkimMloki, which this mirrors). Without this field, a
	// circle member had no way to learn why their balance dropped by more
	// than AmountMloki+FeesPaidMloki.
	FeeSkimMloki int64           `json:"fee_skim_mloki,omitempty"`
	CreatedAt    int64           `json:"created_at"`
	ExpiresAt    *int64          `json:"expires_at,omitempty"`
	SettledAt    *int64          `json:"settled_at,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
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
	// FeeSkimMloki — see Transaction.FeeSkimMloki's doc comment; identical
	// meaning, just on the immediate pay_invoice response rather than a
	// list_transactions row.
	FeeSkimMloki int64 `json:"fee_skim_mloki,omitempty"`
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
	// FeeSkimMloki — see Transaction.FeeSkimMloki's doc comment.
	FeeSkimMloki int64 `json:"fee_skim_mloki,omitempty"`
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
	// TotalReceiveBudget and UsedReceiveBudget are a Circle Wallet's receive
	// budget (NIP-CW); absent on other connections.
	TotalReceiveBudget *int64 `json:"total_receive_budget,omitempty"`
	UsedReceiveBudget  *int64 `json:"used_receive_budget,omitempty"`
}

// RemainingSend is total_budget − used_budget, never below zero.
func (r GetBudgetResult) RemainingSend() int64 { return max(r.TotalBudgetMloki-r.UsedBudgetMloki, 0) }

// RemainingReceive is total_receive_budget − used_receive_budget, never below
// zero; false when the connection reports no receive budget.
func (r GetBudgetResult) RemainingReceive() (int64, bool) {
	if r.TotalReceiveBudget == nil {
		return 0, false
	}
	used := int64(0)
	if r.UsedReceiveBudget != nil {
		used = *r.UsedReceiveBudget
	}
	return max(*r.TotalReceiveBudget-used, 0), true
}

// GetInfoResult is the get_info response payload.
type GetInfoResult struct {
	Alias   string `json:"alias,omitempty"`
	Color   string `json:"color,omitempty"`
	Pubkey  string `json:"pubkey,omitempty"`
	Network string `json:"network,omitempty"`
	// Chain is the chain's name, e.g. bitcoin (NIP-CASH §Network and Chain).
	Chain         string   `json:"chain,omitempty"`
	BlockHeight   int64    `json:"block_height,omitempty"`
	BlockHash     string   `json:"block_hash,omitempty"`
	Methods       []string `json:"methods"`
	Notifications []string `json:"notifications,omitempty"`
	// PrivateMethods names the methods this connection's wallet serves over the
	// NIP-CASH private transport rather than on this kind-23194 connection.
	//
	// It exists because `methods` means "callable HERE" and the four bill methods are
	// not: they are refused on 23194 with NOT_IMPLEMENTED. Listing them there promised
	// something this transport will not do, so they were removed — which left no
	// wire-level signal that they exist at all, since the kind-11190 announcement
	// carries only inbox, limits and relays. A client had to hardcode the set from
	// NIP-CASH §Which Methods a Hub Serves.
	//
	// A sibling field rather than an annotation inside `methods`, because `methods` is a
	// flat []string with nowhere to mark an entry, and keeping it strictly
	// "callable here" is what makes it spec-correct.
	//
	// Informational only. Authorization is still the hub's per-item scope check on the
	// private transport; a client MUST NOT read presence here as permission.
	PrivateMethods []string `json:"private_methods,omitempty"`
	// CircleWallet is set only when the dialed connection IS a circle_hub's
	// own connection (lokihub's get_info_controller.go only attaches it for
	// app.Kind == circle_hub, never for an individual circle_wallet member) —
	// the terms a prospective/current member needs to evaluate the Hub
	// before or after joining. Absent from every other get_info response,
	// including a joined member's own `wallet get-info`.
	CircleWallet *CircleWalletInfo `json:"circle_wallet,omitempty"`
}

// CircleWalletInfo is get_info's circle_hub-only terms block — see
// GetInfoResult.CircleWallet's doc comment for when it's populated.
type CircleWalletInfo struct {
	AvailableMillis int64 `json:"available_millis"`
	MaxExpSecs      int   `json:"max_exp_secs"`
	// FeesPpm is the circle_hub's configured forwarding fee (parts per
	// million of each circle_wallet child's own outgoing, non-self payment —
	// see transactions_service.go's CalculateFeeSkimMloki on the Hub side).
	FeesPpm int `json:"fees_ppm"`
	// CirclePolicy is CirclePolicyAllowlist or CirclePolicyFollowSet.
	CirclePolicy string `json:"circle_policy"`
	// Identity is the node's x-only key that signs the Hub's kind-11190
	// announcement, present only when the Hub offers NIP-CW Private Join. Trust
	// it only from this response: whoever supplies it picks the inbox the join is
	// encrypted to.
	Identity string `json:"identity,omitempty"`
	// PerWalletMaxMillis is the Hub's ceiling on a joiner's max_amount, in the
	// same unit. Zero means the Hub didn't report it.
	PerWalletMaxMillis int64 `json:"per_wallet_max_millis,omitempty"`
	// MinBudgetRenewal is the tightest budget_renewal the Hub accepts
	// ("daily"/"weekly"/"monthly"/"yearly"/"never"). Empty means not reported.
	MinBudgetRenewal string `json:"min_budget_renewal,omitempty"`
	// FeeReserve is the Hub's routing-fee reserve terms.
	FeeReserve *FeeReserve `json:"fee_reserve"`
	// DustThresholdMillis is the dust floor below which a wallet is deleted.
	DustThresholdMillis *int64 `json:"dust_threshold_millis"`
	// RotationDelaySecs is present only on a Hub that supports rotation.
	RotationDelaySecs *int64 `json:"rotation_delay_secs,omitempty"`
	// PerWalletMaxReceiveMillis is the Hub's OPTIONAL per-wallet receive ceiling.
	PerWalletMaxReceiveMillis int64 `json:"per_wallet_max_receive_millis,omitempty"`
	// Accepting says whether the circle takes joins now; nil when absent, which
	// a join client treats as non-conforming.
	Accepting *bool `json:"accepting,omitempty"`

	present map[string]bool
}

// FeeReserve is a Circle Wallet Hub's routing-fee reserve.
type FeeReserve struct {
	Ppm       int64 `json:"ppm"`
	MinMillis int64 `json:"min_millis"`
}

// alwaysCircleKeys are the circle_wallet keys every Hub reports.
var alwaysCircleKeys = []string{"available_millis", "max_exp_secs", "fees_ppm", "fee_reserve",
	"dust_threshold_millis", "circle_policy", "identity", "accepting"}

// UnmarshalJSON remembers which keys were present, since fees_ppm 0 and an
// absent fees_ppm decode alike.
func (i *CircleWalletInfo) UnmarshalJSON(b []byte) error {
	type plain CircleWalletInfo
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		return err
	}
	*i = CircleWalletInfo(p)
	i.present = make(map[string]bool, len(keys))
	for k := range keys {
		i.present[k] = true
	}
	return nil
}

// MissingAlways lists the "always" keys the decoded block did not carry. A block
// built in code (not decoded) reports none.
func (i CircleWalletInfo) MissingAlways() []string {
	if i.present == nil {
		return nil
	}
	var out []string
	for _, k := range alwaysCircleKeys {
		if !i.present[k] {
			out = append(out, k)
		}
	}
	return out
}

// The networks get_info's network names (NIP-CASH §Network and Chain).
const (
	NetworkMainnet = "mainnet"
	NetworkTestnet = "testnet"
	NetworkSignet  = "signet"
	NetworkRegtest = "regtest"
)

// ValidNetwork reports one of the four network values.
func ValidNetwork(s string) bool {
	switch s {
	case NetworkMainnet, NetworkTestnet, NetworkSignet, NetworkRegtest:
		return true
	}
	return false
}

// RotationPending is the rotation_pending notification payload.
type RotationPending struct {
	ConnectionPubkey string `json:"connection_pubkey"`
	CompletesAt      int64  `json:"completes_at"`
}

// RotationChanged is the rotation_cancelled and rotation_completed payload.
type RotationChanged struct {
	ConnectionPubkey string `json:"connection_pubkey"`
}

// circle_policy values (NIP-CW §Membership).
const (
	CirclePolicyAllowlist = "allowlist"
	CirclePolicyFollowSet = "follow_set"
)

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
