package nip57

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ohstr/nmilat/utils"
)

// Failure modes specific to RequestZapInvoice.
var (
	ErrRecipientDoesNotAcceptZaps = errors.New("nip57: recipient's LNURL provider does not support zaps")
	ErrAmountOutOfRange           = errors.New("nip57: amount outside the provider's min/maxSendable range")
	ErrCallbackFailed             = errors.New("nip57: callback did not return an invoice")
)

// RequestZapInvoiceParams describes a zap payment: who to zap, how much, and
// what the resulting invoice should carry.
type RequestZapInvoiceParams struct {
	SenderPrivateKey string   // nsec hex, signs the zap request
	RecipientPubkey  string   // recipient's Nostr pubkey — "p" tag
	RecipientLud16   string   // recipient's LUD-16 identifier, resolved for the LNURL provider
	AmountMsat       int64    // required
	Relays           []string // relays the zap receipt should be published to
	Comment          string   // optional public note attached to the zap
	EventID          *string  // optional "e" tag — zapped event ID
}

// RequestZapInvoiceResult is a zap invoice request's outcome.
type RequestZapInvoiceResult struct {
	Bolt11      string
	PayResponse *utils.PayResponse // the recipient's LNURL provider info, e.g. to inspect Chains
}

// RequestZapInvoice runs the client side of a zap payment up to "pay this
// invoice" (NIP-57 Appendix A): resolve the recipient's LUD-16 identifier,
// build and sign a zap request naming that provider (kind 9734), and call
// back for an invoice. It does not pay the invoice or wait for a receipt —
// pay Bolt11 with your own Lightning client, then verify the resulting kind
// 9735 receipt with ValidateZapReceipt.
func RequestZapInvoice(ctx context.Context, client *http.Client, p RequestZapInvoiceParams) (*RequestZapInvoiceResult, error) {
	if p.AmountMsat <= 0 {
		return nil, ErrInvalidAmountValue
	}

	payResp, err := utils.FetchLud16PayResponse(ctx, client, p.RecipientLud16)
	if err != nil {
		return nil, err
	}
	if !payResp.AllowsNostr || payResp.NostrPubkey == "" {
		return nil, ErrRecipientDoesNotAcceptZaps
	}
	if payResp.MinSendable > 0 && p.AmountMsat < payResp.MinSendable {
		return nil, fmt.Errorf("%w: %d msat below minimum %d", ErrAmountOutOfRange, p.AmountMsat, payResp.MinSendable)
	}
	if payResp.MaxSendable > 0 && p.AmountMsat > payResp.MaxSendable {
		return nil, fmt.Errorf("%w: %d msat above maximum %d", ErrAmountOutOfRange, p.AmountMsat, payResp.MaxSendable)
	}

	bech32LNURL, err := utils.EncodeLNURL(utils.GetLud16URL(p.RecipientLud16))
	if err != nil {
		return nil, fmt.Errorf("encode lnurl: %w", err)
	}

	event := NewZapRequest(ZapRequestParams{
		Recipient:  p.RecipientPubkey,
		Relays:     p.Relays,
		AmountMsat: p.AmountMsat,
		Lnurl:      bech32LNURL,
		EventID:    p.EventID,
		Content:    p.Comment,
	})
	if err := event.Sign(p.SenderPrivateKey); err != nil {
		return nil, fmt.Errorf("sign zap request: %w", err)
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal zap request: %w", err)
	}

	bolt11, err := requestInvoice(ctx, client, payResp.Callback, p.AmountMsat, string(eventJSON), bech32LNURL)
	if err != nil {
		return nil, err
	}
	return &RequestZapInvoiceResult{Bolt11: bolt11, PayResponse: payResp}, nil
}

// requestInvoice calls an LNURL-pay callback with the zap request attached,
// per NIP-57 Appendix A / LUD-06.
func requestInvoice(ctx context.Context, client *http.Client, callback string, amountMsat int64, zapRequestJSON, lnurl string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, callback, nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Set("amount", fmt.Sprintf("%d", amountMsat))
	q.Set("nostr", zapRequestJSON)
	q.Set("lnurl", lnurl)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status %d", ErrCallbackFailed, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var wire struct {
		PR     string `json:"pr"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return "", fmt.Errorf("%w: parse response: %w", ErrCallbackFailed, err)
	}
	if wire.Status == "ERROR" || wire.PR == "" {
		return "", fmt.Errorf("%w: %s", ErrCallbackFailed, wire.Reason)
	}
	return wire.PR, nil
}
