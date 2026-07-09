package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/wire"
)

// WalletError is returned when a wallet service declines a NIP-47 request
// (the response's Error field is set). Method is the NIP-47 method name
// that was called (e.g. nip47.MethodPayInvoice). Use errors.As to recover
// the wallet's Code/Message instead of matching on the error string.
type WalletError struct {
	Method  string
	Code    string
	Message string
}

func (e *WalletError) Error() string {
	return fmt.Sprintf("nwc: wallet declined %s: %s: %s", e.Method, e.Code, e.Message)
}

// NWCClient is a NIP-47 (Nostr Wallet Connect) client bound to one pairing.
// It holds a single persistent WebSocket connection to the wallet's relay,
// reused across every call, and a background dispatcher that demultiplexes
// concurrent in-flight calls by subscription ID. Safe for concurrent use by
// multiple goroutines. Construct with NewNWCClient and release resources
// with Close when done.
type NWCClient struct {
	conn         *Connection
	walletPubkey string
	appPrivKey   string
	encryption   string

	mu       sync.Mutex
	subs     map[string]chan *nip47.ResponseEvent
	closed   bool
	closeErr error

	doneCh chan struct{}
}

// NewNWCClient parses pairing.RelayURLs[0] (only the first relay is used)
// and dials it, then starts a background dispatcher that owns the
// connection's incoming messages for the client's entire lifetime.
// encryption selects the request/response scheme (nip47.EncryptionNIP04 or
// nip47.EncryptionNIP44V2); "" defaults to nip47.EncryptionNIP44V2.
//
// ctx is only used for an up-front cancellation check — it is deliberately
// not threaded into the dial as the connection's lifetime context, since
// Connect's ctx parameter tears the connection down on cancellation, which
// would be a footgun for a client meant to be held and reused long-term.
// Close is the only way to end the connection's life.
func NewNWCClient(ctx context.Context, pairing *nip47.PairingInfo, encryption string) (*NWCClient, error) {
	if pairing == nil || len(pairing.RelayURLs) == 0 {
		return nil, fmt.Errorf("pairing info has no relay urls")
	}
	relayURL, err := url.Parse(pairing.RelayURLs[0])
	if err != nil {
		return nil, fmt.Errorf("invalid relay url %q: %w", pairing.RelayURLs[0], err)
	}

	if encryption == "" {
		encryption = nip47.EncryptionNIP44V2
	}
	if encryption != nip47.EncryptionNIP04 && encryption != nip47.EncryptionNIP44V2 {
		return nil, fmt.Errorf("unsupported encryption %q, must be %q or %q", encryption, nip47.EncryptionNIP04, nip47.EncryptionNIP44V2)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	conn, err := Connect(context.Background(), relayURL)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	c := &NWCClient{
		conn:         conn,
		walletPubkey: pairing.WalletPubkey,
		appPrivKey:   pairing.Secret,
		encryption:   encryption,
		subs:         make(map[string]chan *nip47.ResponseEvent),
		doneCh:       make(chan struct{}),
	}
	go c.dispatch()
	return c, nil
}

// Close closes the underlying connection and fails every in-flight and any
// future call with a terminal error. Blocks until the dispatcher goroutine
// has fully exited, so no goroutine is left running after Close returns.
// Safe to call more than once and safe to call concurrently with in-flight
// calls.
func (c *NWCClient) Close() {
	c.conn.Close()
	<-c.doneCh
}

// dispatch is the sole reader of the underlying connection's incoming
// messages for the client's whole life, fanning parsed responses out to
// whichever call registered the matching subscription ID. A single shared
// reader is required because Connection.Read()'s channel delivers each
// message to exactly one waiting goroutine — multiple calls filtering it
// concurrently by subscription ID would race and drop each other's
// responses.
func (c *NWCClient) dispatch() {
	defer close(c.doneCh)
	for {
		select {
		case msg, ok := <-c.conn.Read():
			if !ok {
				c.failAll(ErrConnectionClosed)
				return
			}
			evMsg, isEvent := msg.(*wire.EventSubscriptionResponse)
			if !isEvent {
				continue
			}
			c.mu.Lock()
			ch, found := c.subs[evMsg.SubscriptionID]
			c.mu.Unlock()
			if !found {
				continue
			}
			resp, err := nip47.ParseResponseEvent(evMsg.Event, c.appPrivKey)
			if err != nil {
				continue
			}
			select {
			case ch <- resp:
			default:
			}
		case err := <-c.conn.Errors():
			c.failAll(err)
			return
		case <-c.conn.Closed():
			c.failAll(ErrConnectionClosed)
			return
		}
	}
}

func (c *NWCClient) failAll(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed, c.closeErr = true, err
	for id, ch := range c.subs {
		close(ch)
		delete(c.subs, id)
	}
}

func (c *NWCClient) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr != nil {
		return c.closeErr
	}
	return ErrConnectionClosed
}

// register allocates a fresh subscription ID and a bufSize-buffered
// response channel, or fails immediately if the client is already closed.
func (c *NWCClient) register(bufSize int) (subID string, ch chan *nip47.ResponseEvent, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return "", nil, c.closeErr
	}
	subID = uuid.NewString()
	ch = make(chan *nip47.ResponseEvent, bufSize)
	c.subs[subID] = ch
	return subID, ch, nil
}

// unregister removes subID from the dispatch table and best-effort tells
// the relay we're done with it. Safe to call after failAll has already
// removed the entry (no-op in that case).
func (c *NWCClient) unregister(subID string) {
	c.mu.Lock()
	_, ok := c.subs[subID]
	if ok {
		delete(c.subs, subID)
	}
	c.mu.Unlock()
	if ok {
		c.conn.CloseSubscription(subID)
	}
}

// subscribeAndSend builds, signs, and sends a NIP-47 request, registering a
// bufSize-buffered response channel under a fresh subscription ID before
// sending, so no response can race the registration. The returned cleanup
// func must be called (typically via defer) exactly once.
func (c *NWCClient) subscribeAndSend(ctx context.Context, method string, params any, bufSize int) (<-chan *nip47.ResponseEvent, func(), error) {
	select {
	case <-ctx.Done():
		return nil, func() {}, ctx.Err()
	default:
	}

	subID, ch, err := c.register(bufSize)
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { c.unregister(subID) }

	reqEvent, err := nip47.NewRequestEvent(c.appPrivKey, c.walletPubkey, method, params, c.encryption)
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("build request: %w", err)
	}
	if err := reqEvent.Sign(c.appPrivKey); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("sign request: %w", err)
	}

	filters := nip01.NewSubscriptionFilterGroup(
		nip01.NewFilter().WithKinds(nip47.KindNWCResponse).WithTag("e", reqEvent.ID),
	)
	if ok := c.conn.SubscribeWithID(subID, filters); !ok {
		cleanup()
		return nil, func() {}, ErrConnectionClosed
	}
	if !c.conn.Send(reqEvent) {
		cleanup()
		return nil, func() {}, ErrConnectionClosed
	}
	return ch, cleanup, nil
}

func (c *NWCClient) waitOne(ctx context.Context, ch <-chan *nip47.ResponseEvent) (*nip47.ResponseEvent, error) {
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, c.err()
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// waitAll collects one response per id in ids (matched via
// ResponseEvent.SubPaymentID), ignoring stray or duplicate responses, until
// every id has answered or ctx is done. Returns whatever was collected so
// far alongside a non-nil error on partial completion.
func (c *NWCClient) waitAll(ctx context.Context, ch <-chan *nip47.ResponseEvent, ids []string) (map[string]*nip47.ResponseEvent, error) {
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	got := make(map[string]*nip47.ResponseEvent, len(ids))
	for len(got) < len(want) {
		select {
		case resp, ok := <-ch:
			if !ok {
				return got, c.err()
			}
			if _, expected := want[resp.SubPaymentID]; !expected {
				continue
			}
			if _, dup := got[resp.SubPaymentID]; dup {
				continue
			}
			got[resp.SubPaymentID] = resp
		case <-ctx.Done():
			return got, ctx.Err()
		}
	}
	return got, nil
}

// nwcCall performs the subscribe -> send -> wait-for-one-response ->
// error-or-unmarshal round trip shared by every single-response NWC
// method. This is the only generic in the package; it's unexported, so
// callers of PayInvoice/GetBalance/etc. never see a type parameter.
func nwcCall[TResult any](ctx context.Context, c *NWCClient, method string, params any) (*TResult, error) {
	ch, cleanup, err := c.subscribeAndSend(ctx, method, params, 1)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	resp, err := c.waitOne(ctx, ch)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &WalletError{Method: method, Code: resp.Error.Code, Message: resp.Error.Message}
	}
	var result TResult
	if len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			return nil, fmt.Errorf("unmarshal %s result: %w", method, err)
		}
	}
	return &result, nil
}

// PayInvoice pays a BOLT11 invoice.
func (c *NWCClient) PayInvoice(ctx context.Context, params nip47.PayInvoiceParams) (*nip47.PayInvoiceResult, error) {
	return nwcCall[nip47.PayInvoiceResult](ctx, c, nip47.MethodPayInvoice, params)
}

// PayKeysend pays a keysend payment.
func (c *NWCClient) PayKeysend(ctx context.Context, params nip47.PayKeysendParams) (*nip47.PayKeysendResult, error) {
	return nwcCall[nip47.PayKeysendResult](ctx, c, nip47.MethodPayKeysend, params)
}

// MakeInvoice creates a new BOLT11 invoice.
func (c *NWCClient) MakeInvoice(ctx context.Context, params nip47.MakeInvoiceParams) (*nip47.Transaction, error) {
	return nwcCall[nip47.Transaction](ctx, c, nip47.MethodMakeInvoice, params)
}

// MakeHoldInvoice creates a new hold invoice.
func (c *NWCClient) MakeHoldInvoice(ctx context.Context, params nip47.MakeHoldInvoiceParams) (*nip47.Transaction, error) {
	return nwcCall[nip47.Transaction](ctx, c, nip47.MethodMakeHoldInvoice, params)
}

// CancelHoldInvoice cancels a hold invoice.
func (c *NWCClient) CancelHoldInvoice(ctx context.Context, params nip47.CancelHoldInvoiceParams) error {
	_, err := nwcCall[struct{}](ctx, c, nip47.MethodCancelHoldInvoice, params)
	return err
}

// SettleHoldInvoice settles a hold invoice.
func (c *NWCClient) SettleHoldInvoice(ctx context.Context, params nip47.SettleHoldInvoiceParams) error {
	_, err := nwcCall[struct{}](ctx, c, nip47.MethodSettleHoldInvoice, params)
	return err
}

// LookupInvoice looks up an invoice by payment hash or invoice string.
func (c *NWCClient) LookupInvoice(ctx context.Context, params nip47.LookupInvoiceParams) (*nip47.Transaction, error) {
	return nwcCall[nip47.Transaction](ctx, c, nip47.MethodLookupInvoice, params)
}

// ListTransactions lists past transactions.
func (c *NWCClient) ListTransactions(ctx context.Context, params nip47.ListTransactionsParams) (*nip47.ListTransactionsResult, error) {
	return nwcCall[nip47.ListTransactionsResult](ctx, c, nip47.MethodListTransactions, params)
}

// GetBalance returns the wallet's current balance.
func (c *NWCClient) GetBalance(ctx context.Context) (*nip47.GetBalanceResult, error) {
	return nwcCall[nip47.GetBalanceResult](ctx, c, nip47.MethodGetBalance, nil)
}

// GetInfo returns the wallet's capabilities and node info.
func (c *NWCClient) GetInfo(ctx context.Context) (*nip47.GetInfoResult, error) {
	return nwcCall[nip47.GetInfoResult](ctx, c, nip47.MethodGetInfo, nil)
}

// GetBudget returns the connection's budget status.
func (c *NWCClient) GetBudget(ctx context.Context) (*nip47.GetBudgetResult, error) {
	return nwcCall[nip47.GetBudgetResult](ctx, c, nip47.MethodGetBudget, nil)
}

// SignMessage asks the wallet to sign an arbitrary message.
func (c *NWCClient) SignMessage(ctx context.Context, params nip47.SignMessageParams) (*nip47.SignMessageResult, error) {
	return nwcCall[nip47.SignMessageResult](ctx, c, nip47.MethodSignMessage, params)
}

// MultiPayInvoiceResult is one sub-payment's outcome from MultiPayInvoice:
// exactly one of Result or Error is set, correlated back to the request
// item via its Id (MultiPayInvoiceItem.Id).
type MultiPayInvoiceResult struct {
	Id     string
	Result *nip47.PayInvoiceResult
	Error  *nip47.Error
}

// MultiPayKeysendResult is one sub-payment's outcome from MultiPayKeysend:
// exactly one of Result or Error is set, correlated back to the request
// item via its Id (MultiPayKeysendItem.Id).
type MultiPayKeysendResult struct {
	Id     string
	Result *nip47.PayKeysendResult
	Error  *nip47.Error
}

// validateSubPaymentIDs rejects empty or duplicate Ids up front: the wallet
// correlates each fan-out response back to its request item solely via the
// "d" tag mirroring Id, so an empty or repeated Id makes correct
// demultiplexing impossible.
func validateSubPaymentIDs(ids []string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			return fmt.Errorf("sub-payment id must not be empty")
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("duplicate sub-payment id %q", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// MultiPayInvoice pays multiple BOLT11 invoices in one request, waiting for
// every sub-payment's response event or ctx.Done(), whichever first. On
// full success every params.Invoices item has a corresponding entry (in
// request order) with either Result or Error set — a per-item wallet
// decline does not fail the overall call. On partial completion (ctx
// expires or the connection dies before every sub-payment answered) it
// returns whatever was collected so far, in request order, together with a
// non-nil error.
func (c *NWCClient) MultiPayInvoice(ctx context.Context, params nip47.MultiPayInvoiceParams) ([]MultiPayInvoiceResult, error) {
	ids := make([]string, len(params.Invoices))
	for i, item := range params.Invoices {
		ids[i] = item.Id
	}
	if err := validateSubPaymentIDs(ids); err != nil {
		return nil, err
	}

	ch, cleanup, err := c.subscribeAndSend(ctx, nip47.MethodMultiPayInvoice, params, len(ids))
	if err != nil {
		return nil, err
	}
	defer cleanup()

	got, waitErr := c.waitAll(ctx, ch, ids)

	results := make([]MultiPayInvoiceResult, 0, len(got))
	for _, id := range ids {
		resp, ok := got[id]
		if !ok {
			continue
		}
		item := MultiPayInvoiceResult{Id: id, Error: resp.Error}
		if resp.Error == nil {
			var pr nip47.PayInvoiceResult
			if err := json.Unmarshal(resp.Result, &pr); err != nil {
				item.Error = &nip47.Error{Code: nip47.ErrInternal, Message: fmt.Sprintf("unmarshal result: %v", err)}
			} else {
				item.Result = &pr
			}
		}
		results = append(results, item)
	}
	return results, waitErr
}

// MultiPayKeysend pays multiple keysend payments in one request. See
// MultiPayInvoice for collection semantics.
func (c *NWCClient) MultiPayKeysend(ctx context.Context, params nip47.MultiPayKeysendParams) ([]MultiPayKeysendResult, error) {
	ids := make([]string, len(params.Keysends))
	for i, item := range params.Keysends {
		ids[i] = item.Id
	}
	if err := validateSubPaymentIDs(ids); err != nil {
		return nil, err
	}

	ch, cleanup, err := c.subscribeAndSend(ctx, nip47.MethodMultiPayKeysend, params, len(ids))
	if err != nil {
		return nil, err
	}
	defer cleanup()

	got, waitErr := c.waitAll(ctx, ch, ids)

	results := make([]MultiPayKeysendResult, 0, len(got))
	for _, id := range ids {
		resp, ok := got[id]
		if !ok {
			continue
		}
		item := MultiPayKeysendResult{Id: id, Error: resp.Error}
		if resp.Error == nil {
			var pr nip47.PayKeysendResult
			if err := json.Unmarshal(resp.Result, &pr); err != nil {
				item.Error = &nip47.Error{Code: nip47.ErrInternal, Message: fmt.Sprintf("unmarshal result: %v", err)}
			} else {
				item.Result = &pr
			}
		}
		results = append(results, item)
	}
	return results, waitErr
}

// Call sends method with params and returns the raw parsed response
// envelope — SubPaymentID, RequestEventID, and Response.Error verbatim,
// without converting a wallet decline into a Go error — the caller
// inspects resp.Error themselves. Use this for wallet-specific/nonstandard
// methods not covered by the typed methods above. It waits for exactly one
// response event; it is not suitable for fan-out under a non-standard
// method name.
func (c *NWCClient) Call(ctx context.Context, method string, params any) (*nip47.ResponseEvent, error) {
	ch, cleanup, err := c.subscribeAndSend(ctx, method, params, 1)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return c.waitOne(ctx, ch)
}
