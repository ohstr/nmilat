// Package client orders cash over an Order connection (NIP-CO): it decodes and
// verifies a cashorder1 string, reads the terms with get_info and runs the
// online check, places cash_order on NIP-CASH's private transport, reads the
// order with cash_lookup and listens for its notices.
//
// Every order is written ahead to a nipcash/client Journal before it is sent,
// and recovered with nipcash/client.Recover, passing OrderClient.Lookup.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// Options tunes a connection. Session options reach the private-transport
// session (for example nipcash/client.WithPowBudget).
type Options struct {
	Session []cashclient.SessionOption
}

var (
	// ErrOrderNotSold is terms that sell nothing on this connection, or not the
	// payment kind asked for. Nothing is written or sent.
	ErrOrderNotSold = errors.New("nipCO/client: the Hub sells nothing of this kind on this connection")
	// ErrOrderReplyInvalid is an order reply a client must not show to pay: an
	// on-chain address that is not a segwit address of the Hub's network and
	// chain. The call stays pending.
	ErrOrderReplyInvalid = errors.New("nipCO/client: the order reply is invalid; nothing to pay")
)

// OrderClient orders over one Order connection. Construct with Connect.
type OrderClient struct {
	conn     nipCO.OrderConnection
	verified bool
	nwc      *relayclient.NWCClient
	session  *cashclient.BatchSession

	mu       sync.Mutex
	network  string
	accepted map[string][]string // notify → the relays that accepted the order
}

// Connect dials a cashorder1 string (NIP-CO §Client Behavior, step 1): decode,
// verify TLV 5 (an unverified string still connects, Verified false: report it,
// the caller decides), get_info with the online check (pubkey = TLV 4, chain =
// TLV 6, else nipcash.ErrHubIdentityMismatch or ErrChainMismatch) and valid
// terms, then the Hub's announcement fetched from TLV 1 and verified against
// TLV 4, usable for bill calls (else nipcash/client.ErrHubUnusable).
func Connect(ctx context.Context, cashorder string, o Options) (*OrderClient, error) {
	conn, err := nipCO.DecodeOrderConnection(cashorder)
	if err != nil {
		return nil, err
	}
	nwc, err := relayclient.NewNWCClient(ctx, &nip47.PairingInfo{
		WalletPubkey: conn.Pubkey, RelayURLs: conn.Relays, Secret: conn.Secret,
	}, nip47.EncryptionNIP44V2)
	if err != nil {
		return nil, err
	}
	c := &OrderClient{conn: conn, verified: conn.Verify() == nil, nwc: nwc, accepted: map[string][]string{}}
	if _, err := c.Terms(ctx); err != nil {
		nwc.Close()
		return nil, err
	}
	s, err := cashclient.OpenBatchSession(ctx, conn.HubIdentity, conn.Relays, o.Session...)
	if err != nil {
		nwc.Close()
		return nil, err
	}
	if err := s.BillCallsUsable(); err != nil {
		nwc.Close()
		return nil, fmt.Errorf("%w: %v", cashclient.ErrHubUnusable, err)
	}
	c.session = s
	return c, nil
}

// Close releases the connection.
func (c *OrderClient) Close() { c.nwc.Close() }

// Verified reports whether the string's connection signature (TLV 5) verified at
// Connect. An unverified Hub is never shown as confirmed.
func (c *OrderClient) Verified() bool { return c.verified }

// Connection is the decoded Order connection.
func (c *OrderClient) Connection() nipCO.OrderConnection { return c.conn }

// Network is the network get_info last reported.
func (c *OrderClient) Network() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.network
}

// infoHead is what the online check reads from get_info.
type infoHead struct {
	Pubkey    string          `json:"pubkey"`
	Network   string          `json:"network"`
	Chain     string          `json:"chain"`
	CashOrder json.RawMessage `json:"cash_order"`
}

// Terms reads the selling terms with get_info on the connection, running the
// online check on every read. The terms are validated with Validate(0): a client
// cannot see the per-wallet ceiling. Terms that sell nothing are returned (see
// Terms.SellsNothing); Place refuses them.
func (c *OrderClient) Terms(ctx context.Context) (*nipCO.Terms, error) {
	resp, err := c.nwc.Call(ctx, nip47.MethodGetInfo, nil)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &relayclient.WalletError{Method: nip47.MethodGetInfo, Code: resp.Error.Code, Message: resp.Error.Message}
	}
	var head infoHead
	if err := json.Unmarshal(resp.Result, &head); err != nil {
		return nil, fmt.Errorf("nipCO/client: get_info: %w", err)
	}
	if err := (nipcash.OnlineCheck{HubIdentity: c.conn.HubIdentity, Chain: c.conn.Chain}).Check(head.Pubkey, head.Chain); err != nil {
		return nil, err
	}
	if len(head.CashOrder) == 0 {
		return nil, fmt.Errorf("%w: get_info carries no cash_order", nipCO.ErrOrderTerms)
	}
	terms, err := nipCO.ParseOrderInfo(head.CashOrder)
	if err != nil {
		return nil, err
	}
	if err := terms.Validate(0); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.network = head.Network
	c.mu.Unlock()
	return terms, nil
}

// bill is the Order connection as a batch item's target and bill-proof key.
func (c *OrderClient) bill() (cashclient.Bill, error) {
	return cashclient.BillFromParts(c.conn.Pubkey, c.conn.Secret)
}
