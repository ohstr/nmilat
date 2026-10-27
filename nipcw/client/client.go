// Package client is the NIP-CW network client: dial a Circle Wallet Hub
// connection (a circlehub1 string), join over NIP-CASH's private transport,
// look a lost join up, and delete a member's own wallet. nipcw itself builds and
// parses the protocol's types and makes no network calls.
package client

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// ErrHubNonConforming is a get_info that does not describe a Circle Wallet Hub
// as NIP-CW requires: no circle_wallet block, an "always" key missing (fees_ppm
// 0 must be present), or a negative available_millis. Nothing is sent to it.
var ErrHubNonConforming = errors.New("nipcw/client: the connection's get_info is not a conforming Circle Wallet Hub's")

// Options tunes a Client. Session is passed to the private-transport session
// (proof-of-work budget and the like).
type Options struct {
	Session []cashclient.SessionOption
}

// Client is bound to one Circle Wallet Hub connection. Construct with Connect.
type Client struct {
	conn     nipcw.CircleHubConnection
	verified bool
	nwc      *relayclient.NWCClient
	opts     Options

	mu      sync.Mutex
	session *cashclient.BatchSession
}

// Connect dials a circlehub1 string (all lowercase or all uppercase). The string
// is decoded and its connection signature checked, then get_info must pass the
// online check: circle_wallet.identity, compared in x-only form, equals TLV 4 and
// chain equals TLV 6 (else nipcash.ErrHubIdentityMismatch or
// nipcash.ErrChainMismatch, and the connection is closed). A string whose
// signature does not verify still connects, with Verified false: report it and
// never show the Hub as confirmed.
func Connect(ctx context.Context, circlehub string, o Options) (*Client, error) {
	conn, err := nipcw.DecodeCircleHubConnection(circlehub)
	if err != nil {
		return nil, err
	}
	nwc, err := relayclient.NewNWCClient(ctx, &nip47.PairingInfo{
		WalletPubkey: conn.Pubkey, RelayURLs: conn.Relays, Secret: conn.Secret,
	}, nip47.EncryptionNIP44V2)
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, verified: conn.Verify() == nil, nwc: nwc, opts: o}
	if _, err := c.info(ctx); err != nil {
		nwc.Close()
		return nil, err
	}
	return c, nil
}

// Close releases the connection.
func (c *Client) Close() { c.nwc.Close() }

// HubPubkey is the connection's TLV 0, the key a join proof's d tag binds.
func (c *Client) HubPubkey() string { return c.conn.Pubkey }

// Verified reports whether the string's connection signature (TLV 5) verified.
func (c *Client) Verified() bool { return c.verified }

// Connection is the decoded circlehub1 string.
func (c *Client) Connection() nipcw.CircleHubConnection { return c.conn }

// info reads get_info and runs the online check on every read.
func (c *Client) info(ctx context.Context) (*nip47.GetInfoResult, error) {
	gi, err := c.nwc.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	if gi.CircleWallet == nil {
		return nil, fmt.Errorf("%w: no circle_wallet block", ErrHubNonConforming)
	}
	if err := (nipcash.OnlineCheck{HubIdentity: c.conn.HubIdentity, Chain: c.conn.Chain}).Check(gi.CircleWallet.Identity, gi.Chain); err != nil {
		return nil, err
	}
	return gi, nil
}

// batchSession opens the private transport once: the kind-11190 announcement,
// fetched from TLV 1 and the announcement's relays and verified against TLV 4,
// the identity the online check confirmed.
func (c *Client) batchSession(ctx context.Context) (*cashclient.BatchSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return c.session, nil
	}
	s, err := cashclient.OpenBatchSession(ctx, c.conn.HubIdentity, c.conn.Relays, c.opts.Session...)
	if err != nil {
		return nil, err
	}
	c.session = s
	return s, nil
}

func (c *Client) hubBill() (cashclient.Bill, error) {
	return cashclient.BillFromParts(c.conn.Pubkey, c.conn.Secret)
}
