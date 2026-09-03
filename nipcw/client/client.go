// Package client is the NIP-CW network client: dial a Circle Wallet Hub
// connection and make its calls (as distinct from nipcw itself, which only
// builds/parses the protocol's types and makes no network calls). It
// mirrors nmilat's own relay/client split, the same one nipB7/nipB7/client
// and nipcash/nipcash/client already establish.
package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ohstr/nmilat/nip47"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// Client is a NIP-CW client bound to one Circle Wallet Hub connection.
// Construct with Connect.
type Client struct {
	nwc       *relayclient.NWCClient
	hubPubkey string
}

// Connect dials pairingURI (a raw nostr+walletconnect://... connection
// string — a Circle Wallet Hub connection is always shared/public, handed
// out directly, never wrapped in a bech32 token the way a cash token is).
func Connect(ctx context.Context, pairingURI string) (*Client, error) {
	pairing, err := nip47.ParsePairingURI(pairingURI)
	if err != nil {
		return nil, fmt.Errorf("nipcw/client: %w", err)
	}
	nwc, err := relayclient.NewNWCClient(ctx, pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		return nil, err
	}
	return &Client{nwc: nwc, hubPubkey: pairing.WalletPubkey}, nil
}

// Close releases the underlying connection.
func (c *Client) Close() { c.nwc.Close() }

// HubPubkey returns this Circle Wallet Hub connection's own pubkey — the
// value nipcw's Request builders bind a proof to.
func (c *Client) HubPubkey() string { return c.hubPubkey }

// rawCall performs the subscribe -> send -> wait-for-one-response ->
// error-or-raw-result round trip, built on NWCClient's own exported Call
// (its generic nwcCall equivalent is unexported — see nipcash/client's own
// identical helper for the full reasoning).
func rawCall(ctx context.Context, c *Client, method string, params any) (json.RawMessage, error) {
	resp, err := c.nwc.Call(ctx, method, params)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &relayclient.WalletError{Method: method, Code: resp.Error.Code, Message: resp.Error.Message}
	}
	return resp.Result, nil
}
