// Package client is the NIP-CASH network client: dial a Cash Hub or Cash
// Wallet connection and make its calls (as distinct from nipcash itself,
// which only builds/parses the protocol's types and makes no network
// calls). It mirrors nmilat's own relay/client split, the same one
// nipB7/nipB7/client already establishes: nipcash stays a
// dependency-light protocol library, while this package is the piece that
// actually dials out.
package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ohstr/nmilat/nip47"
	relayclient "github.com/ohstr/nmilat/relay/client"

	"github.com/ohstr/nmilat/nipcash"
)

// Client is a NIP-CASH client bound to one Cash Hub or Cash Wallet
// connection. Construct with Connect.
type Client struct {
	nwc          *relayclient.NWCClient
	walletPubkey string
}

// Connect dials tokenOrPairingURI, accepting either a cash-token-family
// bech32 string (lokicash1..., satscash1..., ...) or a raw
// nostr+walletconnect://... pairing URI — both decode to identical NIP-47
// pairing data, so either is a fully sufficient connection credential.
func Connect(ctx context.Context, tokenOrPairingURI string) (*Client, error) {
	pairing, err := nip47.ParsePairingURI(tokenOrPairingURI)
	if err != nil {
		token, decodeErr := nipcash.Decode(tokenOrPairingURI)
		if decodeErr != nil {
			return nil, fmt.Errorf("nipcash/client: %q is neither a valid pairing uri (%v) nor a valid cash token (%v)", tokenOrPairingURI, err, decodeErr)
		}
		pairing = &nip47.PairingInfo{
			WalletPubkey: token.WalletPubkey,
			RelayURLs:    token.RelayURLs,
			Secret:       token.Secret,
		}
	}
	nwc, err := relayclient.NewNWCClient(ctx, pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		return nil, err
	}
	return &Client{nwc: nwc, walletPubkey: pairing.WalletPubkey}, nil
}

// Close releases the underlying connection.
func (c *Client) Close() { c.nwc.Close() }

// WalletPubkey returns this connection's own wallet pubkey — the value
// nipcash's Request builders bind a proof to.
func (c *Client) WalletPubkey() string { return c.walletPubkey }

// call performs the subscribe -> send -> wait-for-one-response ->
// error-or-unmarshal round trip every method below shares, built on
// NWCClient's own exported Call (its generic nwcCall equivalent is
// unexported, so this package can't reuse it directly — Call is the
// documented escape hatch for exactly this: "wallet-specific/nonstandard
// methods not covered by the typed methods" nip47 itself defines).
func call[TResult any](ctx context.Context, c *Client, method string, params any) (*TResult, error) {
	resp, err := c.nwc.Call(ctx, method, params)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &relayclient.WalletError{Method: method, Code: resp.Error.Code, Message: resp.Error.Message}
	}
	var result TResult
	if len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			return nil, fmt.Errorf("nipcash/client: unmarshal %s result: %w", method, err)
		}
	}
	return &result, nil
}

// rawCall is like call, but returns the response's raw, still-JSON result
// bytes instead of unmarshaling them directly — for methods whose
// nipcash.XParams.ParseResult does its own unmarshaling (and, for
// cash_transfer/cash_consolidate, delivery decryption) rather than a plain
// json.Unmarshal into a wire struct.
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
