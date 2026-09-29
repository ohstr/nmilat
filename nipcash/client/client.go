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
	"sync"

	"github.com/ohstr/nmilat/nip47"
	relayclient "github.com/ohstr/nmilat/relay/client"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// Client is a NIP-CASH client bound to one Cash Hub or Cash Wallet
// connection. Construct with Connect.
//
// It hides which transport a call takes. Bill methods — cash_status, cash_redeem,
// cash_transfer, cash_consolidate — travel over the PRIVATE transport, which is the
// only transport that serves them (NIP-CASH §The Private Transport); hub methods such
// as mint_cash keep the standard kind-23194 connection. A caller does neither piece of
// bookkeeping: it dials and calls.
type Client struct {
	nwc          *relayclient.NWCClient
	walletPubkey string

	// token is the bill this client was dialled with, when it was dialled with one
	// rather than with a bare pairing URI. Bill methods need it: a bill's mint
	// signature is the only thing that identifies its minting Hub, and that identity
	// is what the transport announcement is verified against.
	token *nipcash.Token

	// session is opened lazily and reused. Lazily because a Client dialled purely to
	// mint never needs one, and opening it costs a relay round trip; reused because
	// every bill method on this connection addresses the same hub.
	sessionMu sync.Mutex
	session   *BatchSession
}

// billSession returns the private-transport session this client's bill methods run
// over, opening it on first use.
//
// The hub identity comes from the bill's own mint signature, which is mandatory
// (§Mint Provenance) precisely so this always works. A Client dialled with a bare
// pairing URI has no token and therefore no hub identity, so it can mint but cannot
// act on a bill — that is a real limit of a pairing URI, not of this client.
func (c *Client) billSession(ctx context.Context) (*BatchSession, error) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.session != nil {
		return c.session, nil
	}
	if c.token == nil {
		return nil, fmt.Errorf("nipcash/client: bill methods need a cash token — a pairing URI carries no mint signature, so there is no hub identity to verify a transport announcement against")
	}
	minter, ok := nipcash.VerifyProvenance(*c.token)
	if !ok {
		return nil, fmt.Errorf("nipcash/client: this bill carries no verifiable mint signature, so its hub cannot be identified and its methods cannot be reached")
	}
	session, err := c.NewBatchSession(ctx, minter, c.token.RelayURLs)
	if err != nil {
		return nil, err
	}
	c.session = session
	return session, nil
}

// oneItemOutcome unwraps a single-item batch back into the shape a single-bill caller
// expects: a result, or an error that says what happened.
//
// An OMISSION becomes an error here rather than a nil result, and deliberately so: it
// is information-free by design, so the honest translation is "no answer", never
// "nothing was there". For a spend that distinction is the difference between
// retrying safely and double-paying.
func oneItemOutcome(state OutcomeState, resultErr *transport.ResultError, sendErr error, method string) error {
	switch {
	case sendErr != nil:
		return sendErr
	case state == OutcomeError && resultErr != nil:
		return &relayclient.WalletError{Method: method, Code: resultErr.Code, Message: resultErr.Message}
	case state != OutcomeResult:
		return fmt.Errorf("nipcash/client: the hub returned no answer for this %s; it may or may not have been applied, so ask before retrying", method)
	}
	return nil
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
	c := &Client{nwc: nwc, walletPubkey: pairing.WalletPubkey}
	if tok, err := nipcash.Decode(tokenOrPairingURI); err == nil {
		c.token = &tok
	}
	return c, nil
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
