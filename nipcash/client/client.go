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

	// connSecret is the bill's connection secret, kept from the pairing data this
	// client was dialled with. It signs every item's kind-23193 bill proof, which is
	// how a hub learns the sender genuinely holds this bill rather than having
	// guessed its wallet pubkey.
	//
	// Taken from the pairing rather than from token, so it is present whether the
	// caller supplied a lokicash token or the bill's raw pairing URI — the same
	// secret either way.
	connSecret string

	// session is opened lazily and reused. Lazily because a Client dialled purely to
	// mint never needs one, and opening it costs a relay round trip; reused because
	// every bill method on this connection addresses the same hub.
	sessionMu sync.Mutex
	session   *BatchSession
}

// bill returns this connection's own Bill — the bill every single-item method acts
// on, paired with the secret that proves possession.
//
// An error rather than an empty string: an item built without it is refused by the
// codec, and a hub that somehow received one would omit it — information-free, so
// the caller would never learn why. Failing here, by name, is the only place this
// can be diagnosed.
func (c *Client) bill() (Bill, error) {
	if c.connSecret == "" {
		return Bill{}, fmt.Errorf("nipcash/client: this connection carries no bill secret, so no bill proof can be signed; dial the bill's own token or pairing uri")
	}
	return BillFromParts(c.walletPubkey, c.connSecret)
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
// NotServedError is an OMISSION: the hub gave this item no answer at all.
//
// A distinct type rather than a formatted string because the two things a caller
// must do with it cannot be derived from text. It is deliberately
// information-free — the same answer for a bill the hub does not hold, a proof
// that did not verify, and a method it will not serve, since telling those apart
// would make the transport an oracle for which bills a hub holds — so a caller
// can neither report a cause nor rule one out.
//
// Whether resending is safe depends on the METHOD, which is why this type
// reports the method and not a retryable flag. An omission is indistinguishable
// from a request that WAS applied and whose reply was lost: harmless for a read
// like cash_status, a possible double-spend for cash_redeem or cash_transfer.
// Callers that classified this by falling through to a generic transport error
// got "retryable" for every method, including the ones where resending pays
// twice.
type NotServedError struct {
	// Method is the item's method, for the message only.
	Method string
}

func (e *NotServedError) Error() string {
	return fmt.Sprintf("nipcash/client: the hub returned no answer for this %s; it may or may not have been applied, so ask before retrying", e.Method)
}

func oneItemOutcome(state OutcomeState, resultErr *transport.ResultError, sendErr error, method string) error {
	// A DECIDED outcome beats sendErr, which is the ordering the *Many wrappers
	// already use. Checking sendErr first threw away answers the hub had actually
	// given.
	//
	// sendErr and a decided outcome co-occur by design: sendBatch returns outcomes AND
	// an error together when a reply was incomplete, precisely so a caller can keep
	// what did arrive. A hub controls `total`, and nothing bounds it from above, so it
	// can declare total=2, send the complete genuine result in chunk 1, and never send
	// chunk 2. collectReply then takes its partial branch and returns the correct
	// outcome alongside ErrIncompleteReply — and this switch discarded the outcome.
	//
	// What was discarded is the unrecoverable part. After a carve the source bill is
	// drained and deleted and the funds live in a new wallet whose token existed ONLY
	// in that reply, so losing it strands them; and cash_status is the very call a
	// client is told to make after an ambiguous spend, so erasing its answer — tombstone
	// included — pins the caller in the one state they must never retry from.
	//
	// Round 1 filed this as latent-but-unreachable, reasoning that a 1-item reply
	// returns via len(seen)==total first. That holds only for an HONEST total.
	switch {
	case state == OutcomeResult:
		return nil
	case sendErr != nil:
		return sendErr
	case state == OutcomeError && resultErr != nil:
		return &relayclient.WalletError{Method: method, Code: resultErr.Code, Message: resultErr.Message}
	case state != OutcomeResult:
		return &NotServedError{Method: method}
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
	c := &Client{nwc: nwc, walletPubkey: pairing.WalletPubkey, connSecret: pairing.Secret}
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
