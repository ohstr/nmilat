package client

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// HubClient mints over a Cash Hub connection (a cashhub1 string).
type HubClient struct {
	conn     nipcash.CashHubConnection
	verified bool
	nwc      *relayclient.NWCClient
	opts     []SessionOption

	mu      sync.Mutex
	session *BatchSession
}

// HubInfo is what Info learned about the Hub. IdentityXOnly is the string's
// TLV 4; Chain and Network come from get_info. Verified is false for a string
// whose connection signature did not verify: report it, never show it as
// confirmed; the caller decides.
type HubInfo struct {
	IdentityXOnly, Chain, Network string
	Verified                      bool
	MaxRequestAge                 int64
	LookupOffered                 bool
	Relays                        []string
}

// TestNetwork reports a network that is not mainnet, missing or unknown
// included. The SDK only reports it.
func (i HubInfo) TestNetwork() bool { return i.Network != "mainnet" }

// ConnectCashHub dials a cashhub1 string. It is decoded and its connection
// signature checked; a string that does not verify still connects, with
// HubInfo.Verified false.
func ConnectCashHub(ctx context.Context, cashhub string, opts ...SessionOption) (*HubClient, error) {
	conn, err := nipcash.DecodeCashHubConnection(cashhub)
	if err != nil {
		return nil, err
	}
	nwc, err := relayclient.NewNWCClient(ctx, &nip47.PairingInfo{
		WalletPubkey: conn.Pubkey, RelayURLs: conn.Relays, Secret: conn.Secret,
	}, nip47.EncryptionNIP44V2)
	if err != nil {
		return nil, err
	}
	return &HubClient{conn: conn, verified: conn.Verify() == nil, nwc: nwc, opts: opts}, nil
}

// Close releases the connection.
func (h *HubClient) Close() { h.nwc.Close() }

// Info runs the online check — get_info's identity must be TLV 4 and its chain
// TLV 6, else ErrHubIdentityMismatch or ErrChainMismatch — on every call, and
// reads the Hub's announcement (verified against TLV 4) from the connection's
// relays once.
func (h *HubClient) Info(ctx context.Context) (*HubInfo, error) {
	gi, err := h.nwc.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	if err := (nipcash.OnlineCheck{HubIdentity: h.conn.HubIdentity, Chain: h.conn.Chain}).Check(gi.Pubkey, gi.Chain); err != nil {
		return nil, err
	}
	s, err := h.batchSession(ctx)
	if err != nil {
		return nil, err
	}
	return &HubInfo{
		IdentityXOnly: h.conn.HubIdentity, Chain: gi.Chain, Network: gi.Network, Verified: h.verified,
		MaxRequestAge: s.MaxRequestAge(), LookupOffered: slices.Contains(gi.PrivateMethods, nipcash.MethodCashLookup),
		Relays: s.Relays(),
	}, nil
}

func (h *HubClient) batchSession(ctx context.Context) (*BatchSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.session != nil {
		return h.session, nil
	}
	s, err := OpenBatchSession(ctx, h.conn.HubIdentity, h.conn.Relays, h.opts...)
	if err != nil {
		return nil, err
	}
	h.session = s
	return s, nil
}

// MintCash mints over the connection. WithPublishFilter and WithAfterPublish
// on ctx apply to the mint request (not to the get_info read before it).
// Before anything is written: the online
// check, cash_lookup among private_methods, and a usable max_request_age (else
// ErrHubUnusable). Then the call is written ahead to j, as device's, with its
// exact deadline, and sent with that deadline as its NIP-47 expiration.
//
// BAD_REQUEST is a *FinalError; any other answer short of a result an
// *IndeterminateError (look it up with LookupMint); ErrNotSent nothing sent. A
// result that does not parse is returned with an *IndeterminateError: funds
// may be committed.
func (h *HubClient) MintCash(ctx context.Context, p nipcash.MintCashParams, j Journal, device string) (*nipcash.MintCashResult, error) {
	if j == nil {
		return nil, ErrNoJournal
	}
	// The publish hooks are for the mint request alone, not the get_info read.
	info, err := h.Info(withoutPublishHooks(ctx))
	if err != nil {
		return nil, err
	}
	if !info.LookupOffered {
		return nil, fmt.Errorf("%w: get_info private_methods lacks cash_lookup", ErrHubUnusable)
	}
	s, err := h.batchSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.checkBillCalls([]itemBuilder{{RequestID: "x"}}, sendOptions{journal: j}); err != nil {
		return nil, err
	}
	if p.RequestID == "" {
		if p.RequestID, err = nipcash.NewRequestID(); err != nil {
			return nil, err
		}
	}
	req, err := p.Request()
	if err != nil {
		return nil, err
	}
	pc, err := p.Pending(h.conn.Pubkey)
	if err != nil {
		return nil, err
	}
	pc.Deadline = time.Now().Add(s.deadlineWindow()).Unix()
	pc.HubIdentity, pc.MaxRequestAge, pc.Device, pc.Chain = h.conn.HubIdentity, s.MaxRequestAge(), device, h.conn.Chain
	pc = asReplacement(ctx, pc)
	if err := j.WriteAhead(ctx, []nipcash.PendingCall{pc}); err != nil {
		return nil, fmt.Errorf("%w: write ahead: %v", ErrNotSent, err)
	}
	if time.Until(time.Unix(pc.Deadline, 0)) < nipcash.MinPublishMargin*time.Second {
		return nil, fmt.Errorf("%w: %w", ErrNotSent, ErrDeadlineTooClose)
	}
	resp, err := h.nwc.CallWithOptions(ctx, nipcash.MethodMintCash, req, nip47.WithExpiration(pc.Deadline))
	if err != nil {
		return nil, &IndeterminateError{Call: pc, Cause: err}
	}
	if resp.Error != nil {
		code := resp.Error.Code
		if nipcash.FinalCode(code) {
			return nil, &FinalError{Method: nipcash.MethodMintCash, Code: code, Message: resp.Error.Message}
		}
		if code == nipcash.ErrCodeRequestReused {
			pc.SawReused = true
		} else {
			pc.LastCode = code
		}
		return nil, &IndeterminateError{Call: pc, Code: code, Message: resp.Error.Message}
	}
	res, err := p.ParseResult(resp.Result)
	if err != nil {
		return res, &IndeterminateError{Call: pc, Cause: err}
	}
	return res, nil
}

// LookupMint looks a mint up over the private transport: target TLV 0, item
// and bill proofs signed with the connection key.
func (h *HubClient) LookupMint(ctx context.Context, pc nipcash.PendingCall) (LookupOutcome, error) {
	s, err := h.batchSession(ctx)
	if err != nil {
		return LookupOutcome{}, err
	}
	bill, err := BillFromParts(h.conn.Pubkey, h.conn.Secret)
	if err != nil {
		return LookupOutcome{}, err
	}
	return s.lookup(ctx, bill, nipcash.BySigning(h.conn.Secret), pc, "")
}

var errLookupNoOutcome = errors.New("nipcash/client: the lookup got no outcome")
