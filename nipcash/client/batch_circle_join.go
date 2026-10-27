package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
)

// BatchCircleJoin asks one Circle Wallet Hub for a wallet (NIP-CW §Private Join).
type BatchCircleJoin struct {
	ID string
	// Hub is the Hub connection: BillFromParts(hubPubkey, hubSecret). A join has
	// no bill, so its bill proof is signed with the Hub connection's secret.
	Hub Bill
	// Params is the standard request. Params.Connection MUST be set: its secret
	// is what the returned PairingURI carries.
	Params nipcw.CreateCircleWalletParams
}

// CircleJoinOutcome is one join's answer.
type CircleJoinOutcome struct {
	ItemOutcome
	Result *nipcw.CreateCircleWalletResponse
}

// CreateCircleWalletMany sends one or more circle joins in one request. Every Hub
// must run on this session's node; the Hub evaluates each join on its own.
//
// A refused join is OutcomeError with the standard join's codes (nipcw.ErrNotReady,
// ErrRestricted, ErrWalletExists, ErrRateLimited). An omission is NOT a refusal:
// the join may have run and its reply been lost.
func (s *BatchSession) CreateCircleWalletMany(ctx context.Context, items []BatchCircleJoin) ([]CircleJoinOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	byID := make(map[string]BatchCircleJoin, len(items))
	for i, it := range items {
		it := it
		byID[itemID(it.ID, i)] = it
		builders = append(builders, itemBuilder{
			ID: itemID(it.ID, i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if err := it.Hub.check(id, s.HubIdentity()); err != nil {
					return transport.Item{}, err
				}
				return it.Params.Item(id, it.Hub.target, it.Hub.connSecret, b)
			},
		})
	}

	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]CircleJoinOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		jo := CircleJoinOutcome{ItemOutcome: o}
		if o.Succeeded() {
			// Decrypted from the Hub connection key, not the inbox that carried it.
			it := byID[o.ID]
			result, err := it.Params.ParseResult(it.Hub.target, o.Result)
			if err != nil {
				jo.State = OutcomeError
				jo.Error = decodeError(o.ID, err)
				jo.Undecodable = true
			} else {
				jo.Result = result
			}
		}
		out = append(out, jo)
	}
	return out, sendErr
}
