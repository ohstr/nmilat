package client

import (
	"context"
	"errors"

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
	// Join is the signed join (nipcw.CreateCircleWalletParams.Prepare, bound to
	// Hub's pubkey). It is single use: a join that cannot be built is refused.
	Join *nipcw.PreparedJoin
}

// CircleJoinOutcome is one join's answer.
type CircleJoinOutcome struct {
	ItemOutcome
	Result *nipcw.CreateCircleWalletResponse
}

// CreateCircleWalletMany sends one or more circle joins in one request. Every Hub
// must run on this session's node; the Hub evaluates each join on its own.
//
// A refused join is OutcomeError with NIP-CW's join codes. An omission is NOT a
// refusal: the join may have run and its reply been lost, so it is looked up
// with LookupCircleJoin. A reply that fails nipcw's checks (another
// connection_pubkey, another sender) is OutcomeError with Undecodable set.
//
// Each join's item is built once, from its single-use PreparedJoin. A join that
// would have to move to a later envelope cannot be rebuilt, so the batch stops
// there and the joins not yet sent get no outcome: nothing of them was sent.
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
				if it.Join == nil {
					return transport.Item{}, errors.New("nipcash/client: a circle join needs its prepared join")
				}
				if it.Join.HubPubkey != it.Hub.target {
					return transport.Item{}, errors.New("nipcash/client: the prepared join is bound to another Hub")
				}
				return it.Join.Item(id, it.Hub.connSecret, b)
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
			result, err := it.Join.ParseResult(o.Result)
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
