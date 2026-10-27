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
// Every join gets an outcome, in the order requested. Each join's item is built
// once, from its single-use PreparedJoin, and only for the envelope that carries
// it: the fit is decided on a stand-in of the same size, so joins that spill
// into a later envelope are built and sent there. A join the batch stopped
// before (its envelope was not published) is OutcomeNotSent, returned with the
// error that stopped it; a retry needs a new Prepare. A join with no Hub, no
// prepared join or one bound to another Hub is refused before anything is
// built or sent, with no outcomes.
func (s *BatchSession) CreateCircleWalletMany(ctx context.Context, items []BatchCircleJoin) ([]CircleJoinOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	byID := make(map[string]BatchCircleJoin, len(items))
	// The stand-in's item proof is signed by a throwaway key: a signature and a
	// key are the same size whoever signs, so the stand-in is the join's size.
	standIn, err := transport.NewNonce()
	if err != nil {
		return nil, err
	}
	for i, it := range items {
		it := it
		id := itemID(it.ID, i)
		if err := checkCircleJoin(id, it, s.HubIdentity()); err != nil {
			return nil, err
		}
		byID[id] = it
		builders = append(builders, itemBuilder{
			ID: id,
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if err := checkCircleJoin(id, it, s.HubIdentity()); err != nil {
					return transport.Item{}, err
				}
				return it.Join.Item(id, it.Hub.connSecret, b)
			},
			Measure: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				return nipcash.BuildItem(id, it.Join.HubPubkey, it.Hub.connSecret, nipcw.MethodCreateCircleWallet,
					it.Join.Request, nipcash.BySigning(standIn), b)
			},
		})
	}

	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{})
	got := make(map[string]ItemOutcome, len(outcomes))
	for _, o := range outcomes {
		got[o.ID] = o
	}
	out := make([]CircleJoinOutcome, 0, len(builders))
	for _, b := range builders {
		o, ok := got[b.ID]
		if !ok {
			out = append(out, CircleJoinOutcome{ItemOutcome: ItemOutcome{ID: b.ID, State: OutcomeNotSent}})
			continue
		}
		jo := CircleJoinOutcome{ItemOutcome: o}
		if o.Succeeded() {
			// Decrypted from the Hub connection key, not the inbox that carried it.
			result, err := byID[o.ID].Join.ParseResult(o.Result)
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

// checkCircleJoin is what a join needs before anything is built: a Hub
// connection on this session's node, and a prepared join bound to that Hub.
func checkCircleJoin(id string, it BatchCircleJoin, sessionNode string) error {
	if err := it.Hub.check(id, sessionNode); err != nil {
		return err
	}
	if it.Join == nil {
		return errors.New("nipcash/client: a circle join needs its prepared join")
	}
	if it.Join.HubPubkey != it.Hub.target {
		return errors.New("nipcash/client: the prepared join is bound to another Hub")
	}
	return nil
}
