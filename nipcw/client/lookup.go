package client

import (
	"context"
	"fmt"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
)

// JoinActionKind is what LookupJoin tells the caller to do with a pending join.
type JoinActionKind int

const (
	// JoinClose: the wallet exists; Response holds its checked details.
	JoinClose JoinActionKind = iota
	// JoinWait: ask again at Until (0: on the caller's next refresh).
	JoinWait
	// JoinMayRejoin: the join was not made and never will be. The caller MAY
	// join again, with a new proof and a new connection key, never automatically
	// with this one.
	JoinMayRejoin
	// JoinShow: surface the join to the member; Reason says why. Never rejoin
	// with this connection key.
	JoinShow
)

// JoinAction is LookupJoin's answer.
type JoinAction struct {
	Kind     JoinActionKind
	Until    int64
	Reason   string
	Response *nipcw.CreateCircleWalletResponse
}

// LookupJoin looks a pending join up over the private transport (NIP-CW §Lost
// Join Reply): target the Hub connection, bill proof by its secret, item proof by
// cred, the join's key. pj.ConnectionPubkey may be the key a rotation moved the
// wallet to (§Recovering a Lost Connection).
//
// done → JoinClose with the details checked as a reply; pending → JoinWait until
// retry_after (a rotation's completes_at); unknown → JoinMayRejoin; expired →
// JoinShow "join_expired", never a rejoin with that key; an omitted or
// unanswered lookup (its bill proof did not verify) → JoinWait; UNAUTHORIZED (the
// bill proof verified, the item proof did not) → JoinShow "lookup_unauthorized",
// final for that item proof; another code → JoinShow "lookup_refused"; a done
// whose details fail their checks → JoinShow "lookup_undecodable"; an answer that
// does not parse → JoinShow "lookup_malformed". A lookup works whether or not the
// Hub is accepting joins.
func (c *Client) LookupJoin(ctx context.Context, pj PendingJoin, cred nipcw.Credential) (JoinAction, error) {
	if pj.HubPubkey != c.conn.Pubkey {
		return JoinAction{}, fmt.Errorf("nipcw/client: the pending join is for Hub %s, not this connection's %s", pj.HubPubkey, c.conn.Pubkey)
	}
	if _, err := c.info(ctx); err != nil {
		return JoinAction{}, err
	}
	s, err := c.batchSession(ctx)
	if err != nil {
		return JoinAction{}, err
	}
	hub, err := c.hubBill()
	if err != nil {
		return JoinAction{}, err
	}
	p := nipcw.JoinLookupParams{Credential: cred, ConnectionPubkey: pj.ConnectionPubkey, Deadline: pj.Deadline}
	lo, err := s.LookupCircleJoin(ctx, hub, p)
	if err != nil {
		return JoinAction{}, err
	}
	switch {
	case lo.NotServed:
		return JoinAction{Kind: JoinWait}, nil
	case lo.Malformed:
		return JoinAction{Kind: JoinShow, Reason: "lookup_malformed"}, nil
	case lo.Code == nipcw.ErrUnauthorized:
		return JoinAction{Kind: JoinShow, Reason: "lookup_unauthorized"}, nil
	case lo.Code != "":
		return JoinAction{Kind: JoinShow, Reason: "lookup_refused: " + lo.Code}, nil
	}
	switch lo.Status {
	case nipcash.LookupDone:
		r, err := p.ParseResult(c.conn.Pubkey, lo.Result)
		if err != nil {
			return JoinAction{Kind: JoinShow, Reason: "lookup_undecodable"}, nil
		}
		return JoinAction{Kind: JoinClose, Response: r}, nil
	case nipcash.LookupPending:
		return JoinAction{Kind: JoinWait, Until: lo.RetryAfter}, nil
	case nipcash.LookupUnknown:
		return JoinAction{Kind: JoinMayRejoin}, nil
	case nipcash.LookupExpired:
		return JoinAction{Kind: JoinShow, Reason: "join_expired"}, nil
	}
	return JoinAction{Kind: JoinShow, Reason: "lookup_malformed"}, nil
}
