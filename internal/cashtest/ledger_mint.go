package cashtest

import (
	"encoding/json"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// serveMintFaulted is mint_cash on the Cash Hub connection under the fault in
// force for it (ItemCtx.Kind 23194). reply false sends nothing.
func (h *FakeHub) serveMintFaulted(r *Relay, ev *nip01.Event, method string, params json.RawMessage) (res any, refusal *nip47.Error, reply bool) {
	exp, _ := expirationOf(ev)
	c := ItemCtx{Item: transport.Item{Target: h.walletXOnly, Method: method, Params: params},
		Envelope: &transport.Envelope{NotAfter: exp}, Now: h.Clock.Now(), Relay: r, Kind: kindNWCRequest}
	if h.Fault != nil {
		c.Fault = h.Fault(c)
	}
	switch c.Fault.kind {
	case faultDropBeforeCommit:
		return nil, nil, false
	case faultInternal, faultBreakSigner:
		// Nothing minted: the signer, or the Hub, failed before the commit.
		return nil, &nip47.Error{Code: nipcash.ErrCodeInternal, Message: "internal error"}, true
	case faultStallUntil, faultStallCommit:
		if !h.stall(c) {
			return nil, nil, false
		}
	}
	res, refusal = h.ledger.serveMint(ev, params)
	return res, refusal, c.Fault.kind != faultCommitThenDropReply
}

// mintLookupLocked is cash_lookup of a mint_cash: its item names the Cash Hub
// connection's TLV 0, and both proofs are signed by the connection's client key
// (NIP-CASH §Looking Up a Call). Any other method naming that target is
// omitted (I2), as is an item whose bill proof does not verify (I3).
func (l *WithdrawLedger) mintLookupLocked(c ItemCtx) *transport.Result {
	if c.Item.Method != nipcash.MethodCashLookup {
		return nil
	}
	clientKey, err := utils.GetPublicKey(l.h.connSecret)
	if err != nil {
		return nil
	}
	hash, err := transport.CanonicalParamsHash(c.Item.Params)
	if err != nil {
		return nil
	}
	binding := transport.ProofBinding{Target: l.h.walletXOnly, HubXOnly: l.h.nodeXOnly, Method: c.Item.Method,
		ParamsHash: hash, Nonce: c.Envelope.Nonce, NotAfter: c.Envelope.NotAfter}
	if signer, err := transport.VerifyBillProof(c.Item.BillProof, binding, c.Now); err != nil || signer != clientKey {
		return nil
	}
	var req nipcash.CashLookupRequest
	if json.Unmarshal(c.Item.Params, &req) != nil || req.Validate() != nil || req.ConnectionPubkey != "" {
		return errResult(nipcash.ErrCodeBadRequest, "lookup", "")
	}
	signer := ""
	if c.Item.HasProof() {
		if signer, err = transport.VerifyItemProof(c.Item.Proof, binding, c.Now); err != nil {
			return errResult(nipcash.ErrCodeUnauthorized, "item proof", "")
		}
	}
	if rec := l.calls[req.RequestID]; rec != nil {
		if rec.wallet != l.h.walletXOnly || signer == "" || signer != rec.authorizer {
			return errResult(nipcash.ErrCodeUnauthorized, "not the call's authorizer", "")
		}
		return okResult(map[string]any{"status": nipcash.LookupDone, "result": l.rebuiltMintLocked(rec)})
	}
	d := nipcash.DecideLookup(nipcash.LookupInput{Now: l.nowLocked(), Deadline: req.Deadline, Horizon: l.h.Limits.MaxRequestAgeSeconds})
	out := map[string]any{"status": d.Status}
	if d.Status == nipcash.LookupPending {
		out["retry_after"] = d.RetryAfter
	}
	return okResult(out)
}

// rebuiltMintLocked is a mint's original response, with the bill's tombstone in
// place of its token once the bill is destroyed: status and reason only past
// retained_until.
func (l *WithdrawLedger) rebuiltMintLocked(rec *callRecord) json.RawMessage {
	b := rec.minted
	if b == nil || !b.destroyed {
		return rec.result
	}
	var res map[string]json.RawMessage
	if json.Unmarshal(rec.result, &res) != nil {
		return rec.result
	}
	tomb := l.tombstoneLocked(b, "")
	if l.nowLocked() > b.retainedUntil {
		tomb.RetainedUntil = nil
	}
	raw, err := json.Marshal(tomb)
	if err != nil {
		return rec.result
	}
	res["cash_token"] = raw
	out, err := json.Marshal(res)
	if err != nil {
		return rec.result
	}
	return out
}
