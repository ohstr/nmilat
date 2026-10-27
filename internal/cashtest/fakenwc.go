package cashtest

import (
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/utils"
)

const kindNWCRequest = nip47.KindNWCRequest

// PrivateMethods are the methods the fake lists in its Cash Hub connection's
// get_info private_methods: the bill methods and cash_lookup, served over the
// private transport only (NIP-CASH §Which Methods a Hub Serves).
var PrivateMethods = []string{"cash_status", "cash_redeem", "cash_transfer", "cash_consolidate", "cash_lookup"}

// WithdrawMethods are the methods a Hub offering on-chain withdrawals adds to
// its private_methods.
var WithdrawMethods = []string{"cash_withdraw_quote", "cash_withdraw"}

// privateMethods is PrivateMethods, with WithdrawMethods when the fake offers
// withdrawals.
func (h *FakeHub) privateMethods() []string {
	h.mu.Lock()
	on := h.Withdrawals
	h.mu.Unlock()
	if !on {
		return PrivateMethods
	}
	return append(append([]string(nil), PrivateMethods...), WithdrawMethods...)
}

// FakeNetwork is the network every get_info of the fake reports.
const FakeNetwork = "regtest"

// serveNWC is the fake's kind-23194 side: the Cash Hub connection.
//
// get_info answers with the node identity as pubkey, so a client can find the
// announcement from the connection alone. Every other method is NOT_IMPLEMENTED:
// the bill methods and cash_lookup because they are private-transport only, and
// mint_cash unless the fake has a bill ledger (ServeWithdrawals), which serves
// it and lists it in methods.
func (h *FakeHub) serveNWC(r *Relay, ev *nip01.Event) {
	walletPriv, connSecret, circle := h.walletPriv, h.connSecret, false
	switch {
	case taggedP(ev, h.walletXOnly):
	case h.circle != nil && taggedP(ev, h.circle.xonly):
		walletPriv, connSecret, circle = h.circle.priv, h.circle.secret, true
	default:
		return
	}
	appXOnly, err := utils.GetPublicKey(connSecret)
	if err != nil || ev.PubKey != appXOnly {
		return // not this connection's client key
	}
	req, err := nip47.ParseRequestEvent(ev, walletPriv)
	if err != nil {
		return
	}
	encryption := nip47.EncryptionNIP04
	if enc, err := utils.FindUniqueEventTagValue(ev.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}
	var resp *nip01.Event
	switch {
	case circle && req.Method == "get_info":
		resp, err = nip47.NewResponseEvent(walletPriv, ev.PubKey, req.Method, h.circleInfo(), ev, encryption)
	case circle:
		// A join on the standard transport is NOT_IMPLEMENTED (NIP-CW §Private Join).
		resp, err = nip47.NewErrorResponseEvent(walletPriv, ev.PubKey, req.Method, nip47.Error{
			Code: "NOT_IMPLEMENTED", Message: req.Method + " is served on the private transport only",
		}, ev, encryption)
	case req.Method == "get_info":
		methods := []string{"get_info"}
		if h.ledger != nil {
			methods = append(methods, "mint_cash")
		}
		resp, err = nip47.NewResponseEvent(h.walletPriv, ev.PubKey, req.Method, nip47.GetInfoResult{
			Pubkey:         h.nodeXOnly,
			Network:        FakeNetwork,
			Chain:          FakeChain,
			Methods:        methods,
			PrivateMethods: h.privateMethods(),
		}, ev, encryption)
	case req.Method == "mint_cash" && h.ledger != nil:
		res, refusal := h.ledger.serveMint(ev, req.Params)
		if refusal != nil {
			resp, err = nip47.NewErrorResponseEvent(h.walletPriv, ev.PubKey, req.Method, *refusal, ev, encryption)
		} else {
			resp, err = nip47.NewResponseEvent(h.walletPriv, ev.PubKey, req.Method, res, ev, encryption)
		}
	default:
		resp, err = nip47.NewErrorResponseEvent(h.walletPriv, ev.PubKey, req.Method, nip47.Error{
			Code: "NOT_IMPLEMENTED", Message: req.Method + " is not served on this connection",
		}, ev, encryption)
	}
	if err != nil {
		h.t.Errorf("cashtest: nwc response: %v", err)
		return
	}
	if err := resp.Sign(walletPriv); err != nil {
		h.t.Errorf("cashtest: sign nwc response: %v", err)
		return
	}
	r.Publish(resp)
}

func taggedP(ev *nip01.Event, pubkey string) bool {
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "p" && tag[1] == pubkey {
			return true
		}
	}
	return false
}
