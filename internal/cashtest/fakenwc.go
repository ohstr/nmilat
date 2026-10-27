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

// FakeNetwork is the network every get_info of the fake reports.
const FakeNetwork = "regtest"

// serveNWC is the fake's kind-23194 side: the Cash Hub connection.
//
// get_info answers with the node identity as pubkey, so a client can find the
// announcement from the connection alone. Every other method is NOT_IMPLEMENTED:
// the bill methods and cash_lookup because they are private-transport only, and
// mint_cash because the fake has no ledger yet (it is not listed in methods).
func (h *FakeHub) serveNWC(r *Relay, ev *nip01.Event) {
	if !taggedP(ev, h.walletXOnly) {
		return
	}
	appXOnly, err := utils.GetPublicKey(h.connSecret)
	if err != nil || ev.PubKey != appXOnly {
		return // not this connection's client key
	}
	req, err := nip47.ParseRequestEvent(ev, h.walletPriv)
	if err != nil {
		return
	}
	encryption := nip47.EncryptionNIP04
	if enc, err := utils.FindUniqueEventTagValue(ev.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}
	var resp *nip01.Event
	switch req.Method {
	case "get_info":
		resp, err = nip47.NewResponseEvent(h.walletPriv, ev.PubKey, req.Method, nip47.GetInfoResult{
			Pubkey:         h.nodeXOnly,
			Network:        FakeNetwork,
			Chain:          FakeChain,
			Methods:        []string{"get_info"},
			PrivateMethods: PrivateMethods,
		}, ev, encryption)
	default:
		resp, err = nip47.NewErrorResponseEvent(h.walletPriv, ev.PubKey, req.Method, nip47.Error{
			Code: "NOT_IMPLEMENTED", Message: req.Method + " is not served on this connection",
		}, ev, encryption)
	}
	if err != nil {
		h.t.Errorf("cashtest: nwc response: %v", err)
		return
	}
	if err := resp.Sign(h.walletPriv); err != nil {
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
