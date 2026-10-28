package client

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// wallet is a member's Circle Wallet connection served on one relay: it answers
// delete_circle_wallet with code, or {} when code is "".
func wallet(t *testing.T, code string) (nipcw.WalletConnection, *cashtest.Relay, *[]string) {
	t.Helper()
	r := cashtest.NewRelay(t)
	walletPriv, walletPub := keypair(t)
	secret, client := keypair(t)
	var got []string
	r.OnEvent(func(r *cashtest.Relay, ev *nip01.Event) {
		if ev.Kind != nip47.KindNWCRequest || ev.PubKey != client {
			return
		}
		req, err := nip47.ParseRequestEvent(ev, walletPriv)
		if err != nil {
			return
		}
		got = append(got, req.Method+string(req.Params))
		var resp *nip01.Event
		if code != "" {
			resp, err = nip47.NewErrorResponseEvent(walletPriv, ev.PubKey, req.Method, nip47.Error{Code: code, Message: code}, ev, nip47.EncryptionNIP44V2)
		} else {
			resp, err = nip47.NewResponseEvent(walletPriv, ev.PubKey, req.Method, struct{}{}, ev, nip47.EncryptionNIP44V2)
		}
		if err != nil {
			return
		}
		if resp.Sign(walletPriv) == nil {
			r.Publish(resp)
		}
	})
	return nipcw.WalletConnection{WalletPubkey: walletPub, Relays: []string{r.URL()}, Secret: secret}, r, &got
}

// T12-16 (S-CW-97, 101, 113): nothing is sent unless confirmDust says yes; then
// delete_circle_wallet {} over the wallet's own connection; FROZEN and RESTRICTED
// are surfaced.
func TestDeleteWallet(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	w, r, got := wallet(t, "")
	for _, confirm := range []func(context.Context) bool{nil, func(context.Context) bool { return false }} {
		if err := DeleteWallet(ctx, w, confirm); !errors.Is(err, ErrDustNotConfirmed) {
			t.Fatalf("unconfirmed: %v", err)
		}
	}
	if n := len(r.Accepted()); n != 0 {
		t.Fatalf("%d events sent without confirmation", n)
	}
	told := false
	if err := DeleteWallet(ctx, w, func(context.Context) bool { told = true; return true }); err != nil || !told {
		t.Fatalf("delete: %v (told %v)", err, told)
	}
	if len(*got) != 1 || (*got)[0] != nipcw.MethodDeleteCircleWallet+"{}" {
		t.Fatalf("requests %v", *got)
	}
	for _, code := range []string{nipcw.ErrFrozen, nipcw.ErrRestricted} {
		w, _, _ := wallet(t, code)
		err := DeleteWallet(ctx, w, func(context.Context) bool { return true })
		var we *relayclient.WalletError
		if !errors.As(err, &we) || we.Code != code {
			t.Errorf("%s: %v", code, err)
		}
	}
}
