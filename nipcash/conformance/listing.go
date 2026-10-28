package conformance

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash/listing"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// listCases are the offer-listing cases a Hub implementing Lister runs.
// CT-LIST-05 and CT-LIST-06 retire what they list, so they run last.
var listCases = []ctCase{
	{id: "CT-LIST-01", needs: []need{needLister}, run: ctList01},
	{id: "CT-LIST-02", needs: []need{needLister}, run: ctList02},
	{id: "CT-LIST-03", needs: []need{needLister}, run: ctList03},
	{id: "CT-LIST-04", needs: []need{needLister}, run: ctList04},
	{id: "CT-LIST-05", needs: []need{needLister}, run: ctList05},
	{id: "CT-LIST-06", needs: []need{needLister}, run: ctList06},
}

// listOptions checks listings against the Hub's own chain, test networks
// allowed (a Hub under test runs on one).
func (s *suite) listOptions() listing.CheckOptions {
	return listing.CheckOptions{Chains: []string{s.conn.Chain}, TestNetworks: true}
}

// listed parses the Hub's newest version of every listed address.
func listed(t *testing.T, s *suite) []*listing.Listing {
	t.Helper()
	newest := map[string]*listing.Listing{}
	var order []string
	for _, ev := range s.h.(Lister).Listings(t) {
		if ev.Kind != listing.KindListing {
			continue
		}
		l, err := listing.ParseListing(ev, s.listOptions())
		if err != nil {
			t.Fatalf("listing %s: %v", ev.ID, err)
		}
		cur, ok := newest[l.Address()]
		if !ok {
			order = append(order, l.Address())
		}
		if !ok || nip01.Supersedes(ev, cur.Event) {
			newest[l.Address()] = l
		}
	}
	if len(order) == 0 {
		t.Skip("the Hub lists nothing")
	}
	out := make([]*listing.Listing, 0, len(order))
	for _, a := range order {
		out = append(out, newest[a])
	}
	return out
}

// tapInfo calls get_info on the listed connection, as a wallet does at tap.
func tapInfo(t *testing.T, l *listing.Listing) (*nip47.GetInfoResult, json.RawMessage, error) {
	t.Helper()
	pi := &nip47.PairingInfo{}
	switch {
	case l.Order != nil:
		pi.WalletPubkey, pi.RelayURLs, pi.Secret = l.Order.Pubkey, l.Order.Relays, l.Order.Secret
	case l.Circle != nil:
		pi.WalletPubkey, pi.RelayURLs, pi.Secret = l.Circle.Pubkey, l.Circle.Relays, l.Circle.Secret
	}
	nwc, err := relayclient.NewNWCClient(context.Background(), pi, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("open the listed connection: %v", err)
	}
	defer nwc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := nwc.Call(ctx, nip47.MethodGetInfo, nil)
	if err != nil {
		return nil, nil, err
	}
	if resp.Error != nil {
		return nil, nil, &nwcErr{resp.Error.Code}
	}
	var gi nip47.GetInfoResult
	if err := json.Unmarshal(resp.Result, &gi); err != nil {
		return nil, nil, err
	}
	return &gi, resp.Result, nil
}

type nwcErr struct{ code string }

func (e *nwcErr) Error() string { return "get_info: " + e.code }

// CT-LIST-01 (CASH-LIST-01/05): every published listing passes the wallet's
// checks with the Hub's chain held.
func ctList01(t *testing.T, s *suite) {
	n := 0
	for _, ev := range s.h.(Lister).Listings(t) {
		if ev.Kind != listing.KindListing {
			continue
		}
		n++
		if _, err := listing.ParseListing(ev, s.listOptions()); err != nil {
			t.Errorf("listing %s: %v", ev.ID, err)
		}
	}
	if n == 0 {
		t.Skip("the Hub lists nothing")
	}
}

// CT-LIST-02 (CASH-LIST-02): only signed cashorder1/circlehub1 strings, signed
// with TLV 4, which is the Hub's identity; d = TLV 0, n = TLV 6; network as
// get_info reports it.
func ctList02(t *testing.T, s *suite) {
	for _, l := range listed(t, s) {
		if l.NodeIdentity != s.nodeXOnly {
			t.Errorf("%s signed by %s, not the Hub identity %s", l.Address(), l.NodeIdentity, s.nodeXOnly)
		}
		if l.Status == listing.StatusClosed {
			continue
		}
		gi, _, err := tapInfo(t, l)
		if err != nil {
			t.Errorf("%s: get_info: %v", l.Address(), err)
			continue
		}
		if gi.Network != l.Network {
			t.Errorf("%s: network %q, get_info says %q", l.Address(), l.Network, gi.Network)
		}
	}
}

// CT-LIST-03 (CASH-LIST-02, CASH-S-30): never post-dated; expiration at most 30
// days after created_at.
func ctList03(t *testing.T, s *suite) {
	now := time.Now().Unix()
	for _, ev := range s.h.(Lister).Listings(t) {
		if int64(ev.CreatedAt) > now {
			t.Errorf("%s post-dated: %d > %d", ev.ID, ev.CreatedAt, now)
		}
		if ev.Kind != listing.KindListing {
			continue
		}
		var exp int64
		err := strconv.ErrSyntax
		if v := ev.GetTag("expiration"); len(v) == 1 {
			exp, err = strconv.ParseInt(v[0], 10, 64)
		}
		if err != nil || exp > int64(ev.CreatedAt)+listing.MaxExpirySecs {
			t.Errorf("%s expiration %d beyond 30 days (%v)", ev.ID, exp, err)
		}
	}
}

// CT-LIST-04: the Hub's get_info agrees with each open listing at tap.
func ctList04(t *testing.T, s *suite) {
	for _, l := range listed(t, s) {
		if l.Status == listing.StatusClosed {
			continue
		}
		gi, raw, err := tapInfo(t, l)
		if r := listing.CheckTap(l, gi, raw, err); r.Outcome != listing.TapShow {
			t.Errorf("%s at tap: %v (%s)", l.Address(), r.Outcome, r.Reason)
		}
	}
}

// retireCheck asserts the retirement order for addr: get_info's closed signal
// (hidden until newer at tap), a closed version newer than every open one, and
// a deletion, if any, only after it and after the last open version expired.
func retireCheck(t *testing.T, s *suite, open *listing.Listing) {
	t.Helper()
	gi, raw, err := tapInfo(t, open)
	if r := listing.CheckTap(open, gi, raw, err); r.Outcome != listing.TapHideUntilNewer {
		t.Errorf("after retiring, get_info at tap → %v (%s), want the closed signal", r.Outcome, r.Reason)
	}
	addr := open.Address()
	var closedAt, lastOpenExpiry int64
	for _, ev := range s.h.(Lister).Listings(t) {
		switch ev.Kind {
		case listing.KindListing:
			l, err := listing.ParseListing(ev, s.listOptions())
			if err != nil || l.Address() != addr {
				continue
			}
			if l.Status == listing.StatusClosed {
				closedAt = max(closedAt, l.CreatedAt())
			} else {
				lastOpenExpiry = max(lastOpenExpiry, l.ExpiresAt())
				if closedAt != 0 && l.CreatedAt() >= closedAt {
					t.Errorf("an open version at or after the closed one")
				}
			}
		case 5:
			for _, tg := range ev.Tags {
				if len(tg) >= 2 && tg[0] == "a" && tg[1] == addr {
					if closedAt == 0 || int64(ev.CreatedAt) < lastOpenExpiry {
						t.Errorf("deletion of %s before its closed version or before the last open version expired", addr)
					}
				}
			}
		}
	}
	if closedAt <= open.CreatedAt() {
		t.Errorf("no closed version of %s after the open one", addr)
	}
}

// CT-LIST-05 (CASH-LIST-04): Retire closes get_info first, then publishes a
// closed version, and deletes only after it.
func ctList05(t *testing.T, s *suite) {
	for _, l := range listed(t, s) {
		if l.Type != listing.TypeCashOrder || l.Status == listing.StatusClosed {
			continue
		}
		s.h.(Lister).Retire(t, l.Address())
		retireCheck(t, s, l)
		return
	}
	t.Skip("the Hub lists no open Order connection")
}

// CT-LIST-06 (CASH-LIST-04): CloseCircle turns accepting false first, then
// publishes a closed version.
func ctList06(t *testing.T, s *suite) {
	for _, l := range listed(t, s) {
		if l.Type != listing.TypeCircleWallet || l.Status == listing.StatusClosed {
			continue
		}
		s.h.(Lister).CloseCircle(t, l.D)
		retireCheck(t, s, l)
		return
	}
	t.Skip("the Hub lists no open circle")
}
