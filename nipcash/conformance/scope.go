package conformance

import (
	"context"
	"errors"
	"github.com/ohstr/nmilat/nip47"
	"slices"
	"strings"
	"testing"
	"time"

	relayclient "github.com/ohstr/nmilat/relay/client"
)

// scopeCases are the connection-scope cases (NIP-CASH §Which Methods a Hub
// Serves, §Scopes).
var scopeCases = []ctCase{
	{id: "CT-ENV-14", run: ctEnv14},
	{id: "CT-SCOPE-03", run: ctScope03},
	{id: "CT-CSIG-01", run: ctCsig01},
	{id: "CT-CSIG-02", run: ctCsig02},
}

// CT-CSIG-02 (CASH-CSIG-04, CASH-NET-01): the Cash Hub connection's get_info
// names the chain TLV 6 names, and a network of the four.
func ctCsig02(t *testing.T, s *suite) {
	if s.info.Chain != s.conn.Chain {
		t.Errorf("get_info chain %q, TLV 6 %q", s.info.Chain, s.conn.Chain)
	}
	if !nip47.ValidNetwork(s.info.Network) {
		t.Errorf("get_info network %q", s.info.Network)
	}
}

// CT-CSIG-01 (CASH-CSIG-01..03): the cashhub1 string the Hub hands out carries
// TLV 4, 5 and 6 (it decoded, so they are there), verifies, and its TLV 4 is the
// announcement's author. The circlehub1 and cashorder1 halves join with their
// codecs.
func ctCsig01(t *testing.T, s *suite) {
	if err := s.conn.Verify(); err != nil {
		t.Errorf("cashhub1 does not verify: %v", err)
	}
	// The suite found the announcement through TLV 4, so its author is TLV 4. The
	// get_info half of the online check: its pubkey's x-only part is TLV 4.
	got := strings.ToLower(s.info.Pubkey)
	if len(got) == 66 && (strings.HasPrefix(got, "02") || strings.HasPrefix(got, "03")) {
		got = got[2:]
	}
	if got != s.conn.HubIdentity {
		t.Errorf("get_info pubkey %s is not TLV 4 %s", s.info.Pubkey, s.conn.HubIdentity)
	}
}

// CT-ENV-14 (S-CASH-38, S-CASH-161): the bill methods and cash_lookup sent as
// kind 23194 are refused NOT_IMPLEMENTED.
func ctEnv14(t *testing.T, s *suite) {
	for _, method := range []string{"cash_status", "cash_redeem", "cash_transfer", "cash_consolidate", "cash_lookup"} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := s.nwc.Call(ctx, method, map[string]any{})
		cancel()
		var we *relayclient.WalletError
		switch {
		case errors.As(err, &we):
			if we.Code != "NOT_IMPLEMENTED" {
				t.Errorf("%s on 23194: %s, want NOT_IMPLEMENTED", method, we.Code)
			}
		case err != nil:
			t.Errorf("%s on 23194: %v", method, err)
		case resp.Error == nil || resp.Error.Code != "NOT_IMPLEMENTED":
			t.Errorf("%s on 23194 was not refused NOT_IMPLEMENTED: %+v", method, resp.Response)
		}
	}
}

// CT-SCOPE-03 (S-CASH-31, S-CASH-183): the Cash Hub connection's get_info names
// the node identity (the announcement's author, already verified by the suite's
// setup) and lists cash_lookup among its private methods, never in methods.
func ctScope03(t *testing.T, s *suite) {
	if len(s.info.Pubkey) != 64 {
		t.Errorf("get_info pubkey %q is not 64 hex characters", s.info.Pubkey)
	}
	if !slices.Contains(s.info.PrivateMethods, "cash_lookup") {
		t.Errorf("private_methods %v lacks cash_lookup", s.info.PrivateMethods)
	}
	for _, m := range s.info.PrivateMethods {
		if slices.Contains(s.info.Methods, m) {
			t.Errorf("%s is in both methods and private_methods", m)
		}
	}
}
