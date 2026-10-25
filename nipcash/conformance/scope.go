package conformance

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	relayclient "github.com/ohstr/nmilat/relay/client"
)

// scopeCases are the connection-scope cases (NIP-CASH §Which Methods a Hub
// Serves, §Scopes).
var scopeCases = []ctCase{
	{id: "CT-ENV-14", run: ctEnv14},
	{id: "CT-SCOPE-03", run: ctScope03},
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
