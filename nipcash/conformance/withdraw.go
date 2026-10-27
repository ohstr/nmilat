package conformance

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipcash"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// withdrawCases are the on-chain withdrawal cases that need no bill: what the
// Cash Hub connection says and refuses (NIP-CASH §Redeeming On-chain, §Which
// Methods a Hub Serves).
var withdrawCases = []ctCase{
	{id: "CT-WD-01", run: ctWd01},
	{id: "CT-SCOPE-05", run: ctScope05},
}

// CT-WD-01 (CASH-WD-01), its wire part: cash_withdraw_quote and cash_withdraw
// sent as kind 23194 are NOT_IMPLEMENTED, and get_info's methods lists neither.
func ctWd01(t *testing.T, s *suite) {
	for _, method := range []string{nipcash.MethodCashWithdrawQuote, nipcash.MethodCashWithdraw} {
		if slices.Contains(s.info.Methods, method) {
			t.Errorf("get_info methods lists %s", method)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := s.nwc.Call(ctx, method, map[string]any{})
		cancel()
		var we *relayclient.WalletError
		switch {
		case errors.As(err, &we):
			if we.Code != nipcash.ErrCodeNotImplemented {
				t.Errorf("%s on 23194: %s, want NOT_IMPLEMENTED", method, we.Code)
			}
		case err != nil:
			t.Errorf("%s on 23194: %v", method, err)
		case resp.Error == nil || resp.Error.Code != nipcash.ErrCodeNotImplemented:
			t.Errorf("%s on 23194 was not refused NOT_IMPLEMENTED: %+v", method, resp.Response)
		}
	}
}

// CT-SCOPE-05 (CASH-WD-01): a Hub offering withdrawals lists both
// cash_withdraw and cash_withdraw_quote in private_methods; one that does not
// lists neither.
func ctScope05(t *testing.T, s *suite) {
	quote := slices.Contains(s.info.PrivateMethods, nipcash.MethodCashWithdrawQuote)
	call := slices.Contains(s.info.PrivateMethods, nipcash.MethodCashWithdraw)
	if quote != call {
		t.Errorf("private_methods %v lists one withdrawal method without the other", s.info.PrivateMethods)
	}
}
