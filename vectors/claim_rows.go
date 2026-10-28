package vectors

import (
	"strings"

	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
)

// ownRowCase: nipcash.OwnRow(Rows, credential, Scope) either fails or
// returns Rows[Index]. The credential is named, as in requestCase.
type ownRowCase struct {
	Name       string                    `json:"name"`
	Credential string                    `json:"credential"`
	Scope      string                    `json:"scope"`
	Rows       []nipcash.RecipientStatus `json:"rows"`
	Index      int                       `json:"index"` // -1 = error
	Error      string                    `json:"error,omitempty"`
}

// claimableCase: nipcash.Claimable(Row, Now).
type claimableCase struct {
	Name   string                  `json:"name"`
	Row    nipcash.RecipientStatus `json:"row"`
	Now    int64                   `json:"now"`
	OK     bool                    `json:"ok"`
	Reason string                  `json:"reason"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func ownRowCases(userPub string, ck nipIC.ConnectionKey, iaPub string, targets []*nipcash.CashTarget, cred map[string]nipcash.Credential) ([]ownRowCase, []claimableCase) {
	other := strings.Repeat("ef", 32)
	otherIA := strings.Repeat("9a", 32)
	commit := must(nipcash.CashCommitment(targets[0].Secret()))
	rs := func(typ, value, ia string, amount uint64) nipcash.RecipientStatus {
		return nipcash.RecipientStatus{IdentityType: typ, IdentityValue: value, IAPubkey: ia, AmountMillis: amount}
	}
	cred["cash"] = nipcash.BySecret(targets[0].Secret())
	var own []ownRowCase
	add := func(name, cn, scope string, rows ...nipcash.RecipientStatus) {
		c := ownRowCase{Name: name, Credential: cn, Scope: scope, Rows: rows, Index: -1}
		if c.Rows == nil {
			c.Rows = []nipcash.RecipientStatus{}
		}
		got, err := nipcash.OwnRow(rows, cred[cn], scope)
		if err != nil {
			c.Error = err.Error()
		} else {
			for i := range rows {
				if rows[i] == got {
					c.Index = i
					break
				}
			}
		}
		own = append(own, c)
	}
	add("pubkey, mine", "signing", "mine", rs("pubkey", userPub, "", 1000))
	add("pubkey, empty scope is mine", "signing", "", rs("pubkey", userPub, "", 1000))
	add("connection_key, the credential's IA", "connection_key", "all", rs("connection_key", string(ck), otherIA, 1000), rs("connection_key", string(ck), iaPub, 2000))
	add("connection_key, another IA only", "connection_key", "all", rs("connection_key", string(ck), otherIA, 1000))
	add("cash, mine", "cash", "mine", rs("cash", commit, "", 3000))
	add("cash, uppercase commitment", "cash", "mine", rs("cash", strings.ToUpper(commit), "", 3000))
	add("widened mine with no row", "signing", "mine")
	add("widened mine: two rows", "signing", "mine", rs("pubkey", userPub, "", 1000), rs("pubkey", other, "", 2000))
	add("mine answered with another identity's row", "signing", "mine", rs("pubkey", other, "", 2000))
	add("all: the caller's row among others", "signing", "all", rs("pubkey", other, "", 2000), rs("pubkey", userPub, "", 1000))
	add("all: no match", "signing", "all", rs("pubkey", other, "", 2000), rs("cash", commit, "", 1000))

	const exp = int64(1720000000)
	withExp := func(r nipcash.RecipientStatus, at int64) nipcash.RecipientStatus {
		r.ExpiresAt = nipcash.Expiry{At: at, Present: true}
		return r
	}
	var cl []claimableCase
	addC := func(name string, r nipcash.RecipientStatus, now int64) {
		ok, reason := nipcash.Claimable(r, now)
		cl = append(cl, claimableCase{name, r, now, ok, reason})
	}
	live := rs("pubkey", userPub, "", 1000)
	addC("live, never expires", live, exp)
	claimed := live
	claimed.Claimed = true
	at := exp - 10
	claimed.ClaimedAt = &at
	addC("claimed", claimed, exp)
	wd := live
	wd.WithdrawRequestID = "00112233445566778899aabbccddeeff"
	addC("ended by a cash_withdraw", wd, exp)
	addC("live at expires_at", withExp(live, exp), exp)
	addC("expired one second later", withExp(live, exp), exp+1)
	return own, cl
}
