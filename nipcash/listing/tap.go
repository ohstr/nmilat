package listing

import (
	"encoding/json"
	"strconv"
	"sync"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
)

// TapOutcome is what a wallet does with a listing version after the user taps
// it (§Wallet Rules "At tap"). It is a display state, never a wire code.
type TapOutcome int

const (
	// TapShow shows the terms read from get_info.
	TapShow TapOutcome = iota
	// TapHideForGood hides that version for good: a reply the listed
	// connection signed failed the online check or named another network.
	TapHideForGood
	// TapHideUntilNewer hides it until a newer version: the Hub's own closed
	// signal ("cash_order" selling nothing, or accepting false).
	TapHideUntilNewer
	// TapUnavailable keeps it, shown as unavailable for now: no answer, a silent
	// relay, available_millis 0 or any error code.
	TapUnavailable
)

func (o TapOutcome) String() string {
	switch o {
	case TapShow:
		return "show"
	case TapHideForGood:
		return "hide_for_good"
	case TapHideUntilNewer:
		return "hide_until_newer"
	case TapUnavailable:
		return "unavailable"
	}
	return "unknown"
}

// TapResult is CheckTap's verdict. Terms (cash_order) or Circle (circle_wallet)
// are set with TapShow: show them, never the hint, and say so when HintDiffers.
type TapResult struct {
	Outcome     TapOutcome
	Reason      string
	Terms       *nipCO.Terms
	Circle      *nip47.CircleWalletInfo
	HintDiffers bool
}

// CheckTap runs §Wallet Rules "At tap" steps 2 to 5 on get_info's reply from the
// listed connection: info decoded, raw the same result as JSON (for
// nipCO.ParseOrderInfo), infoErr any failure to get it (no answer, a timeout, a
// silent relay, an NWC error code). The NWC client accepted the reply only from
// TLV 0, so the listed connection signed it, and a mismatch in it hides that
// version for good. The identity read is pubkey for cash_order and
// circle_wallet.identity for a circle.
func CheckTap(l *Listing, info *nip47.GetInfoResult, raw json.RawMessage, infoErr error) TapResult {
	if infoErr != nil || info == nil {
		return TapResult{Outcome: TapUnavailable, Reason: "no get_info answer"}
	}
	var check nipcash.OnlineCheck
	identity := info.Pubkey
	switch {
	case l.Order != nil:
		check = nipcash.OnlineCheck{HubIdentity: l.Order.HubIdentity, Chain: l.Order.Chain}
	case l.Circle != nil:
		check = nipcash.OnlineCheck{HubIdentity: l.Circle.HubIdentity, Chain: l.Circle.Chain}
		identity = ""
		if info.CircleWallet != nil {
			identity = info.CircleWallet.Identity
		}
	default:
		return TapResult{Outcome: TapUnavailable, Reason: "no listed connection"}
	}
	if err := check.Check(identity, info.Chain); err != nil {
		return TapResult{Outcome: TapHideForGood, Reason: "online check failed"}
	}
	if !nipcash.HubIdentityEqual(l.NodeIdentity, identity) {
		return TapResult{Outcome: TapHideForGood, Reason: "get_info names another identity than the listing"}
	}
	if info.Network != l.Network {
		return TapResult{Outcome: TapHideForGood, Reason: "get_info names another network than the listing"}
	}
	if l.Order != nil {
		// Only a cash_order object is the Hub's closed signal: a reply without
		// the key (an old or degraded Hub) is no answer about the terms.
		var keys map[string]json.RawMessage
		if json.Unmarshal(raw, &keys) != nil {
			return TapResult{Outcome: TapUnavailable, Reason: "terms do not parse"}
		}
		if _, ok := keys["cash_order"]; !ok {
			return TapResult{Outcome: TapUnavailable, Reason: "get_info carries no cash_order terms"}
		}
		terms, err := nipCO.ParseOrderInfo(raw)
		if err != nil {
			return TapResult{Outcome: TapUnavailable, Reason: "terms do not parse"}
		}
		if terms.SellsNothing() {
			return TapResult{Outcome: TapHideUntilNewer, Reason: "the Hub sells nothing on this connection"}
		}
		r := TapResult{Outcome: TapShow, Terms: terms}
		for _, h := range l.Hints {
			k := terms.Kind(h.Payment)
			if k == nil || k.MinMillis != h.MinMillis || k.MaxMillis != h.MaxMillis || k.FeeBase != h.FeeBase || k.FeePpm != h.FeePpm {
				r.HintDiffers = true
			}
		}
		return r
	}
	cw := info.CircleWallet
	if cw.Accepting == nil {
		return TapResult{Outcome: TapUnavailable, Reason: "get_info does not say whether the circle accepts joins"}
	}
	if !*cw.Accepting {
		return TapResult{Outcome: TapHideUntilNewer, Reason: "the circle takes no joins"}
	}
	if cw.AvailableMillis <= 0 {
		return TapResult{Outcome: TapUnavailable, Reason: "the circle has nothing available"}
	}
	return TapResult{Outcome: TapShow, Circle: cw}
}

// TapCache remembers tap outcomes per pubkey, d and created_at. Only
// TapHideForGood and TapHideUntilNewer hide; both are per version, so a newer
// created_at is never hidden by an older version's outcome. It is safe for
// concurrent use.
//
// It also remembers which addresses (pubkey and d) passed the check at tap
// (TapShow), which decides what shows when several pubkeys list one d
// (VersionBook.CurrentByD).
type TapCache struct {
	mu     sync.Mutex
	hide   map[string]TapOutcome
	passed map[string]bool
}

// NewTapCache returns an empty cache.
func NewTapCache() *TapCache {
	return &TapCache{hide: map[string]TapOutcome{}, passed: map[string]bool{}}
}

func tapKey(l *Listing) string {
	return l.NodeIdentity + ":" + l.D + ":" + strconv.FormatUint(l.Event.CreatedAt, 10)
}

// Record stores a hiding outcome for l's version and marks l's address as
// passed on TapShow; TapUnavailable records nothing, and a version hidden for
// good stays so.
func (c *TapCache) Record(l *Listing, r TapResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hide == nil {
		c.hide = map[string]TapOutcome{}
	}
	if c.passed == nil {
		c.passed = map[string]bool{}
	}
	switch r.Outcome {
	case TapShow:
		c.passed[l.Address()] = true
	case TapHideForGood, TapHideUntilNewer:
		if prev, ok := c.hide[tapKey(l)]; !ok || prev != TapHideForGood {
			c.hide[tapKey(l)] = r.Outcome
		}
	}
}

// Hidden reports whether a recorded outcome hides l's version.
func (c *TapCache) Hidden(l *Listing) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.hide[tapKey(l)]
	return ok
}

// Outcome returns the hiding outcome recorded for l's version, if any.
func (c *TapCache) Outcome(l *Listing) (TapOutcome, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, ok := c.hide[tapKey(l)]
	return o, ok
}

// Passed reports whether l's signer passed the check at tap for l's address.
func (c *TapCache) Passed(l *Listing) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.passed[l.Address()]
}
