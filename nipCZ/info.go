package nipCZ

import (
	"github.com/ohstr/nmilat/nip01"
)

// CashZapInfo is a parsed kind 10522 (NIP-CZ §Kind 10522). A nil *CashZapInfo
// is a recipient with no 10522 (every ConnectionKey included): any chain, no
// trusted minter, no relays.
type CashZapInfo struct {
	// Pubkey is the recipient, the 10522's author.
	Pubkey string
	// Chains are the accepted chains; none means any.
	Chains []string
	// Mints maps an accepted chain to the x-only keys of the minters listed for
	// it. A mint for an unaccepted chain, without a chain, or not 66 lowercase hex
	// is ignored.
	Mints  map[string][]string
	Relays []string
}

// ParseCashZapInfo verifies a 10522's signature and reads its tags.
func ParseCashZapInfo(ev *nip01.Event) (*CashZapInfo, error) {
	if ev == nil || ev.Kind != KindCashZapInfo {
		return nil, ErrWrongKind
	}
	if err := ev.Verify(); err != nil {
		return nil, err
	}
	info := &CashZapInfo{Pubkey: ev.PubKey, Mints: map[string][]string{}}
	type mint struct{ key, chain string }
	var mints []mint
	for _, t := range ev.Tags {
		if len(t) < 2 || t[1] == "" {
			continue
		}
		switch t[0] {
		case "chain":
			if !contains(info.Chains, t[1]) {
				info.Chains = append(info.Chains, t[1])
			}
		case "mint":
			if len(t) < 3 || t[2] == "" || len(t[1]) != 66 || minterKey(t[1]) == "" {
				continue
			}
			mints = append(mints, mint{key: minterKey(t[1]), chain: t[2]})
		case "relay":
			info.Relays = append(info.Relays, t[1])
		}
	}
	for _, m := range mints {
		if info.Accepts(m.chain) && !contains(info.Mints[m.chain], m.key) {
			info.Mints[m.chain] = append(info.Mints[m.chain], m.key)
		}
	}
	return info, nil
}

// Accepts reports a chain the recipient accepts: any chain without chain tags
// or without a 10522.
func (i *CashZapInfo) Accepts(chain string) bool {
	if i == nil || len(i.Chains) == 0 {
		return true
	}
	return contains(i.Chains, chain)
}

// ListsMinter reports a minter the recipient lists for chain, compared by its
// x-only part (minterXOnly may be compressed or x-only).
func (i *CashZapInfo) ListsMinter(minterXOnly, chain string) bool {
	if i == nil || !i.Accepts(chain) {
		return false
	}
	x := minterKey(minterXOnly)
	return x != "" && contains(i.Mints[chain], x)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
