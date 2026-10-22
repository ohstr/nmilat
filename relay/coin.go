package relay

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ohstr/nmilat/nipAZ"
)

// Coin is the unit a zap was paid in, from its invoice. Amounts are kept in
// milli-units of their coin (msat, mloki); a whole unit is 1000.
type Coin byte

const (
	CoinUnknown Coin = iota
	CoinSats
	CoinLoki

	numCoins = 3
)

var coinNames = [numCoins]string{"", "sats", "loki"}

// chainCoins names the coin of each chain nipAZ knows.
var chainCoins = map[nipAZ.Chain]Coin{
	"bitcoin":   CoinSats,
	"flokicoin": CoinLoki,
}

func (c Coin) String() string {
	if int(c) < numCoins {
		return coinNames[c]
	}
	return ""
}

// Coins lists the known coins.
func Coins() []Coin { return []Coin{CoinSats, CoinLoki} }

// ParseCoin reads a coin name ("sats", "loki").
func ParseCoin(s string) (Coin, error) {
	for c := CoinSats; c < numCoins; c++ {
		if strings.EqualFold(s, coinNames[c]) {
			return c, nil
		}
	}
	return CoinUnknown, fmt.Errorf("unknown coin %q", s)
}

// coinForCurrency maps a BOLT11 currency prefix ("bc", "fc", ...) to its coin.
func coinForCurrency(currency string) Coin {
	for chain, prefixes := range nipAZ.InvoiceCurrencies {
		if slices.Contains(prefixes, currency) {
			return chainCoins[chain]
		}
	}
	return CoinUnknown
}

// WholeUnits converts milli-units to whole units, rounding down.
func WholeUnits(milli uint64) uint64 { return milli / 1000 }
