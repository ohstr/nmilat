package nipCZ

import "github.com/ohstr/nmilat/nipcash"

// Chain is one row of NIP-CZ §Chains: a token prefix (HRP), the chain it names
// and the signed-message prefix its Minters sign under.
type Chain struct{ HRP, Name, SignedMessagePrefix string }

// Chains are the rows this package knows. The first is the spec's; the second
// is implementation-defined, as the spec allows any other energy-backed coin's
// implementation to define its own. A token whose prefix has no row carries no
// valid signature (rule 6).
var Chains = []Chain{
	{HRP: "satscash", Name: "bitcoin", SignedMessagePrefix: nipcash.LndSignedMessagePrefix},
	{HRP: "lokicash", Name: "flokicoin", SignedMessagePrefix: nipcash.LNSignedMessagePrefix},
}

// ChainForHRP is the row for a token prefix, and false for a prefix with none.
func ChainForHRP(hrp string) (Chain, bool) {
	for _, c := range Chains {
		if c.HRP == hrp {
			return c, true
		}
	}
	return Chain{}, false
}
