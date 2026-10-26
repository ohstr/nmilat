package nipcash

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrHubIdentityMismatch is a get_info identity that is not the string's TLV 4.
	ErrHubIdentityMismatch = errors.New("nipcash: get_info names another hub identity than the connection string")
	// ErrChainMismatch is a get_info chain that is missing or not the string's TLV 6.
	ErrChainMismatch = errors.New("nipcash: get_info names another chain than the connection string")
)

// OnlineCheck is what a client checks against get_info before it mints, orders or
// joins over a connection (NIP-CASH §Connection Signatures, online check): TLV 4
// (x-only hex) and TLV 6.
type OnlineCheck struct{ HubIdentity, Chain string }

// Check compares get_info's identity (pubkey, or circle_wallet.identity) and chain
// with the string. A missing chain fails. A client uses no connection that fails.
func (o OnlineCheck) Check(infoIdentity, infoChain string) error {
	if !HubIdentityEqual(o.HubIdentity, infoIdentity) {
		return fmt.Errorf("%w: %q, want %q", ErrHubIdentityMismatch, infoIdentity, o.HubIdentity)
	}
	if infoChain == "" || infoChain != o.Chain {
		return fmt.Errorf("%w: %q, want %q", ErrChainMismatch, infoChain, o.Chain)
	}
	return nil
}

// HubIdentityEqual compares TLV 4 with a get_info identity: the value is
// lowercased, a 66-hex value starting 02 or 03 loses those two characters, and
// the 64 left must equal TLV 4 as hex.
func HubIdentityEqual(tlv4XOnly, value string) bool {
	v := strings.ToLower(value)
	if len(v) == 66 && (strings.HasPrefix(v, "02") || strings.HasPrefix(v, "03")) {
		v = v[2:]
	}
	return len(v) == 64 && isLowerHex64(v) && v == strings.ToLower(tlv4XOnly)
}
