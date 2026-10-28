package nipcw

import (
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// Item builds the join's create_circle_wallet item for NIP-CASH's private
// transport (NIP-CW §Private Join), the only transport a join travels on. It
// targets the Hub (j.HubPubkey); its kind-23192 item proof is signed by the
// requester's key, and its bill proof by hubSecret, the secret of the Hub
// connection the member holds. b.HubXOnly is the node identity from get_info.
//
// Item is single use: a second call returns ErrPreparedJoinUsed, so one proof is
// never sent twice. A retry needs a new Prepare.
func (j *PreparedJoin) Item(id, hubSecret string, b nipcash.ItemBinding) (transport.Item, error) {
	if err := j.claim(); err != nil {
		return transport.Item{}, err
	}
	return nipcash.BuildItem(id, j.HubPubkey, hubSecret, MethodCreateCircleWallet, j.Request,
		nipcash.BySigning(j.cred.privKeyHex), b)
}
