package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// suite is what every case knows about the Hub, found once from its Cash Hub
// connection the way a client finds it: TLV 4 names the node identity, whose
// announcement names the inbox, limits and relays.
type suite struct {
	h         HubUnderTest
	o         Options
	conn      nipcash.CashHubConnection
	nwc       *relayclient.NWCClient
	info      *nip47.GetInfoResult
	nodeXOnly string
	inbox     string
	limits    transport.Limits
	relays    []string
	wd        wdState
}

func connect(t *testing.T, h HubUnderTest, o Options) *suite {
	t.Helper()
	conn, err := nipcash.DecodeCashHubConnection(h.CashHubConnection())
	if err != nil {
		t.Fatalf("conformance: the Hub's cashhub1 string does not decode: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	nwc, err := relayclient.NewNWCClient(context.Background(), &nip47.PairingInfo{
		WalletPubkey: conn.Pubkey, RelayURLs: conn.Relays, Secret: conn.Secret,
	}, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("conformance: open the Cash Hub connection: %v", err)
	}
	t.Cleanup(nwc.Close)
	info, err := nwc.GetInfo(ctx)
	if err != nil {
		t.Fatalf("conformance: get_info on the Cash Hub connection: %v", err)
	}
	session, err := client.OpenBatchSession(ctx, conn.HubIdentity, conn.Relays)
	if err != nil {
		t.Fatalf("conformance: the announcement of %s (TLV 4) did not verify: %v", conn.HubIdentity, err)
	}
	return &suite{
		h: h, o: o, conn: conn, nwc: nwc, info: info, nodeXOnly: conn.HubIdentity,
		inbox: session.Inbox(), limits: session.Limits(), relays: session.Relays(),
	}
}

// quiet is how long a case waits before concluding no reply is coming.
func (s *suite) quiet() time.Duration {
	if s.o.Long {
		return 10 * time.Second
	}
	return 2 * time.Second
}
