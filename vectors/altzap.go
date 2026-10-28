package vectors

import (
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/utils"
)

// ---- altzap.json (NIP-AZ; drift only)

type altzapFile struct {
	header
	KAT      altzapKAT        `json:"kat"`
	Validate []altzapValidate `json:"validateForRelay"`
}

// altzapKAT: K-AZ-1, a deterministic 9520 from key 01x32 to a github
// connection key with an ia (key 02x32), created_at 1720000000.
type altzapKAT struct {
	ID            string      `json:"id"`
	SenderSecret  string      `json:"senderSecret"`
	GithubUserID  string      `json:"githubUserId"`
	ConnectionKey string      `json:"connectionKey"`
	IA            string      `json:"ia"`
	Lnurl         string      `json:"lnurl"`
	Event         nip01.Event `json:"event"`
}

type altzapValidate struct {
	Name  string      `json:"name"`
	Event nip01.Event `json:"event"`
	Error string      `json:"error,omitempty"`
}

func buildAltZap() (any, error) {
	f := altzapFile{header: newHeader(
		"NIP-AZ alternative zap request (kind 9520) to a connection key, frozen for drift (K-AZ-1).",
		"nipAZ/request.go NewAltZapRequest, ValidateAltZapRequestForRelay; nipAZ/kat_test.go (K-AZ-1)",
	)}
	const userID = "1234567"
	ck, err := nipIC.ConnectionKeyFromAttested("github", userID)
	if err != nil {
		return nil, err
	}
	ia, err := utils.GetPublicKey(strings.Repeat("02", 32))
	if err != nil {
		return nil, err
	}
	lnurl, err := utils.EncodeLNURL("https://pay.example.com/lnurlp/alice")
	if err != nil {
		return nil, err
	}
	ev, err := nipAZ.NewAltZapRequest(nipAZ.AltZapRequestParams{
		PrivateKey: strings.Repeat("01", 32), Chain: "examplecoin",
		Recipient: nipAZ.ResolvedConnection(ck, "github"), IA: ia,
		Lnurl: lnurl, AmountMloki: 21000, Relays: []string{"wss://relay.example.com"},
	})
	if err != nil {
		return nil, err
	}
	ev.CreatedAt = 1720000000
	if err := ev.Sign(strings.Repeat("01", 32)); err != nil {
		return nil, err
	}
	f.KAT = altzapKAT{"K-AZ-1", strings.Repeat("01", 32), userID, string(ck), ia, lnurl, *ev}
	val := func(name string, e nip01.Event) {
		f.Validate = append(f.Validate, altzapValidate{name, e, errString(nipAZ.ValidateAltZapRequestForRelay(&e))})
	}
	val("K-AZ-1", *ev)
	bad := *ev
	bad.Sig = flipHex(bad.Sig)
	val("bad signature", bad)
	return f, nil
}
