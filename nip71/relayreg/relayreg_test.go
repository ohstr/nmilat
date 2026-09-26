package relayreg_test

import (
	"testing"

	"github.com/ohstr/nmilat/nip11"
	_ "github.com/ohstr/nmilat/nip71/relayreg"
	"github.com/ohstr/nmilat/relay"
)

func TestNIP71IsDeclared(t *testing.T) {
	var ids []string
	for _, id := range relay.RegisteredNIPs() {
		if id == nip11.NIP(71) {
			return
		}
		ids = append(ids, id.String())
	}
	t.Errorf("NIP-71 is not declared in the relay's supported NIPs; declared: %v", ids)
}
