package relayreg_test

import (
	"testing"

	"github.com/ohstr/nmilat/nip11"
	_ "github.com/ohstr/nmilat/nipA0/relayreg"
	"github.com/ohstr/nmilat/relay"
)

// NIP-A0's id is a letter form, so it must be declared via
// RegisterLetteredNIP. Declaring it with RegisterNIP would compile fine and
// silently advertise "NIP-160" instead -- this test is what catches that.
func TestNIPA0IsDeclaredAsALetteredNIP(t *testing.T) {
	var ids []string
	for _, id := range relay.RegisteredNIPs() {
		if id == nip11.NIPLetter("A0") {
			return
		}
		ids = append(ids, id.String())
	}
	t.Errorf("NIP-A0 is not declared as a lettered NIP; declared: %v", ids)
}

func TestNIPA0IsNotDeclaredAsANumber(t *testing.T) {
	for _, id := range relay.RegisteredNIPs() {
		if id == nip11.NIP(0xA0) {
			t.Error(`NIP-A0 is declared as the number 160; use RegisterLetteredNIP("A0")`)
		}
	}
}
