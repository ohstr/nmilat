package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// K-PH-1..4 (plan §4.2): the params hash of {} (and absent params), of
// {"scope":"all"}, and of a number beyond 2^53 beside an HTML character;
// K-PH-4 are the hashes of the two wrong canonicalizations, which
// CanonicalParamsHash never produces.
func TestKPH_ParamsHash(t *testing.T) {
	for _, c := range []struct {
		id, params, want string
	}{
		{"K-PH-1", "{}", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		{"K-PH-1 absent", "", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		{"K-PH-2", `{"scope":"all"}`, "ad912f7b3df717e48cbec6d735d0a02bdef1569dd700e374445aea82120592d5"},
		{"K-PH-3", `{"amount":18446744073709551615,"invoice":"a<b"}`, "88fe51f35b9c0a5ee45347afdaa517b2cb3ebc5916e4e0fe3b2fe42494e616a4"},
	} {
		var p json.RawMessage
		if c.params != "" {
			p = json.RawMessage(c.params)
		}
		if got, err := CanonicalParamsHash(p); err != nil || got != c.want {
			t.Errorf("%s = %s (%v), want %s", c.id, got, err, c.want)
		}
	}
	k3, _ := CanonicalParamsHash(json.RawMessage(`{"amount":18446744073709551615,"invoice":"a<b"}`))
	for _, c := range []struct{ id, text, want string }{
		{"K-PH-4 < escaped", `{"amount":18446744073709551615,"invoice":"a\u003cb"}`, "2625065109f911142b060568bcfeda2e1f83514be6607bcc039feedbdb3e7b60"},
		{"K-PH-4 float-rounded", `{"amount":18446744073709552000,"invoice":"a<b"}`, "b5900d536afbcdce0fe359557e6b7b5c0258d41ddbad09ca7a2cda99ae5b89c6"},
	} {
		sum := sha256.Sum256([]byte(c.text))
		if hex.EncodeToString(sum[:]) != c.want {
			t.Errorf("%s = %x, want %s", c.id, sum, c.want)
		}
		if k3 == c.want {
			t.Errorf("%s: CanonicalParamsHash produced the negative vector", c.id)
		}
	}
}
