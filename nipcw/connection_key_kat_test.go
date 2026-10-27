package nipcw

import "testing"

// ConnectionKeyFromSecret known answers: the x-only public key of a member's
// connection secret (values frozen in connection-key.json, matching the
// independent cashkit port). A secret that is not 64 lowercase hex is refused.
func TestConnectionKeyFromSecret_KAT(t *testing.T) {
	for _, c := range []struct{ secret, pubkey string }{
		{"1111111111111111111111111111111111111111111111111111111111111111", "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"},
		{"0000000000000000000000000000000000000000000000000000000000000001", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
		{"0000000000000000000000000000000000000000000000000000000000000002", "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"},
		{"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
	} {
		k, err := ConnectionKeyFromSecret(c.secret)
		if err != nil || k.Pubkey() != c.pubkey {
			t.Errorf("ConnectionKeyFromSecret(%s) = %s (%v), want %s", c.secret, k.Pubkey(), err, c.pubkey)
		}
	}
	for _, s := range []string{
		"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
		"11111111111111111111111111111111111111111111111111111111111111",
		"111111111111111111111111111111111111111111111111111111111111111111",
		"zz11111111111111111111111111111111111111111111111111111111111111",
		"",
	} {
		if _, err := ConnectionKeyFromSecret(s); err == nil {
			t.Errorf("ConnectionKeyFromSecret(%q) accepted", s)
		}
	}
}
