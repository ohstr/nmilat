package nipcash

import "testing"

// testInvoice is a real BOLT11 invoice (nip57's own decode test fixture) —
// reused here rather than hand-constructing one, since a hand-rolled
// invoice string risks not matching the real BOLT11 checksum/encoding
// nip57.DecodeBolt11 actually parses.
const testInvoice = "lnfc50n1p5hxs4npp5smus34m4mzd2jk7gepqkx9j89w2ukrjfajrvevwgslklzgt8l4zsdqqcqzvsxqyz5vqrzjqwz8th0q6p25q5wcvxh2s75n960tm3tung3vc7lmmmcdltt98pjs9apyqqqqqqqqqyqqqqlgqqqqqeqpjqrzjqtnr4hly8edgpl5wvcx86ekcc2rezdnq2calx5xpwk92l50qscwteapyqqqqqqqqquqqqqlgqqqqqeqpjqrzjqwz8th0q6p25q5wcvxh2s75n960tm3tung3vc7lmmmcdltt98pjs9apyqqqqqqqqqgqqqqlgqqqqqeqpjqsp5ge3wl84an6d34x6r7hm82thlg7vgwdffec5xnut90uwj3fvtaqjs9qxpqysgq6rp4rv2lgkffvd239dmj4ehg7vfxuuulu2amjpjf3rrhjhyay0djvjj8hn95rlz9g2kudqmqhw49urrxm6fhnzx6htwpjv6hj3k53hcq7qxkwk"

func TestCashRedeemParams_Request_Bearer(t *testing.T) {
	p := CashRedeemParams{Invoice: testInvoice, Credential: BySecret("mysecret")}
	req, err := p.Request(randomKeyHex(t))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.BearerSecret != "mysecret" {
		t.Fatalf("BearerSecret: got %q", req.BearerSecret)
	}
	if req.IdentityType != "" || req.IdentityEvent != "" {
		t.Fatalf("a bearer request must carry no identity fields: %+v", req)
	}
}

func TestCashRedeemParams_Request_Signing(t *testing.T) {
	privKeyHex, pubKeyHex := generateTestKeypair(t)
	walletPubkey := randomKeyHex(t)

	p := CashRedeemParams{Invoice: testInvoice, Credential: BySigning(privKeyHex)}
	req, err := p.Request(walletPubkey)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if req.IdentityType != identityTypePubkey {
		t.Fatalf("IdentityType: got %s", req.IdentityType)
	}
	if req.IdentityValue != pubKeyHex {
		t.Fatalf("IdentityValue: got %s, want %s", req.IdentityValue, pubKeyHex)
	}
	if req.IdentityEvent == "" {
		t.Fatal("expected a signed identity_event")
	}
	if req.BearerSecret != "" {
		t.Fatalf("a signing request must carry no bearer_secret: %+v", req)
	}
}

func TestCashRedeemParams_Request_InvalidInvoice(t *testing.T) {
	p := CashRedeemParams{Invoice: "not-a-real-invoice", Credential: BySecret("s")}
	if _, err := p.Request(randomKeyHex(t)); err == nil {
		t.Fatal("expected an error for a malformed invoice")
	}
}
