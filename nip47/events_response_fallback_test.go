package nip47

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// findTag returns the first value of tag name's first occurrence, or ""
// if absent.
func findTag(tags [][]string, name string) (string, bool) {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == name {
			return tag[1], true
		}
	}
	return "", false
}

// removeTag drops every occurrence of name from tags.
func removeTag(tags [][]string, name string) [][]string {
	out := make([][]string, 0, len(tags))
	for _, tag := range tags {
		if len(tag) >= 1 && tag[0] == name {
			continue
		}
		out = append(out, tag)
	}
	return out
}

// stripEncryptionTagAndResign builds a normal get_balance response event via
// NewResponseEvent (which self-tags a NIP-44 v2 response with its own
// "encryption" tag), then strips that tag and re-signs - reproducing a
// wallet that replies in kind without redeclaring which scheme it used, the
// case ParseResponseEventWithFallback exists for. The event is still
// genuinely encrypted under encryption; only the tag declaring that is
// missing.
func stripEncryptionTagAndResign(t *testing.T, appPubkey string, requestEvent *nip01.Event, encryption string) *nip01.Event {
	t.Helper()
	respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodGetBalance, GetBalanceResult{BalanceMloki: 1000}, requestEvent, encryption)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	respEv.Tags = removeTag(respEv.Tags, "encryption")
	if err := respEv.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return respEv
}

func TestParseResponseEvent_DefaultsToNIP04(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodGetBalance, nil, EncryptionNIP04)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// NewResponseEvent never tags a NIP-04 response with "encryption" at
	// all (buildResponseEvent only adds the tag for NIP-44 v2) - so this is
	// already an untagged response, no stripping needed.
	respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodGetBalance, GetBalanceResult{BalanceMloki: 1000}, reqEv, EncryptionNIP04)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	if err := respEv.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if tag, _ := findTag(respEv.Tags, "encryption"); tag != "" {
		t.Fatalf("test setup: expected no encryption tag on a NIP-04 response, got %q", tag)
	}

	got, err := ParseResponseEvent(respEv, testAppPrivKey)
	if err != nil {
		t.Fatalf("ParseResponseEvent() error = %v, want it to decrypt an untagged response as NIP-04 by default", err)
	}
	var balance GetBalanceResult
	if err := unmarshalParams(got.Result, &balance); err != nil {
		t.Fatalf("unmarshal result error = %v", err)
	}
	if balance.BalanceMloki != 1000 {
		t.Errorf("BalanceMloki = %d, want 1000", balance.BalanceMloki)
	}
}

func TestParseResponseEvent_UntaggedNIP44Response_MisparsedAsNIP04(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodGetBalance, nil, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	respEv := stripEncryptionTagAndResign(t, appPubkey, reqEv, EncryptionNIP44V2)

	// This is the exact bug ParseResponseEventWithFallback exists to let
	// callers avoid: ParseResponseEvent's own hardcoded NIP-04 default
	// cannot tell this genuinely-NIP-44-v2 response apart from a genuinely
	// untagged NIP-04 one, and fails to decrypt it. This test locks in
	// that this is ParseResponseEvent's documented, unchanged behavior
	// (existing callers of the plain function must keep seeing it) -
	// ParseResponseEventWithFallback is the fix, not a change to this
	// function's own default.
	if _, err := ParseResponseEvent(respEv, testAppPrivKey); err == nil {
		t.Fatal("ParseResponseEvent() error = nil, want a decrypt failure for an untagged NIP-44 v2 response under the hardcoded NIP-04 default")
	}
}

func TestParseResponseEventWithFallback_UntaggedResponse_UsesFallback(t *testing.T) {
	for _, encryption := range []string{EncryptionNIP04, EncryptionNIP44V2} {
		t.Run(encryption, func(t *testing.T) {
			walletPubkey := pubkeyOf(t, testWalletPrivKey)
			appPubkey := pubkeyOf(t, testAppPrivKey)

			reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodGetBalance, nil, encryption)
			if err != nil {
				t.Fatalf("NewRequestEvent() error = %v", err)
			}
			if err := reqEv.Sign(testAppPrivKey); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			respEv := stripEncryptionTagAndResign(t, appPubkey, reqEv, encryption)

			got, err := ParseResponseEventWithFallback(respEv, testAppPrivKey, encryption)
			if err != nil {
				t.Fatalf("ParseResponseEventWithFallback() error = %v, want it to decrypt an untagged response using the fallback scheme", err)
			}
			var balance GetBalanceResult
			if err := unmarshalParams(got.Result, &balance); err != nil {
				t.Fatalf("unmarshal result error = %v", err)
			}
			if balance.BalanceMloki != 1000 {
				t.Errorf("BalanceMloki = %d, want 1000", balance.BalanceMloki)
			}
		})
	}
}

func TestParseResponseEventWithFallback_TaggedResponse_TagWinsOverFallback(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodGetBalance, nil, EncryptionNIP04)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// A real NIP-44 v2 response, correctly self-tagged - NewResponseEvent's
	// own default behavior, untouched.
	respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodGetBalance, GetBalanceResult{BalanceMloki: 1000}, reqEv, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	if err := respEv.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Fallback says NIP-04, deliberately wrong - the response's own tag
	// (NIP-44 v2) MUST still win, or a caller that guessed the wrong
	// fallback would break responses that actually do self-declare.
	got, err := ParseResponseEventWithFallback(respEv, testAppPrivKey, EncryptionNIP04)
	if err != nil {
		t.Fatalf("ParseResponseEventWithFallback() error = %v, want the response's own tag to override an incorrect fallback", err)
	}
	var balance GetBalanceResult
	if err := unmarshalParams(got.Result, &balance); err != nil {
		t.Fatalf("unmarshal result error = %v", err)
	}
	if balance.BalanceMloki != 1000 {
		t.Errorf("BalanceMloki = %d, want 1000", balance.BalanceMloki)
	}
}

func TestParseResponseEventWithFallback_WrongKindRejected(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodGetBalance, nil, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodGetBalance, GetBalanceResult{BalanceMloki: 1000}, reqEv, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	respEv.Kind = KindNWCRequest // wrong kind
	if err := respEv.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if _, err := ParseResponseEventWithFallback(respEv, testAppPrivKey, EncryptionNIP44V2); err == nil {
		t.Fatal("ParseResponseEventWithFallback() error = nil, want a kind-mismatch error")
	}
}

func TestParseResponseEventWithFallback_MissingETagRejected(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodGetBalance, nil, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodGetBalance, GetBalanceResult{BalanceMloki: 1000}, reqEv, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	respEv.Tags = removeTag(respEv.Tags, "e")
	if err := respEv.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if _, err := ParseResponseEventWithFallback(respEv, testAppPrivKey, EncryptionNIP44V2); err == nil {
		t.Fatal("ParseResponseEventWithFallback() error = nil, want a missing-e-tag error")
	}
}

func TestParseResponseEventWithFallback_SubPaymentIDStillParsed(t *testing.T) {
	walletPubkey := pubkeyOf(t, testWalletPrivKey)
	appPubkey := pubkeyOf(t, testAppPrivKey)

	reqEv, err := NewRequestEvent(testAppPrivKey, walletPubkey, MethodMultiPayInvoice, nil, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewRequestEvent() error = %v", err)
	}
	if err := reqEv.Sign(testAppPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	respEv, err := NewResponseEvent(testWalletPrivKey, appPubkey, MethodMultiPayInvoice, PayInvoiceResult{Preimage: "abcd"}, reqEv, EncryptionNIP44V2, []string{"d", "sub-1"})
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	respEv.Tags = removeTag(respEv.Tags, "encryption")
	if err := respEv.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	got, err := ParseResponseEventWithFallback(respEv, testAppPrivKey, EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("ParseResponseEventWithFallback() error = %v", err)
	}
	if got.SubPaymentID != "sub-1" {
		t.Errorf("SubPaymentID = %q, want %q", got.SubPaymentID, "sub-1")
	}
}
