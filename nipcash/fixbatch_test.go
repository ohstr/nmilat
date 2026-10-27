package nipcash

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A cancel request with several bad fields always gets the same reason.
func TestParseWithdrawCancel_DeterministicReason(t *testing.T) {
	in := json.RawMessage(`{"cancel":true,"request_id":"x","cash_secret":"y","zz":1,"aa":2}`)
	var first string
	for i := 0; i < 50; i++ {
		_, isCancel, err := ParseWithdrawCancel(in)
		if !isCancel || err == nil {
			t.Fatalf("isCancel %v err %v", isCancel, err)
		}
		if i == 0 {
			first = err.Error()
		} else if err.Error() != first {
			t.Fatalf("reason changed: %q then %q", first, err.Error())
		}
	}
	if !strings.Contains(first, "a field other than") {
		t.Errorf("reason %q, want the unknown field first", first)
	}
	_, _, err := ParseWithdrawCancel(json.RawMessage(`{"cancel":true,"request_id":"x","cash_secret":"y"}`))
	if err == nil || !strings.Contains(err.Error(), "request_id") {
		t.Errorf("reason %v, want request_id before cash_secret", err)
	}
}

// A base58check address gets ErrAddressNoWitness, not "mixed case".
func TestNormalizeAddress_Base58(t *testing.T) {
	if _, err := NormalizeAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"); !errors.Is(err, ErrAddressNoWitness) {
		t.Errorf("base58: %v, want ErrAddressNoWitness", err)
	}
	if _, err := NormalizeAddress("bc1Qxyz"); !errors.Is(err, ErrAddressMalformed) {
		t.Errorf("mixed case: %v, want ErrAddressMalformed", err)
	}
	if got, err := NormalizeAddress(" BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4 "); err != nil || got != "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" {
		t.Errorf("uppercase: %q %v", got, err)
	}
}

// Withdraw terms must list at least one script type.
func TestWithdrawTerms_EmptyScriptTypes(t *testing.T) {
	w := WithdrawTerms{FinalDepth: 6}
	if err := w.Validate(); err == nil {
		t.Error("empty script_types accepted")
	}
	w.ScriptTypes = [][2]int{{0, 20}}
	if err := w.Validate(); err != nil {
		t.Errorf("one script type: %v", err)
	}
}
