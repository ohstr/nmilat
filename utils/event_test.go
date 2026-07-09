package utils

import (
	"testing"
)

func TestATag(t *testing.T) {

	a := "30000:0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c:test"
	kind, pubKey, dValue, err := ParseATag(a)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("kind=%d pubkey=%s dValue=%s", kind, pubKey, dValue)
}
