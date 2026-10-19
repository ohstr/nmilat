package nip01

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Event ids computed by nostr-tools 2.23.8 (getEventHash) for kind 1,
// created_at 1, content "a b": tags must be escaped exactly like the
// content, so U+2028/U+2029 stay raw and control characters match too.
func TestHashID_TagsEscapeLikeNostrTools(t *testing.T) {
	const pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	var controls strings.Builder
	for c := 0; c < 0x20; c++ {
		controls.WriteByte(byte(c))
	}
	controls.WriteString("\"\\\x7f<>&")
	for name, tc := range map[string]struct {
		tags [][]string
		id   string
	}{
		"U+2028":       {[][]string{{"t", "x y"}}, "55b7d6cf4db2d74af8c15a8669062dec63972c52f9ec85c387de2a9a39035036"},
		"U+2029":       {[][]string{{"t", "x y"}}, "d2a50abf461fd8326dda103ddcce52531df8ab0789306df9c5b16e1a7b5636e0"},
		"control+json": {[][]string{{"c", controls.String()}}, "e59afa3755730f32c120072671907c93e9acad1cdc4574e41c2be842a13d5451"},
		"no tags":      {nil, "be86ccffbb0bcf1b297ebe190e73fb8901048a2380a33f9dc45a1a662600b5d6"},
		"one empty":    {[][]string{{}}, "fa2cc124b4f35ca422213df5452860335241d949bdd17ae4fca810deac4d6f48"},
	} {
		ev := NewUnsignedEvent(1, pubkey, "a b", tc.tags...)
		ev.CreatedAt = 1
		id, err := ev.HashID()
		if err != nil {
			t.Fatalf("%s: HashID: %v", name, err)
		}
		if got := hex.EncodeToString(id); got != tc.id {
			t.Errorf("%s: id = %s, want nostr-tools' %s", name, got, tc.id)
		}
	}
}
