package transport

import (
	"encoding/json"
	"testing"
)

// NIP-CASH §Item Proofs: canonical params serialize strings as RFC 8785 does.
// The input spells every string escaped, and in a different key order, so only
// the canonicaliser decides the output. The expected hash was computed outside
// this package: printf of the expected bytes piped to sha256sum.
func TestCanonicalParams_RFC8785Strings(t *testing.T) {
	in := json.RawMessage(`{
		"z": "<>&",
		"q": "\"\\\b\t\n\f\r\u0001\u001f\u007f é",
		"n": 12345678901234567890,
		"arr": [1.50, true, null],
		"a": "x y z"
	}`)
	want := `{"a":"x` + " " + `y` + " " + `z","arr":[1.50,true,null],"n":12345678901234567890,` +
		`"q":"\"\\\b\t\n\f\r\u0001\u001f` + "\x7f" + ` é","z":"<>&"}`
	const wantHash = "069de3ad539b89d0ab1afbbce26f1e49fc4afc0f5ddb4bb75342cdd22b823f7b"

	got, err := canonicalJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical form:\n got %q\nwant %q", got, want)
	}
	hash, err := CanonicalParamsHash(in)
	if err != nil {
		t.Fatal(err)
	}
	if hash != wantHash {
		t.Fatalf("ph = %s, want %s", hash, wantHash)
	}
}

// Each character the spec names on its own, so a regression points at one.
func TestCanonicalParams_CharactersWrittenLiterally(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"less-than":   {`{"s":"<"}`, `{"s":"<"}`},
		"greater":     {`{"s":">"}`, `{"s":">"}`},
		"ampersand":   {`{"s":"&"}`, `{"s":"&"}`},
		"U+2028":      {`{"s":" "}`, "{\"s\":\" \"}"},
		"U+2029":      {`{"s":" "}`, "{\"s\":\" \"}"},
		"non-ASCII":   {`{"s":"é😀"}`, "{\"s\":\"é\U0001F600\"}"},
		"slash":       {`{"s":"\/"}`, `{"s":"/"}`},
		"key escaped": {`{"<k":1}`, `{"<k":1}`},
		"backspace":   {`{"s":"\u0008"}`, `{"s":"\b"}`},
		"formfeed":    {`{"s":"\u000c"}`, `{"s":"\f"}`},
		"other ctrl":  {`{"s":"\u000b"}`, `{"s":"\u000b"}`},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := canonicalJSON(json.RawMessage(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// NIP-CASH §Item Proofs sorts keys as RFC 8785 does, by UTF-16 code units. Byte order agrees for every key up to
// U+FFFF; above it a surrogate pair (0xD800…) sorts before U+E000…U+FFFF, where UTF-8 bytes put it after.
func TestCanonicalParams_KeysSortByUTF16CodeUnits(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"above U+FFFF before U+FFFF":   {"{\"￿\":1,\"\U00010000\":2}", "{\"\U00010000\":2,\"￿\":1}"},
		"above U+FFFF before U+E000":   {"{\"\":1,\"\U0001F600\":2}", "{\"\U0001F600\":2,\"\":1}"},
		"U+D7FF before above U+FFFF":   {"{\"\U00010000\":1,\"퟿\":2}", "{\"퟿\":2,\"\U00010000\":1}"},
		"two pairs by their low units": {"{\"\U0001F601\":1,\"\U0001F600\":2}", "{\"\U0001F600\":2,\"\U0001F601\":1}"},
		"a prefix sorts first":         {"{\"ab\":1,\"a\":2}", `{"a":2,"ab":1}`},
		"ASCII as before":              {`{"z":1,"Z":2,"a":3,"":4,"_":5}`, `{"":4,"Z":2,"_":5,"a":3,"z":1}`},
		"two-byte as before":           {"{\"é\":1,\"z\":2}", "{\"z\":2,\"é\":1}"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := canonicalJSON(json.RawMessage(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	// Params whose keys are ASCII, as every NIP-CASH method's are, hash as they always did.
	const asciiHash = "069de3ad539b89d0ab1afbbce26f1e49fc4afc0f5ddb4bb75342cdd22b823f7b"
	if h, _ := CanonicalParamsHash(json.RawMessage("{\"z\":\"<>&\",\"q\":\"\\\"\\\\\\b\\t\\n\\f\\r\\u0001\\u001f\\u007f é\",\"n\":12345678901234567890,\"arr\":[1.50,true,null],\"a\":\"x y z\"}")); h != asciiHash {
		t.Fatalf("ASCII-keyed params: ph = %s, want %s", h, asciiHash)
	}
}
