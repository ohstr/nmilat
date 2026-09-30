package transport

// Known-answer vectors for DeriveReplyKey, the derivation that AUTHENTICATES a hub's
// reply on the private transport.
//
// Why these exist, and why they are shaped the way they are. The reply key is the whole
// of the hub's authentication: a client accepts a response envelope because it decrypts
// under a key only the hub could have derived. Until this audit round the derivation was
// undefined in NIP-CASH — it existed only as this Go function, so "correct" meant
// "whatever the code does", and a change to the label, the input order, or the HKDF
// stage would have kept every existing test green while silently splitting this
// implementation from every other one. The QA role's NIP-44 finding earlier in this
// round is the same lesson at full severity: the MAC check could be deleted with all 841
// test files still passing, because the tests all went through the same code they were
// checking.
//
// So two rules here, both deliberate:
//
//  1. The expected outputs are FROZEN CONSTANTS, computed outside this repo. If the
//     derivation changes, these fail. That is the point — they are a compatibility
//     commitment, not a description of the current code.
//
//  2. The in-test derivation re-expresses HKDF-Expand from crypto/hmac per RFC 5869
//     §2.3, and deliberately does NOT import golang.org/x/crypto/hkdf the way
//     response.go does. Calling the same library the implementation calls would make
//     the two agree by construction, which is exactly the failure NIP-44 had. Written
//     this way, the test and the code CAN disagree, and one of the three ways to be
//     wrong (label, concatenation order, Expand-vs-Extract) shows up as a mismatch
//     rather than as silent divergence from other implementations.
//
// The label is spelled out as a literal below rather than read from replyKeyInfo, for
// the same reason: renaming the constant must break these, not follow them.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// katReplyKeyLabel is NIP-CASH's reply-key label, frozen as a literal. The spec text is
// "HKDF-Expand(SHA-256, prk = conversation_key, info = \"nipcash-reply-v1\" ||
// reply_to_hex, L = 32)".
const katReplyKeyLabel = "nipcash-reply-v1"

// katHKDFExpand is RFC 5869 §2.3 written out: T(1) = HMAC-SHA256(PRK, info || 0x01),
// and the first L bytes of T(1) || T(2) || ... are the output. For L = 32 with SHA-256
// exactly one block is needed, so the loop runs once — kept as a loop anyway so the
// construction is recognisable as HKDF rather than as a bare HMAC that happens to
// match at this one length.
func katHKDFExpand(prk, info []byte, length int) []byte {
	var out, t []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

func TestAuditC_DeriveReplyKey_KnownAnswerVectors(t *testing.T) {
	vectors := []struct {
		name            string
		conversationKey string
		replyTo         string
		wantReplyKey    string
	}{
		{
			name:            "ck_counting_bytes__reply_all_zero",
			conversationKey: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			replyTo:         "0000000000000000000000000000000000000000000000000000000000000000",
			wantReplyKey:    "aede656a94d03cfa382dcc742ec44cec9248ed2be2b71bf0fa92ed48298705da",
		},
		{
			name:            "ck_all_ff__reply_deadbeef",
			conversationKey: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			replyTo:         "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			wantReplyKey:    "a0953747794eb0fc06b187bf8a1449f60716b788b850b7adfe82e11753d03a7b",
		},
		{
			name:            "ck_sha256_of_label__reply_mixed",
			conversationKey: "0e11ac12d17df2ba09c49b400df9aa1cba33288b42a099068bbcf05f6c910741",
			replyTo:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantReplyKey:    "d80410259b62e3676c3a95a9b1ccdd639c8a8c6cbc48ec1d7bc375774f2e16b1",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			var ck [32]byte
			raw, err := hex.DecodeString(v.conversationKey)
			if err != nil || len(raw) != 32 {
				t.Fatalf("bad vector: conversation key %q", v.conversationKey)
			}
			copy(ck[:], raw)

			got, err := DeriveReplyKey(ck, v.replyTo)
			if err != nil {
				t.Fatalf("DeriveReplyKey() error = %v", err)
			}
			if hex.EncodeToString(got[:]) != v.wantReplyKey {
				t.Errorf("DeriveReplyKey() = %s, want the frozen vector %s\n"+
					"This is a WIRE-COMPATIBILITY break, not a failing assertion: a client "+
					"deriving the old value can no longer read this hub's replies, and vice "+
					"versa. If the derivation changed on purpose, NIP-CASH's own text and "+
					"these vectors change together, with a version bump on the label.",
					hex.EncodeToString(got[:]), v.wantReplyKey)
			}

			// The second, independent check: the same answer from HMAC directly, never
			// touching x/crypto/hkdf. If this disagrees with the frozen constant, the
			// vector itself is wrong; if it disagrees with DeriveReplyKey, the code is.
			independent := katHKDFExpand(ck[:], []byte(katReplyKeyLabel+v.replyTo), 32)
			if hex.EncodeToString(independent) != v.wantReplyKey {
				t.Errorf("the vector disagrees with RFC 5869 written out from HMAC: got %s, frozen %s",
					hex.EncodeToString(independent), v.wantReplyKey)
			}
			if !hmac.Equal(independent, got[:]) {
				t.Errorf("DeriveReplyKey() and RFC 5869 from HMAC disagree: %s vs %s",
					hex.EncodeToString(got[:]), hex.EncodeToString(independent))
			}
		})
	}
}

// TestAuditC_DeriveReplyKey_LabelIsLoadBearing pins the three ways the derivation can
// be changed while still being "an HKDF of the same two inputs". Each produces a
// different key, so each is a silent wire break, and none is caught by a test that
// derives its expectation the same way the code does.
func TestAuditC_DeriveReplyKey_LabelIsLoadBearing(t *testing.T) {
	var ck [32]byte
	for i := range ck {
		ck[i] = byte(i)
	}
	const replyTo = "00000000000000000000000000000000000000000000000000000000000000ff"

	genuine, err := DeriveReplyKey(ck, replyTo)
	if err != nil {
		t.Fatalf("DeriveReplyKey() error = %v", err)
	}

	wrong := []struct {
		name string
		info []byte
	}{
		{"a_different_label_version", []byte("nipcash-reply-v2" + replyTo)},
		{"no_label_at_all", []byte(replyTo)},
		{"label_only_no_reply_to", []byte(katReplyKeyLabel)},
		{"reply_to_before_the_label", []byte(replyTo + katReplyKeyLabel)},
		{"label_separated_by_a_colon", []byte(katReplyKeyLabel + ":" + replyTo)},
		{"reply_to_as_raw_bytes_not_hex", func() []byte {
			raw, _ := hex.DecodeString(replyTo)
			return append([]byte(katReplyKeyLabel), raw...)
		}()},
		{"upper_case_reply_to", []byte(katReplyKeyLabel + strings.ToUpper(replyTo))},
	}
	for _, w := range wrong {
		t.Run(w.name, func(t *testing.T) {
			if hmac.Equal(katHKDFExpand(ck[:], w.info, 32), genuine[:]) {
				t.Errorf("this variant derives the SAME key as the real derivation, so the " +
					"derivation does not actually bind what it is meant to bind")
			}
		})
	}

	// And the input that must not be an HKDF question at all: reply_to is what makes
	// the key single-use, so a malformed one has to be refused rather than hashed.
	// Otherwise a hub could pick a reply_to that reuses a key across envelopes.
	for _, bad := range []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"too_short", strings.Repeat("ab", 31)},
		{"too_long", strings.Repeat("ab", 33)},
		{"uppercase_hex", strings.ToUpper(replyTo)},
		{"mixed_case_hex", "AB" + replyTo[2:]},
		{"non_hex_characters", strings.Repeat("zz", 32)},
		{"right_length_wrong_alphabet", strings.Repeat("g", 64)},
	} {
		t.Run("refused_"+bad.name, func(t *testing.T) {
			if _, err := DeriveReplyKey(ck, bad.value); err == nil {
				t.Errorf("DeriveReplyKey(%q) was accepted; a reply_to that is not exactly 64 "+
					"lowercase hex characters must be refused, or two different spellings of "+
					"one event id derive two different keys", bad.value)
			}
		})
	}

	// Single-use in the property that matters: one bit of reply_to changes the key.
	neighbour := replyTo[:63] + "e"
	other, err := DeriveReplyKey(ck, neighbour)
	if err != nil {
		t.Fatalf("DeriveReplyKey() error = %v", err)
	}
	if hmac.Equal(genuine[:], other[:]) {
		t.Error("two reply_to values differing in one character derive the same key")
	}
}
