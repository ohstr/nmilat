package nip44

// Session C, QA / test-coverage role — 2026-09-30.
//
// Before this file, the whole nip44 package had four tests: two symmetric round-trips
// through this same implementation, one asserting that both sides of an ECDH agree and
// that the result is 32 bytes long (a property of secp256k1, not of this code), and
// TestVectors, whose body is a comment saying official vectors would go here.
//
// The consequence, established by mutation against the whole repository
// (`GOWORK=off go test -count=1 ./...`, 841 test files, all green under EACH of these):
//
//	1. salt "nip44-v2" -> "nip44-v3"                                   invisible
//	2. getMessageKeys returning (hmacKey, chachaNonce, chachaKey)      invisible
//	3. HKDF-Extract replaced by plain SHA-256 of the shared secret     invisible
//	4. the `if !hmac.Equal(calculatedMac, mac)` check DELETED          invisible
//
// (4) is the one that matters. NIP-44 v2 is ChaCha20 + HMAC-SHA256 in encrypt-then-MAC
// form; ChaCha20 alone is an XOR stream, so the MAC is the only thing standing between a
// relay and a same-length edit of a plaintext it is merely forwarding. And on the private
// transport the reply's MAC is ALL there is: replies are signed by a throwaway ephemeral
// key on purpose, and nipcash/client/batch_send.go says so in as many words — "the
// signature does no authentication work anyway: only this hub can derive the reply key, so
// decrypting is what proves authorship". That sentence is true only while the MAC is
// checked.
//
// These tests are deliberately NOT written as round-trips, and deliberately do not call
// hkdf: a round-trip through one implementation moves both halves together under every
// mutation above, which is why none of them was caught. Each derivation is re-expressed
// from the primitive the spec names (HKDF-Extract is HMAC-SHA256(key=salt, msg=IKM);
// HKDF-Expand is the T(1)|T(2)|... chain) so that the test and the code can disagree.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"golang.org/x/crypto/chacha20"
)

// hkdfExtractIndep is RFC 5869 §2.2, written out: PRK = HMAC-Hash(salt, IKM).
func hkdfExtractIndep(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpandIndep is RFC 5869 §2.3, written out. No `hkdf` import, on purpose.
func hkdfExpandIndep(prk, info []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

func auditCQAFixedKeys(t *testing.T) (*btcec.PrivateKey, *btcec.PrivateKey) {
	t.Helper()
	a, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000f0")
	if err != nil {
		t.Fatal(err)
	}
	pa, _ := btcec.PrivKeyFromBytes(a)
	pb, _ := btcec.PrivKeyFromBytes(b)
	return pa, pb
}

// TestAuditCQA_NIP44_ConversationKeyIsHKDFExtractWithTheV2Salt pins the two degrees of
// freedom in GenerateConversationKey that the existing TestConversationKey cannot see,
// because "both sides agree" and "32 bytes long" hold for any function of the shared
// secret at all.
//
// Kills mutations 1 and 3.
func TestAuditCQA_NIP44_ConversationKeyIsHKDFExtractWithTheV2Salt(t *testing.T) {
	privA, privB := auditCQAFixedKeys(t)

	got, err := GenerateConversationKey(privA, privB.PubKey())
	if err != nil {
		t.Fatal(err)
	}

	shared := btcec.GenerateSharedSecret(privA, privB.PubKey())
	want := hkdfExtractIndep([]byte("nip44-v2"), shared)

	if !bytes.Equal(got, want) {
		t.Fatalf("conversation key = %s, want HKDF-Extract(SHA-256, salt=\"nip44-v2\", ikm=shared) = %s\n"+
			"This is a WIRE-COMPATIBILITY break: every other NIP-44 implementation, and every "+
			"already-published event, uses the v2 salt and the Extract step. Changing it makes "+
			"every message from this library undecryptable by anyone else, and vice versa.",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// The two specific wrong answers, named so the failure says which one was taken.
	if bare := sha256.Sum256(shared); bytes.Equal(got, bare[:]) {
		t.Fatal("conversation key is plain SHA-256(shared secret): the HKDF-Extract step and its salt were dropped")
	}
	if bytes.Equal(got, hkdfExtractIndep([]byte("nip44-v3"), shared)) {
		t.Fatal("conversation key uses a salt other than \"nip44-v2\"")
	}
}

// TestAuditCQA_NIP44_MessageKeysAreTheSpecSlicesInTheSpecOrder pins the 76-byte split.
//
// Kills mutation 2, which is invisible to every existing test for the reason that makes it
// dangerous: swapping chacha_key and hmac_key is perfectly self-consistent. Encrypt and
// Decrypt still agree with each other. They just no longer agree with anyone else.
func TestAuditCQA_NIP44_MessageKeysAreTheSpecSlicesInTheSpecOrder(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(i)
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}

	chachaKey, chachaNonce, hmacKey, err := getMessageKeys(ck, nonce)
	if err != nil {
		t.Fatal(err)
	}

	keys := hkdfExpandIndep(ck, nonce, 76)
	for _, c := range []struct {
		name string
		got  []byte
		want []byte
	}{
		{"chacha_key = keys[0:32]", chachaKey, keys[0:32]},
		{"chacha_nonce = keys[32:44]", chachaNonce, keys[32:44]},
		{"hmac_key = keys[44:76]", hmacKey, keys[44:76]},
	} {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s: got %s, want %s (independent HKDF-Expand)\n"+
				"A reordered or reoffset split keeps Encrypt/Decrypt agreeing with each other "+
				"and stops them agreeing with every other NIP-44 implementation.",
				c.name, hex.EncodeToString(c.got), hex.EncodeToString(c.want))
		}
	}
}

// auditCQASealIndependently builds a NIP-44 v2 payload without calling Encrypt, so that
// Decrypt is checked against an independent expression of the format rather than against
// its own inverse.
func auditCQASealIndependently(t *testing.T, ck []byte, nonce []byte, plaintext string) []byte {
	t.Helper()
	keys := hkdfExpandIndep(ck, nonce, 76)
	chachaKey, chachaNonce, hmacKey := keys[0:32], keys[32:44], keys[44:76]

	padded := pad(plaintext)
	ct := make([]byte, len(padded))
	c, err := chacha20.NewUnauthenticatedCipher(chachaKey, chachaNonce)
	if err != nil {
		t.Fatal(err)
	}
	c.XORKeyStream(ct, padded)

	h := hmac.New(sha256.New, hmacKey)
	h.Write(nonce) // aad first, then message (NIP-44 hmac_aad)
	h.Write(ct)
	mac := h.Sum(nil)

	out := []byte{Version}
	out = append(out, nonce...)
	out = append(out, ct...)
	out = append(out, mac...)
	return out
}

// TestAuditCQA_NIP44_DecryptAgreesWithAnIndependentlySealedPayload is the known-answer
// test the empty TestVectors stands in for. It is not a round-trip: nothing here calls
// Encrypt, hkdf, or getMessageKeys.
func TestAuditCQA_NIP44_DecryptAgreesWithAnIndependentlySealedPayload(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(0x11 * byte(i%16))
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	const plaintext = `{"v":1,"req_nonce":"aa","seq":1,"total":1,"results":[]}`

	payload := base64.StdEncoding.EncodeToString(auditCQASealIndependently(t, ck, nonce, plaintext))
	got, err := Decrypt(payload, ck)
	if err != nil {
		t.Fatalf("Decrypt refused an independently sealed NIP-44 v2 payload: %v\n"+
			"Either this library's key schedule or its framing has diverged from the spec; "+
			"a peer using any other implementation cannot talk to it.", err)
	}
	if got != plaintext {
		t.Fatalf("Decrypt = %q, want %q", got, plaintext)
	}
	t.Logf("independently sealed payload decrypts: %d bytes of ciphertext, plaintext %q", len(payload), got)
}

// TestAuditCQA_NIP44_ARelayBitFlipCannotAlterThePlaintext is the money test, and the one
// this round's attacker model is actually about.
//
// ChaCha20 is an XOR stream. A relay holds no key, but it does hold the bytes, and the
// plaintext of a private-transport reply is JSON of known shape. Flipping ONE bit at a
// known offset turns "total":1 into "total":3 — 0x31 XOR 0x02 = 0x33 — with the length
// unchanged, so the padding-length prefix still validates and unpad still succeeds. The
// HMAC is the only thing that refuses it.
//
// Verified by mutation: with the `hmac.Equal` check deleted from Decrypt, this test is the
// only one in the repository that fails, and it fails by returning the ALTERED JSON — the
// client would then report ErrIncompleteReply for a cash_redeem the hub had already
// executed, or believe a fabricated roster.
func TestAuditCQA_NIP44_ARelayBitFlipCannotAlterThePlaintext(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(0x5A)
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0xC3)
	}
	const plaintext = `{"v":1,"req_nonce":"aa","seq":1,"total":1,"results":[]}`
	const victim = `"total":1`

	sealed := auditCQASealIndependently(t, ck, nonce, plaintext)

	// Offset of the '1' in `"total":1` inside the ciphertext: 1 version byte + 32 nonce
	// bytes + 2 padding-length bytes + its index in the plaintext.
	idx := bytes.Index([]byte(plaintext), []byte(victim))
	if idx < 0 {
		t.Fatal("fixture: victim substring not present in plaintext")
	}
	flipAt := 1 + 32 + 2 + idx + len(victim) - 1

	tampered := append([]byte(nil), sealed...)
	tampered[flipAt] ^= 0x02 // '1' (0x31) -> '3' (0x33): same length, still valid JSON

	got, err := Decrypt(base64.StdEncoding.EncodeToString(tampered), ck)
	if err == nil {
		t.Fatalf("AUDITC-QA BUG PRESENT: a one-bit edit by a party holding NO key was ACCEPTED.\n"+
			"  original: %s\n  accepted: %s\n"+
			"On the private transport this is a relay rewriting a hub's answer: the reply is "+
			"signed by a throwaway ephemeral key, so the NIP-44 MAC is its only authentication.",
			plaintext, got)
	}
	if !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("a tampered ciphertext must be refused as ErrInvalidMAC, got %v.\n"+
			"Rejecting it for some other reason (bad padding, bad JSON) is luck, not a control: "+
			"this edit preserves the length precisely so that padding still validates.", err)
	}
	t.Logf("one-bit edit at offset %d refused: %v", flipAt, err)
}

// TestAuditCQA_NIP44_EveryRegionOfThePayloadIsAuthenticated walks the framing, because
// "the MAC is checked" is not the same claim as "the MAC covers this byte". The nonce in
// particular is an input to the key schedule AND the HMAC's aad; if it were excluded from
// the aad, a relay could re-point a ciphertext at a different key stream.
func TestAuditCQA_NIP44_EveryRegionOfThePayloadIsAuthenticated(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(7)
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i * 3)
	}
	const plaintext = "a private-transport reply long enough to span a padding boundary......."

	sealed := auditCQASealIndependently(t, ck, nonce, plaintext)
	if got, err := Decrypt(base64.StdEncoding.EncodeToString(sealed), ck); err != nil || got != plaintext {
		t.Fatalf("control: untampered payload must decrypt; got %q, %v", got, err)
	}

	for _, c := range []struct {
		name string
		at   int
	}{
		{"nonce (key-schedule input and HMAC aad)", 1},
		{"nonce, last byte", 32},
		{"ciphertext, first byte", 33},
		{"ciphertext, last byte", len(sealed) - 33},
		{"MAC, first byte", len(sealed) - 32},
		{"MAC, last byte", len(sealed) - 1},
	} {
		tampered := append([]byte(nil), sealed...)
		tampered[c.at] ^= 0x01
		if _, err := Decrypt(base64.StdEncoding.EncodeToString(tampered), ck); err == nil {
			t.Errorf("a flipped bit in %s was ACCEPTED: that region is unauthenticated", c.name)
		}
	}

	// Truncating the MAC must not be a way past it either.
	short := append([]byte(nil), sealed[:len(sealed)-1]...)
	if _, err := Decrypt(base64.StdEncoding.EncodeToString(short), ck); err == nil {
		t.Error("a payload with a truncated MAC was ACCEPTED")
	}
}
