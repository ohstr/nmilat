package nip44

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/utils"
)

// testdata/nip44.vectors.json is the official set from
// github.com/paulmillr/nip44 (sha256 269ed0f6...3ce25040).
type vectors struct {
	V2 struct {
		Valid struct {
			GetConversationKey []struct {
				Sec1, Pub2      string
				ConversationKey string `json:"conversation_key"`
			} `json:"get_conversation_key"`
			GetMessageKeys struct {
				ConversationKey string `json:"conversation_key"`
				Keys            []struct {
					Nonce       string
					ChaChaKey   string `json:"chacha_key"`
					ChaChaNonce string `json:"chacha_nonce"`
					HMACKey     string `json:"hmac_key"`
				}
			} `json:"get_message_keys"`
			CalcPaddedLen  [][2]int `json:"calc_padded_len"`
			EncryptDecrypt []struct {
				Sec1, Sec2      string
				ConversationKey string `json:"conversation_key"`
				Nonce           string
				Plaintext       string
				Payload         string
			} `json:"encrypt_decrypt"`
			EncryptDecryptLongMsg []struct {
				ConversationKey string `json:"conversation_key"`
				Nonce           string
				Pattern         string
				Repeat          int
				PlaintextSHA256 string `json:"plaintext_sha256"`
				PayloadSHA256   string `json:"payload_sha256"`
			} `json:"encrypt_decrypt_long_msg"`
		}
		Invalid struct {
			EncryptMsgLengths  []int `json:"encrypt_msg_lengths"`
			GetConversationKey []struct {
				Sec1, Pub2, Note string
			} `json:"get_conversation_key"`
			Decrypt []struct {
				ConversationKey string `json:"conversation_key"`
				Nonce           string
				Plaintext       string
				Payload         string
				Note            string
			}
		}
	}
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/nip44.vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectorsConversationKey(t *testing.T) {
	for _, tc := range loadVectors(t).V2.Valid.GetConversationKey {
		got, err := ConversationKeyHex(tc.Sec1, tc.Pub2)
		if err != nil {
			t.Fatalf("sec1 %s: %v", tc.Sec1, err)
		}
		if hex.EncodeToString(got) != tc.ConversationKey {
			t.Fatalf("sec1 %s: got %x, want %s", tc.Sec1, got, tc.ConversationKey)
		}
	}
}

func TestVectorsInvalidConversationKey(t *testing.T) {
	for _, tc := range loadVectors(t).V2.Invalid.GetConversationKey {
		if _, err := ConversationKeyHex(tc.Sec1, tc.Pub2); err == nil {
			t.Errorf("%s: accepted", tc.Note)
		}
	}
}

func TestVectorsMessageKeys(t *testing.T) {
	v := loadVectors(t).V2.Valid.GetMessageKeys
	ck := unhex(t, v.ConversationKey)
	for _, tc := range v.Keys {
		nonce := unhex(t, tc.Nonce)
		k, n, h, err := getMessageKeys(ck, nonce)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(k) != tc.ChaChaKey || hex.EncodeToString(n) != tc.ChaChaNonce || hex.EncodeToString(h) != tc.HMACKey {
			t.Fatalf("nonce %s: keys differ", tc.Nonce)
		}

		// MessageKeys over a payload with this nonce returns the same keys.
		payload, err := encryptWithNonce("x", ck, nonce)
		if err != nil {
			t.Fatal(err)
		}
		got, err := MessageKeys(ck, payload)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got.ChaChaKey) != tc.ChaChaKey || hex.EncodeToString(got.ChaChaNonce) != tc.ChaChaNonce || hex.EncodeToString(got.HMACKey) != tc.HMACKey {
			t.Fatalf("nonce %s: MessageKeys differ", tc.Nonce)
		}
	}
}

func TestVectorsPaddedLen(t *testing.T) {
	for _, tc := range loadVectors(t).V2.Valid.CalcPaddedLen {
		if got := calcPaddedLen(tc[0]); got != tc[1] {
			t.Fatalf("calcPaddedLen(%d) = %d, want %d", tc[0], got, tc[1])
		}
	}
}

func TestVectorsEncryptDecrypt(t *testing.T) {
	for _, tc := range loadVectors(t).V2.Valid.EncryptDecrypt {
		ck := unhex(t, tc.ConversationKey)
		got, err := ConversationKeyHex(tc.Sec1, mustPub(t, tc.Sec2))
		if err != nil || !bytes.Equal(got, ck) {
			t.Fatalf("conversation key for sec1 %s: %x %v", tc.Sec1, got, err)
		}
		payload, err := encryptWithNonce(tc.Plaintext, ck, unhex(t, tc.Nonce))
		if err != nil {
			t.Fatal(err)
		}
		if payload != tc.Payload {
			t.Fatalf("payload for %q differs", tc.Plaintext)
		}
		plain, err := Decrypt(tc.Payload, ck)
		if err != nil || plain != tc.Plaintext {
			t.Fatalf("Decrypt: %q %v", plain, err)
		}
		keys, err := MessageKeys(ck, tc.Payload)
		if err != nil {
			t.Fatal(err)
		}
		plain, err = OpenWithKeys(keys, tc.Payload)
		if err != nil || plain != tc.Plaintext {
			t.Fatalf("OpenWithKeys: %q %v", plain, err)
		}
	}
}

func TestVectorsLongMessages(t *testing.T) {
	for _, tc := range loadVectors(t).V2.Valid.EncryptDecryptLongMsg {
		ck := unhex(t, tc.ConversationKey)
		plaintext := strings.Repeat(tc.Pattern, tc.Repeat)
		if sum := sha256.Sum256([]byte(plaintext)); hex.EncodeToString(sum[:]) != tc.PlaintextSHA256 {
			t.Fatal("plaintext hash differs")
		}
		payload, err := encryptWithNonce(plaintext, ck, unhex(t, tc.Nonce))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256([]byte(payload)); hex.EncodeToString(sum[:]) != tc.PayloadSHA256 {
			t.Fatal("payload hash differs")
		}
		keys, err := MessageKeys(ck, payload)
		if err != nil {
			t.Fatal(err)
		}
		if plain, err := OpenWithKeys(keys, payload); err != nil || plain != plaintext {
			t.Fatalf("OpenWithKeys: %v", err)
		}
	}
}

func TestVectorsInvalidDecrypt(t *testing.T) {
	for _, tc := range loadVectors(t).V2.Invalid.Decrypt {
		ck := unhex(t, tc.ConversationKey)
		if _, err := Decrypt(tc.Payload, ck); err == nil {
			t.Errorf("Decrypt accepted: %s", tc.Note)
		}
		if _, err := MessageKeys(ck, tc.Payload); err == nil && !strings.Contains(tc.Note, "padding") {
			t.Errorf("MessageKeys accepted: %s", tc.Note)
		}
	}
}

func TestVectorsInvalidLengths(t *testing.T) {
	ck := make([]byte, 32)
	for _, n := range loadVectors(t).V2.Invalid.EncryptMsgLengths {
		// These vectors predate the extended length prefix this package
		// implements, which accepts lengths of 65536 and up.
		if n >= extendedPrefixThreshold {
			continue
		}
		if _, err := Encrypt(strings.Repeat("a", n), ck); err == nil {
			t.Errorf("length %d accepted", n)
		}
	}
}

func mustPub(t *testing.T, sec string) string {
	t.Helper()
	pub, err := utils.GetPublicKey(sec)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// One payload's keys must open only that payload, and every changed byte
// must be refused.
func TestMessageKeysRefusals(t *testing.T) {
	v := loadVectors(t).V2.Valid.EncryptDecrypt[0]
	ck := unhex(t, v.ConversationKey)
	keys, err := MessageKeys(ck, v.Payload)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("another payload of the same conversation", func(t *testing.T) {
		other, err := Encrypt(v.Plaintext, ck)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenWithKeys(keys, other); !errors.Is(err, ErrInvalidMAC) {
			t.Fatalf("got %v, want ErrInvalidMAC", err)
		}
	})

	t.Run("another conversation key", func(t *testing.T) {
		wrong := append([]byte(nil), ck...)
		wrong[0] ^= 1
		if _, err := MessageKeys(wrong, v.Payload); !errors.Is(err, ErrInvalidMAC) {
			t.Fatalf("got %v, want ErrInvalidMAC", err)
		}
	})

	t.Run("every changed byte", func(t *testing.T) {
		raw, _ := base64.StdEncoding.DecodeString(v.Payload)
		for i := range raw {
			b := append([]byte(nil), raw...)
			b[i] ^= 0x01
			p := base64.StdEncoding.EncodeToString(b)
			if _, err := OpenWithKeys(keys, p); err == nil {
				t.Fatalf("byte %d changed, still opens", i)
			}
			if _, err := MessageKeys(ck, p); err == nil {
				t.Fatalf("byte %d changed, MessageKeys accepted", i)
			}
		}
	})

	t.Run("changed keys", func(t *testing.T) {
		for name, mutate := range map[string]func(*Keys){
			"hmac key":     func(k *Keys) { k.HMACKey = flip(k.HMACKey) },
			"short hmac":   func(k *Keys) { k.HMACKey = k.HMACKey[:31] },
			"short chacha": func(k *Keys) { k.ChaChaKey = k.ChaChaKey[:31] },
			"long nonce":   func(k *Keys) { k.ChaChaNonce = append(append([]byte(nil), k.ChaChaNonce...), 0) },
		} {
			k := keys
			mutate(&k)
			if _, err := OpenWithKeys(k, v.Payload); err == nil {
				t.Errorf("%s: still opens", name)
			}
		}
		// A wrong ChaCha key passes the MAC but cannot give the plaintext.
		k := keys
		k.ChaChaKey = flip(k.ChaChaKey)
		if plain, err := OpenWithKeys(k, v.Payload); err == nil && plain == v.Plaintext {
			t.Fatal("wrong chacha key gave the plaintext")
		}
	})

	t.Run("bad version", func(t *testing.T) {
		raw, _ := base64.StdEncoding.DecodeString(v.Payload)
		raw[0] = 1
		p := base64.StdEncoding.EncodeToString(raw)
		if _, err := MessageKeys(ck, p); !errors.Is(err, ErrInvalidVersion) {
			t.Fatalf("got %v, want ErrInvalidVersion", err)
		}
		if _, err := OpenWithKeys(keys, p); !errors.Is(err, ErrInvalidVersion) {
			t.Fatalf("got %v, want ErrInvalidVersion", err)
		}
	})

	t.Run("json round trip", func(t *testing.T) {
		b, err := json.Marshal(keys)
		if err != nil {
			t.Fatal(err)
		}
		var back Keys
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if plain, err := OpenWithKeys(back, v.Payload); err != nil || plain != v.Plaintext {
			t.Fatalf("after JSON: %q %v", plain, err)
		}
		for _, bad := range []string{
			`{"chacha_key":"00","chacha_nonce":"00","hmac_key":"00"}`,
			`{"chacha_key":"zz"}`,
		} {
			if err := json.Unmarshal([]byte(bad), &back); err == nil {
				t.Errorf("accepted %s", bad)
			}
		}
	})

	t.Run("too short", func(t *testing.T) {
		p := base64.StdEncoding.EncodeToString(make([]byte, 96))
		if _, err := MessageKeys(ck, p); !errors.Is(err, ErrMessageTooShort) {
			t.Fatalf("got %v, want ErrMessageTooShort", err)
		}
	})
}

func flip(b []byte) []byte {
	c := append([]byte(nil), b...)
	c[0] ^= 1
	return c
}
