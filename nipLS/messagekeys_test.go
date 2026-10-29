package nipLS

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip46"
)

func TestMessageKeysOpenOnePayload(t *testing.T) {
	var seen []*Request
	policy := PolicyFunc(func(_ context.Context, r *Request) error {
		seen = append(seen, r)
		if r.Method == nip46.MethodNIP44MessageKeys && r.Counterpart != mustPeer(t).PubKey() {
			return Deny("counterpart not allowed")
		}
		return nil
	})
	c := dial(t, start(t, ServerConfig{Policy: policy}))
	ctx := context.Background()
	peer := mustPeer(t)

	payload, err := peer.Encrypt(ctx, nip46.EncryptionNIP44V2, c.PubKey(), "one message")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := c.MessageKeys(ctx, peer.PubKey(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := nip44.OpenWithKeys(keys, payload); err != nil || plain != "one message" {
		t.Fatalf("OpenWithKeys: %q %v", plain, err)
	}
	last := seen[len(seen)-1]
	if last.Method != nip46.MethodNIP44MessageKeys || last.Ciphertext != payload || last.Counterpart != peer.PubKey() {
		t.Fatalf("policy saw %+v", last)
	}

	// The keys don't open the next message of the same conversation.
	other, _ := peer.Encrypt(ctx, nip46.EncryptionNIP44V2, c.PubKey(), "another")
	if _, err := nip44.OpenWithKeys(keys, other); !errors.Is(err, nip44.ErrInvalidMAC) {
		t.Fatalf("keys opened another payload: %v", err)
	}

	// Another counterpart is refused by the policy; a tampered payload by the MAC.
	third, _ := NewLocalKey("0000000000000000000000000000000000000000000000000000000000000007")
	if _, err := c.MessageKeys(ctx, third.PubKey(), payload); !errors.Is(err, ErrDenied) {
		t.Fatalf("other counterpart: %v", err)
	}
	if _, err := c.MessageKeys(ctx, peer.PubKey(), tamper(payload)); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

// A key that can't derive message keys answers "unsupported method".
func TestMessageKeysUnsupportedKey(t *testing.T) {
	lk, _ := NewLocalKey(testPriv)
	c := dial(t, start(t, ServerConfig{Key: signOnly{lk}}))
	_, err := c.MessageKeys(context.Background(), mustPeer(t).PubKey(), "AgAA")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

type resultPolicy struct {
	allowed  func(result string) bool
	consults int
}

func (p *resultPolicy) Authorize(context.Context, *Request) error { return nil }

func (p *resultPolicy) AuthorizeResult(_ context.Context, _ *Request, result string) error {
	p.consults++
	if !p.allowed(result) {
		return Deny("result not allowed")
	}
	return nil
}

func TestResultPolicy(t *testing.T) {
	p := &resultPolicy{allowed: func(r string) bool { return r == "ok" }}
	h := start(t, ServerConfig{Policy: p})
	c := dial(t, h)
	ctx := context.Background()
	peer := mustPeer(t)

	good, _ := peer.Encrypt(ctx, nip46.EncryptionNIP44V2, c.PubKey(), "ok")
	if pt, err := c.Decrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), good); err != nil || pt != "ok" {
		t.Fatalf("allowed result: %q %v", pt, err)
	}
	bad, _ := peer.Encrypt(ctx, nip46.EncryptionNIP44V2, c.PubKey(), "secret")
	pt, err := c.Decrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), bad)
	if !errors.Is(err, ErrDenied) || pt != "" {
		t.Fatalf("refused result leaked: %q %v", pt, err)
	}
	if p.consults != 2 {
		t.Fatalf("consulted %d times", p.consults)
	}
	// The refusal is logged as a denial.
	d := h.decisions()
	if d[len(d)-1].Allowed() {
		t.Fatal("refused result logged as allowed")
	}
	// A failed decrypt never reaches the hook.
	if _, err := c.Decrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), tamper(good)); err == nil {
		t.Fatal("tampered payload decrypted")
	}
	if p.consults != 2 {
		t.Fatal("hook saw a failed decrypt")
	}
}

func mustPeer(t *testing.T) *LocalKey {
	t.Helper()
	k, err := NewLocalKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// tamper flips one base64 character in the ciphertext region.
func tamper(payload string) string {
	b := []byte(payload)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// signOnly is a Key without nip46.MessageKeyer.
type signOnly struct{ k *LocalKey }

func (s signOnly) PubKey() string                                  { return s.k.PubKey() }
func (s signOnly) Sign(ctx context.Context, ev *nip01.Event) error { return s.k.Sign(ctx, ev) }
func (s signOnly) Encrypt(ctx context.Context, scheme, peer, pt string) (string, error) {
	return s.k.Encrypt(ctx, scheme, peer, pt)
}
func (s signOnly) Decrypt(ctx context.Context, scheme, peer, ct string) (string, error) {
	return s.k.Decrypt(ctx, scheme, peer, ct)
}

// nip44_message_keys is both an encrypt and a decrypt: its keys seal any
// plaintext under the payload's nonce. A policy allowing decryption but not
// encryption refuses it and still allows nip44_decrypt; one allowing both
// allows it.
func TestMessageKeysGovernedAsEncryptAndDecrypt(t *testing.T) {
	ctx := context.Background()
	peer := mustPeer(t)
	decryptOnly := PolicyFunc(func(_ context.Context, r *Request) error {
		if r.Encrypts() {
			return Deny("no encryption")
		}
		return nil
	})
	c := dial(t, start(t, ServerConfig{Policy: decryptOnly}))
	payload, err := peer.Encrypt(ctx, nip46.EncryptionNIP44V2, c.PubKey(), "one message")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.MessageKeys(ctx, peer.PubKey(), payload); !errors.Is(err, ErrDenied) {
		t.Fatalf("message keys under a decrypt-only policy: %v", err)
	}
	if plain, err := c.Decrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), payload); err != nil || plain != "one message" {
		t.Fatalf("decrypt under a decrypt-only policy: %q %v", plain, err)
	}
	if _, err := c.Encrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), "x"); !errors.Is(err, ErrDenied) {
		t.Fatalf("encrypt under a decrypt-only policy: %v", err)
	}

	encryptOnly := PolicyFunc(func(_ context.Context, r *Request) error {
		if r.Decrypts() {
			return Deny("no decryption")
		}
		return nil
	})
	c = dial(t, start(t, ServerConfig{Policy: encryptOnly}))
	if _, err := c.MessageKeys(ctx, peer.PubKey(), payload); !errors.Is(err, ErrDenied) {
		t.Fatalf("message keys under an encrypt-only policy: %v", err)
	}

	both := PolicyFunc(func(_ context.Context, r *Request) error {
		if r.Encrypts() && r.Decrypts() && r.Counterpart == peer.PubKey() {
			return nil
		}
		return Deny("not both")
	})
	c = dial(t, start(t, ServerConfig{Policy: both}))
	if _, err := c.MessageKeys(ctx, peer.PubKey(), payload); err != nil {
		t.Fatalf("message keys allowed for both: %v", err)
	}
}

func TestRequestEncryptsDecrypts(t *testing.T) {
	for _, c := range []struct {
		method       string
		enc, decrypt bool
	}{
		{nip46.MethodNIP04Encrypt, true, false},
		{nip46.MethodNIP44Encrypt, true, false},
		{nip46.MethodNIP04Decrypt, false, true},
		{nip46.MethodNIP44Decrypt, false, true},
		{nip46.MethodNIP44MessageKeys, true, true},
		{nip46.MethodSignEvent, false, false},
		{nip46.MethodPing, false, false},
	} {
		r := &Request{Method: c.method}
		if r.Encrypts() != c.enc || r.Decrypts() != c.decrypt {
			t.Errorf("%s: encrypts %v decrypts %v", c.method, r.Encrypts(), r.Decrypts())
		}
	}
}
