package nipLS

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipOA"
	"github.com/ohstr/nmilat/utils"
)

const attestSubPriv = "5c2a8d1f3b6e47a90c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7"

// startAttestServer runs a Server offering nipoa_attest over a pipe and
// returns a client of it.
func startAttestServer(t *testing.T, authorize AttestFunc) (*Client, *LocalKey) {
	t.Helper()
	key, err := NewLocalKey("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := nipOA.NewKeySigner(key.PrivKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{
		Key:     key,
		Policy:  AllowAll,
		Methods: map[string]Handler{nipOA.MethodSignAttestation: AttestationMethod(signer, authorize)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b := net.Pipe()
	go srv.ServeConn(ctx, a)
	c, err := NewClient(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, key
}

func TestAttestationMethod_ThroughClient(t *testing.T) {
	sub, _ := utils.GetPublicKey(attestSubPriv)
	var seen nipOA.Conditions
	c, key := startAttestServer(t, func(_ context.Context, _ *Request, s string, cond nipOA.Conditions) error {
		if s != sub {
			return Deny("not this key")
		}
		if len(cond.CreatedAtLT) == 0 {
			return Deny("an attestation must expire")
		}
		seen = cond
		return nil
	})
	rs, err := nipOA.NewRemoteSigner(c, c.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tag, err := nipOA.Sign(ctx, rs, sub, "created_at<4102444800")
	if err != nil {
		t.Fatal(err)
	}
	if tag[1] != key.PubKey() || seen.Raw != "created_at<4102444800" {
		t.Fatalf("tag %v, seen %+v", tag, seen)
	}
	if _, err := nipOA.ParseAuthTag([][]string{tag}, sub); err != nil {
		t.Fatal(err)
	}

	// The rule's refusal comes back as a denial.
	if _, err := nipOA.Sign(ctx, rs, sub, "kind=1"); !errors.Is(err, ErrDenied) {
		t.Fatalf("no expiry: %v, want ErrDenied", err)
	}
	// Malformed requests are refused before the rule runs.
	if _, err := c.Call(ctx, nipOA.MethodSignAttestation, "abc", ""); err == nil {
		t.Fatal("bad subordinate signed")
	}
	if _, err := c.Call(ctx, nipOA.MethodSignAttestation, sub, "kind=01"); err == nil {
		t.Fatal("bad conditions signed")
	}
	if _, err := c.Call(ctx, nipOA.MethodSignAttestation, sub); err == nil {
		t.Fatal("one param signed")
	}
}

// A gate that refuses one key by its lowercase hex must still refuse the
// uppercase form of that key: AttestationMethod canonicalizes the
// subordinate before authorize sees it, so case cannot evade the denial.
func TestAttestationMethod_UppercaseDoesNotEvadeGate(t *testing.T) {
	sub, _ := utils.GetPublicKey(attestSubPriv)
	c, _ := startAttestServer(t, func(_ context.Context, _ *Request, s string, _ nipOA.Conditions) error {
		if s == sub {
			return Deny("this key is banned")
		}
		return nil
	})
	ctx := context.Background()
	upper := strings.ToUpper(sub)
	if upper == sub {
		t.Fatal("test key has no case variant")
	}
	if _, err := c.Call(ctx, nipOA.MethodSignAttestation, upper, "created_at<4102444800"); !errors.Is(err, ErrDenied) {
		t.Fatalf("uppercase banned key: got %v, want ErrDenied", err)
	}
}

func TestAttestationMethod_NilRuleDenies(t *testing.T) {
	sub, _ := utils.GetPublicKey(attestSubPriv)
	c, _ := startAttestServer(t, nil)
	rs, err := nipOA.NewRemoteSigner(c, c.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nipOA.Sign(context.Background(), rs, sub, "created_at<4102444800"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v, want ErrDenied", err)
	}
}
