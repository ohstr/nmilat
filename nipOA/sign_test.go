package nipOA

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/utils"
)

// Throwaway keys, never used anywhere else.
const (
	attesterPriv    = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	subordinatePriv = "5c2a8d1f3b6e47a90c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7"
)

func mustPub(t *testing.T, priv string) string {
	t.Helper()
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustSigner(t *testing.T) *KeySigner {
	t.Helper()
	s, err := NewKeySigner(attesterPriv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSign_RoundTripsWithVerify(t *testing.T) {
	ctx := context.Background()
	s := mustSigner(t)
	sub := mustPub(t, subordinatePriv)
	for _, cond := range []string{"", "kind=1", "created_at<4102444800", "kind=1&created_at>1700000000&created_at<4102444800"} {
		tag, err := Sign(ctx, s, sub, cond)
		if err != nil {
			t.Fatalf("Sign(%q): %v", cond, err)
		}
		if len(tag) != 4 || tag[0] != TagName || tag[1] != s.PubKey() || tag[2] != cond {
			t.Fatalf("Sign(%q) tag = %v", cond, tag)
		}
		if err := VerifySignature(tag[1], sub, tag[2], tag[3]); err != nil {
			t.Fatalf("VerifySignature(%q): %v", cond, err)
		}
		parsed, err := ParseAuthTag([][]string{tag}, sub)
		if err != nil || parsed == nil {
			t.Fatalf("ParseAuthTag(%q) = %v, %v", cond, parsed, err)
		}
		// Bound to the subordinate: another key can't carry it.
		other := mustPub(t, attesterPriv[:62]+"aa")
		if _, err := ParseAuthTag([][]string{tag}, other); !errors.Is(err, ErrSignatureVerificationFailed) {
			t.Fatalf("tag for %q accepted for another key: %v", cond, err)
		}
	}
}

// The spec's vector key is the secp256k1 generator's (private key 1):
// signing the vector's preimage with it must verify against the vector.
func TestSign_OfficialVectorKey(t *testing.T) {
	priv := "0000000000000000000000000000000000000000000000000000000000000001"
	s, err := NewKeySigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	if s.PubKey() != vectorOwnerPubkey {
		t.Fatalf("pubkey %s, want the vector's %s", s.PubKey(), vectorOwnerPubkey)
	}
	tag, err := Sign(context.Background(), s, vectorAgentPubkey, vectorConditions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAuthTag([][]string{tag}, vectorAgentPubkey); err != nil {
		t.Fatal(err)
	}
}

func TestSign_TimeBounds(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	until := now.Add(30 * 24 * time.Hour)
	cond := Until(until)
	if cond != "created_at<"+strconv.FormatInt(until.Unix(), 10) {
		t.Fatalf("Until = %q", cond)
	}
	tag, err := Sign(ctx, mustSigner(t), mustPub(t, subordinatePriv), cond)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAuthTag([][]string{tag}, mustPub(t, subordinatePriv))
	if err != nil {
		t.Fatal(err)
	}
	c := parsed.Conditions
	cases := []struct {
		at      time.Time
		expired bool
	}{
		{now, false},
		{until.Add(-time.Second), false},
		{until, true}, // created_at< is strict
		{until.Add(time.Hour), true},
	}
	for _, tc := range cases {
		if got := c.ExpiredAt(tc.at); got != tc.expired {
			t.Errorf("ExpiredAt(%d) = %v, want %v", tc.at.Unix(), got, tc.expired)
		}
		if got := c.EvaluateTimeClauses(uint64(tc.at.Unix())); got == tc.expired {
			t.Errorf("EvaluateTimeClauses(%d) = %v, want %v", tc.at.Unix(), got, !tc.expired)
		}
	}
	// A not-before bound: not yet valid reads as expired too.
	nb, _ := ParseConditions("created_at>" + strconv.FormatInt(now.Unix(), 10))
	if !nb.ExpiredAt(now) || nb.ExpiredAt(now.Add(time.Second)) {
		t.Fatal("created_at> bound misread")
	}
}

type badSigner struct {
	*KeySigner
	sig string
	err error
}

func (b badSigner) SignAttestation(context.Context, string, string) (string, error) {
	return b.sig, b.err
}

func TestSign_Refusals(t *testing.T) {
	ctx := context.Background()
	s := mustSigner(t)
	sub := mustPub(t, subordinatePriv)
	good, err := Sign(ctx, s, sub, "kind=1")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		signer Signer
		sub    string
		cond   string
		want   error
	}{
		{"nil signer", nil, sub, "", ErrNoSigner},
		{"bad subordinate", s, "abc", "", ErrInvalidSubordinatePubkey},
		{"self attestation", s, s.PubKey(), "", ErrSelfAttestation},
		{"malformed conditions", s, sub, "kind=01", ErrMalformedConditions},
		{"unsupported clause", s, sub, "until=5", ErrUnsupportedClause},
		{"signer error", badSigner{s, "", errors.New("refused")}, sub, "", nil},
		{"wrong signature", badSigner{s, good[3], nil}, sub, "kind=7", ErrSignatureVerificationFailed},
		{"garbage signature", badSigner{s, "zz", nil}, sub, "", ErrInvalidSignatureHex},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tag, err := Sign(ctx, tc.signer, tc.sub, tc.cond)
			if err == nil || tag != nil {
				t.Fatalf("Sign = %v, %v; want an error", tag, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

type fakeCaller struct {
	s      *KeySigner
	method string
}

func (f *fakeCaller) Call(ctx context.Context, method string, params ...string) (string, error) {
	f.method = method
	return f.s.SignAttestation(ctx, params[0], params[1])
}

func TestRemoteSigner(t *testing.T) {
	s := mustSigner(t)
	fc := &fakeCaller{s: s}
	r, err := NewRemoteSigner(fc, s.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	tag, err := Sign(context.Background(), r, mustPub(t, subordinatePriv), "created_at<4102444800")
	if err != nil {
		t.Fatal(err)
	}
	if fc.method != MethodSignAttestation || tag[1] != s.PubKey() {
		t.Fatalf("method %q, tag %v", fc.method, tag)
	}
	if _, err := NewRemoteSigner(nil, s.PubKey()); !errors.Is(err, ErrNoSigner) {
		t.Fatal(err)
	}
	if _, err := NewRemoteSigner(fc, "nope"); !errors.Is(err, ErrInvalidOwnerPubkey) {
		t.Fatal(err)
	}
}

func TestNewKeySigner(t *testing.T) {
	if _, err := NewKeySigner("not a key"); err == nil {
		t.Fatal("accepted a bad key")
	}
	s, err := NewKeySigner("  " + attesterPriv + "\n")
	if err != nil || s.PubKey() != mustPub(t, attesterPriv) {
		t.Fatalf("%v %v", s, err)
	}
}
