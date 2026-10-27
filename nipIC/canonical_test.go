package nipIC

import (
	"errors"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"strings"
	"testing"
	"unicode/utf8"
)

// T05-01 (K-CK-1..3).
func TestT05_01_NumericIDs(t *testing.T) {
	for in, want := range map[string]string{
		"80351110224678912":    "22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d",
		"12345":                "",
		"12":                   "",
		"1":                    "",
		"18446744073709551615": "",
	} {
		k, err := NewConnectionKey("discord", in)
		if err != nil {
			t.Errorf("%q refused: %v", in, err)
		}
		if want != "" && string(k) != want {
			t.Errorf("%q = %s", in, k)
		}
	}
	if k, _ := NewConnectionKey("x", "12345"); k != "e659b0738cfe438a5d0a58a6eaac063b29537dc9e4570dafac589de080f35c58" {
		t.Errorf("K-CK-2 %s", k)
	}
	if k, _ := NewConnectionKey("x", "12"); k != "e16c8f9271f1bc728d668a96e548fedb6da230ac3cb15f5b0a813020695e46e9" {
		t.Errorf("K-CK-3 %s", k)
	}
	for _, in := range []string{"080351110224678912", "0", "+5", "-5", "٥", "５", "18446744073709551616", strings.Repeat("1", 21),
		" 12345", "12345 ", "12345\n", "@12345", "@80351110224678912", "alice", "@alice"} {
		if _, err := NewConnectionKey("discord", in); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

// T05-02 (K-CK-4..6).
func TestT05_02_Email(t *testing.T) {
	for in, want := range map[string]string{
		"  Alice@Example.COM ": "alice@example.com",
		"alice@bücher.example": "alice@xn--bcher-kva.example",
		"Ünal@x.example":       "Ünal@x.example",
		`"a@b"@Bücher.example`: `"a@b"@xn--bcher-kva.example`,
	} {
		got, err := CanonicalUserID("email", in)
		if err != nil || got != want {
			t.Errorf("%q = %q (%v), want %q", in, got, err, want)
		}
	}
	for in, key := range map[string]string{
		"  Alice@Example.COM ": "889e87fc03d0477823a739f269555750a3fd94dacfd1694589bf2bc4eef07b55",
		"alice@bücher.example": "7beaed89bf6d42d0a7cc67425e8da643156c213496c7695847456dfe8842b518",
		`"a@b"@Bücher.example`: "2ca700d6bf1859ef642bb8abe7768f6554e4915b8ca32852e335fc408482183d",
	} {
		if k, _ := NewConnectionKey("email", in); string(k) != key {
			t.Errorf("%q key %s", in, k)
		}
	}
	for _, in := range []string{"alice@BÜCHER.example", "alice@faß.de", "jürgen@x.example", "alice", "alice@example.com.", "@example.com"} {
		if _, err := CanonicalUserID("email", in); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

// T05-03, T05-20 (K-CK-7, K-CK-9, K-IDNA-1..6).
func TestT05_03_DNS(t *testing.T) {
	for _, in := range []string{"bücher.example", "BüCHER.example", "XN--BCHER-KVA.EXAMPLE"} {
		got, err := CanonicalUserID("dns", in)
		if err != nil || got != "xn--bcher-kva.example" {
			t.Errorf("%q = %q (%v)", in, got, err)
		}
		if k, _ := NewConnectionKey("dns", in); k != "34155e197a74f55bd430d823c3ed9990393530a5122edfda37dfb891014b3bbb" {
			t.Errorf("K-CK-7 %q %s", in, k)
		}
	}
	if k, _ := NewConnectionKey("dns", "example.com"); k != "2e93281bfa333b6ab13689eab03c2025404912f99af7b698f19f6ad678eb67e3" {
		t.Errorf("K-CK-9 dns %s", k)
	}
	for _, in := range []string{"BÜCHER.example", "ｂücher.example", "bücher。example", "bücher.example", "faß.de",
		"ς.example", "a‌b.example", "a‍b.example", "ab--c.example", "-a.example", "a_b.example", "a..example",
		strings.Repeat("a", 64) + ".example", "אa.example", "example.com.", "@example.com", "xn--fa-hia.de"} {
		if _, err := CanonicalUserID("dns", in); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

// T05-04, T05-05, T05-06 (K-CK-8, K-CK-9).
func TestT05_05_AttestedKeys(t *testing.T) {
	for _, p := range []WebIdentity{"Discord", "git:hub", "git hub", ""} {
		if _, err := NewConnectionKey(p, "1"); !errors.Is(err, ErrPlatformName) {
			t.Errorf("%q: %v", p, err)
		}
		if _, err := ConnectionKeyFromAttested(p, "1"); !errors.Is(err, ErrPlatformName) {
			t.Errorf("%q attested: %v", p, err)
		}
	}
	k, _ := ConnectionKeyFromAttested("github", "Alice")
	if k != "5aaf77cac277108947fa433a956917db62967e209141acb5f605bd6143422e96" {
		t.Errorf("K-CK-8 %s", k)
	}
	if k2, _ := ConnectionKeyFromAttested("github", "alice"); k2 != "ccf01c68a2769518a7892ffd068d855bf1a798b06058acb87033613b02741501" {
		t.Errorf("K-CK-8 neg %s", k2)
	}
	if k3, _ := ConnectionKeyFromAttested("github", "12345"); k3 != "2db75fb4d7a8e3005aca09c643b4e6f40142ddcfc18c675509988c1b111d0dcf" {
		t.Errorf("K-CK-9 %s", k3)
	}
	if _, err := NewConnectionKey("github", "Alice"); !errors.Is(err, ErrTypedInputNotCanonical) {
		t.Errorf("typed github: %v", err)
	}
	if _, err := ParseConnectionKey(strings.ToUpper(string(k))); !errors.Is(err, ErrConnectionKey) {
		t.Errorf("uppercase key: %v", err)
	}
}

// F-CK-1: canonicalization is idempotent, ASCII for domains, and never lets a
// deviation character into a domain.
func FuzzCanonicalUserID(f *testing.F) {
	for _, s := range []string{"80351110224678912", "Alice@Example.COM", "bücher.example", "faß.de", "xn--bcher-kva.example"} {
		f.Add("dns", s)
		f.Add("email", s)
		f.Add("discord", s)
	}
	f.Fuzz(func(t *testing.T, p, s string) {
		out, err := CanonicalUserID(WebIdentity(p), s)
		if err != nil {
			return
		}
		again, err := CanonicalUserID(WebIdentity(p), out)
		if err != nil || again != out {
			t.Fatalf("not idempotent: %q → %q → %q (%v)", s, out, again, err)
		}
		// The deviation rule is a domain rule: an email's local part gets only
		// NFC (NIP-IC §Canonical Platform User IDs), so check the domain.
		domain := out
		if p == "email" {
			domain = out[strings.LastIndexByte(out, '@')+1:]
		}
		if strings.ContainsAny(domain, deviations) {
			t.Fatalf("deviation character accepted: %q", out)
		}
		if p == "dns" {
			for i := 0; i < len(out); i++ {
				if out[i] > 0x7f {
					t.Fatalf("non-ASCII domain %q", out)
				}
			}
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 %q", out)
		}
	})
}

func encodeNpv(t *testing.T, hrp string, data []byte) ChallengeToken {
	return ChallengeToken(encodeNpvString(t, hrp, data))
}

func encodeNpvString(t *testing.T, hrp string, data []byte) string {
	t.Helper()
	bits5, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := bech32.Encode(hrp, bits5)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
