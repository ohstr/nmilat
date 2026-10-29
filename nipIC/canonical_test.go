package nipIC

import (
	"errors"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
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

// No value carries a leading '@': an email whose local part starts with one is
// refused, never repaired; an '@' elsewhere in the local part is kept.
func TestEmail_LeadingAtRefused(t *testing.T) {
	for _, in := range []string{"@alice@example.com", " @alice@example.com", "@@example.com", "\t@Alice@Example.com"} {
		if out, err := CanonicalUserID("email", in); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%q: got %q, %v; want ErrNotCanonical", in, out, err)
		}
		if _, err := NewConnectionKey("email", in); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%q: key built: %v", in, err)
		}
	}
	for in, want := range map[string]string{
		"a@example.com":        "a@example.com",
		" Alice@example.com":   "alice@example.com",
		"alice@b@example.com":  "alice@b@example.com",
		`"@alice"@example.com`: `"@alice"@example.com`,
		"alice.@x@example.com": "alice.@x@example.com",
	} {
		if got, err := CanonicalUserID("email", in); err != nil || got != want {
			t.Errorf("%q = %q (%v), want %q", in, got, err, want)
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
		"ς.example", "a\u200cb.example", "a\u200db.example", "ab--c.example", "-a.example", "a_b.example", "a..example",
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

// On a platform with a canonical form an attested user id must already be
// canonical; elsewhere it is hashed byte for byte (NIP-IC §Terminology).
func TestConnectionKeyFromAttested_CanonicalPlatforms(t *testing.T) {
	for _, c := range [][2]string{{"discord", "080351110224678912"}, {"discord", "@alice"}, {"x", "0"}, {"email", "Alice@Example.COM"}, {"dns", "BÜCHER.example"}} {
		if _, err := ConnectionKeyFromAttested(WebIdentity(c[0]), c[1]); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%s %q: %v, want ErrNotCanonical", c[0], c[1], err)
		}
	}
	if k, err := ConnectionKeyFromAttested("discord", "80351110224678912"); err != nil || k != "22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d" {
		t.Errorf("canonical discord: %s %v", k, err)
	}
}

// Nostr is not a Web Identity: "nostr" is no platform name, so a pubkey is
// never hashed into a ConnectionKey, signed into a 35522 or carried in an
// nconnection; names that only contain it stay valid.
func TestPlatformNostrRefused(t *testing.T) {
	ia, alice := newKeypair(t), newKeypair(t)
	if ValidPlatformName(PlatformNostr) {
		t.Error(`"nostr" is a valid platform name`)
	}
	if _, err := ConnectionKeyFromAttested(PlatformNostr, alice.pub); !errors.Is(err, ErrPlatformName) {
		t.Errorf("attested key: %v", err)
	}
	if _, err := NewConnectionKey(PlatformNostr, alice.pub); !errors.Is(err, ErrPlatformName) {
		t.Errorf("typed key: %v", err)
	}
	if _, err := NewAttestation(AttestationParams{PrivateKey: ia.priv, UserPubkey: alice.pub, Platform: PlatformNostr,
		AuthType: "oauth", Evidence: Evidence{UserID: alice.pub}}); !errors.Is(err, ErrPlatformName) {
		t.Errorf("35522 signed: %v", err)
	}
	key, _ := ConnectionKeyFromAttested("github", "Alice")
	if _, err := EncodeNConnection(key, nil, PlatformNostr); !errors.Is(err, ErrPlatformName) {
		t.Errorf("nconnection encoded: %v", err)
	}
	for _, p := range []WebIdentity{"nostr2", "nostr.example", "x-nostr", "nost", "github"} {
		if !ValidPlatformName(p) {
			t.Errorf("%q refused", p)
		}
		if _, err := ConnectionKeyFromAttested(p, "Alice"); err != nil {
			t.Errorf("%q attested: %v", p, err)
		}
	}
	if _, err := NewAttestation(AttestationParams{PrivateKey: ia.priv, UserPubkey: alice.pub, Platform: "nostr2",
		AuthType: "oauth", Evidence: Evidence{UserID: "Alice"}}); err != nil {
		t.Errorf("35522 on nostr2: %v", err)
	}
}

// The linked UTS #46 and NFC tables are the Unicode version every client
// canonicalizes with: a code point unassigned in 15.0.0 (CJK Extension I, a
// letter from 15.1 on) is refused, an assigned one is accepted.
func TestUnicodeTablesPinned(t *testing.T) {
	if idna.UnicodeVersion != UnicodeVersion || norm.Version != UnicodeVersion || !tablesPinned {
		t.Fatalf("idna %s, norm %s, want %s: canonical forms would differ from other clients'", idna.UnicodeVersion, norm.Version, UnicodeVersion)
	}
	if _, err := CanonicalUserID(PlatformDNS, "\U0002EBF0.example"); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("a CJK Extension I domain: %v", err)
	}
	if got, err := CanonicalUserID(PlatformDNS, "中.example"); err != nil || got != "xn--fiq.example" {
		t.Errorf("a CJK domain = %q, %v", got, err)
	}
}

// Linked with tables of another Unicode version, email and dns values are
// refused, while numeric ids, which use no table, still canonicalize.
func TestUnicodeVersionMismatchRefusesTableValues(t *testing.T) {
	tablesPinned = false
	t.Cleanup(func() { tablesPinned = true })
	for _, c := range [][2]string{{"email", "alice@example.com"}, {"dns", "example.com"}} {
		if _, err := CanonicalUserID(WebIdentity(c[0]), c[1]); !errors.Is(err, ErrUnicodeVersion) {
			t.Errorf("%s: %v", c[0], err)
		}
		if _, err := ConnectionKeyFromAttested(WebIdentity(c[0]), c[1]); !errors.Is(err, ErrUnicodeVersion) {
			t.Errorf("%s attested: %v", c[0], err)
		}
	}
	if _, err := NewConnectionKey("discord", "80351110224678912"); err != nil {
		t.Errorf("discord: %v", err)
	}
	if _, err := ConnectionKeyFromAttested("github", "Alice"); err != nil {
		t.Errorf("github attested: %v", err)
	}
}
