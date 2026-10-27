package nipcw

import (
	"errors"
	"strconv"
	"testing"
)

// K-TERMS-1..2 (NIP-CW §Identity Proof, check 7).
func TestTermsTag_KnownAnswers(t *testing.T) {
	cases := []struct {
		name string
		in   Terms
		want string
	}{
		{"K-TERMS-1", Terms{MaxAmount: 100000, MaxReceive: 200000, Expiry: 0, Renewal: RenewalMonthly}, "100000:200000:0:monthly"},
		{"K-TERMS-2", Terms{MaxAmount: 20000000, MaxReceive: 50000000}, "20000000:50000000:0:never"},
	}
	for _, c := range cases {
		got, err := TermsTag(c.in)
		if err != nil || got != c.want {
			t.Errorf("%s: TermsTag = %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

// T12-02: ParseTerms is strict.
func TestParseTerms_Refusals(t *testing.T) {
	for _, s := range []string{
		"020000000:50000000:0:monthly",
		"20000000:50000000::monthly",
		"100000:200000::monthly",
		"0100000:200000:0:monthly",
		"20000000:50000000:0:Monthly",
		"+20000000:50000000:0:monthly",
		"-1:50000000:0:monthly",
		"20000000:50000000:0",
		"20000000:50000000:0:monthly:x",
		"20000000:50000000:0:",
		"20000000:50000000:0x10:never",
		" 1:2:0:never",
		"9223372036854775808:0:0:never",
		"0:18446744073709551616:0:never",
	} {
		if _, err := ParseTerms(s); !errors.Is(err, ErrTerms) {
			t.Errorf("ParseTerms(%q) = %v, want ErrTerms", s, err)
		}
	}
	got, err := ParseTerms("0:0:0:never")
	if err != nil || got != (Terms{Renewal: RenewalNever}) {
		t.Fatalf("ParseTerms(0:0:0:never) = %+v, %v", got, err)
	}
}

// T12-27 for TermsTag and ParseTerms: 2^63-1 accepted, 2^63 refused.
func TestTerms_Range(t *testing.T) {
	maxs := strconv.FormatUint(MaxTermValue, 10)
	tag := maxs + ":" + maxs + ":" + maxs + ":yearly"
	got, err := ParseTerms(tag)
	if err != nil || got.MaxAmount != MaxTermValue || got.MaxReceive != MaxTermValue || got.Expiry != MaxTermValue {
		t.Fatalf("ParseTerms(max) = %+v, %v", got, err)
	}
	if s, err := TermsTag(got); err != nil || s != tag {
		t.Fatalf("TermsTag(max) = %q, %v", s, err)
	}
	for _, tt := range []Terms{{MaxAmount: MaxTermValue + 1}, {MaxReceive: MaxTermValue + 1}, {Expiry: MaxTermValue + 1}, {Renewal: "Monthly"}} {
		if _, err := TermsTag(tt); !errors.Is(err, ErrTerms) {
			t.Errorf("TermsTag(%+v) = %v, want ErrTerms", tt, err)
		}
	}
}

func TestRenewalAtLeast(t *testing.T) {
	cases := []struct {
		req, floor string
		want       bool
	}{
		{"monthly", "monthly", true},
		{"yearly", "monthly", true},
		{"", "monthly", true}, // omitted is never
		{"never", "monthly", true},
		{"weekly", "monthly", false},
		{"daily", "monthly", false},
		{"daily", "", true},
		{"Monthly", "", false},
		{"monthly", "bogus", false},
	}
	for _, c := range cases {
		if got := RenewalAtLeast(c.req, c.floor); got != c.want {
			t.Errorf("RenewalAtLeast(%q, %q) = %v, want %v", c.req, c.floor, got, c.want)
		}
	}
}

// F-CW-1: ParseTerms and TermsTag round-trip whatever ParseTerms accepts.
func FuzzParseTerms(f *testing.F) {
	for _, s := range []string{"100000:200000:0:monthly", "20000000:50000000:0:never", "0:0:0:daily", "01:1:1:weekly", "1:2:3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tt, err := ParseTerms(s)
		if err != nil {
			return
		}
		back, err := TermsTag(tt)
		if err != nil || back != s {
			t.Fatalf("round trip %q -> %+v -> %q, %v", s, tt, back, err)
		}
	})
}
