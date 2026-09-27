package relay

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
)

func hasNIP(nips []nip11.NIPID, n int) bool {
	for _, v := range nips {
		if v == nip11.NIP(n) {
			return true
		}
	}
	return false
}

func TestSupportedNIPsCore(t *testing.T) {
	store := newStore(t)
	sh := NewSessionHandler(store, &nip11.Metadata{}, nil, WithLogger(testlogger.New(t)))

	got := sh.SupportedNIPs().Slice()
	for _, want := range coreNIPs {
		if !hasNIP(got, want) {
			t.Errorf("SupportedNIPs() = %v, want core NIP %d present", got, want)
		}
	}
	for _, conditional := range []int{42, 43, 26, 50} {
		if hasNIP(got, conditional) {
			t.Errorf("SupportedNIPs() = %v, did not expect conditional NIP %d with no auth/self/delegation/search configured", got, conditional)
		}
	}
}

func TestSupportedNIPsConditional(t *testing.T) {
	store := newStore(t)

	metadata := &nip11.Metadata{
		Limitation: nip11.Limitation{AuthRequired: true},
		Self:       publicKey,
	}
	sh := NewSessionHandler(store, metadata, &MockSearchService{}, WithSessionConfig(SessionConfig{
		Delegation: &DelegationConfig{Issuer: "issuer", Conditions: "cond", Token: "tok"},
	}), WithLogger(testlogger.New(t)))

	got := sh.SupportedNIPs().Slice()
	for _, want := range []int{42, 43, 26, 50} {
		if !hasNIP(got, want) {
			t.Errorf("SupportedNIPs() = %v, want conditional NIP %d present", got, want)
		}
	}
}

func TestSupportedNIPs_43NotAdvertisedWithoutSelf(t *testing.T) {
	store := newStore(t)
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{AuthRequired: true}}
	sh := NewSessionHandler(store, metadata, nil, WithLogger(testlogger.New(t)))

	got := sh.SupportedNIPs().Slice()
	if hasNIP(got, 43) {
		t.Errorf("SupportedNIPs() = %v, did not expect NIP 43 with no self pubkey configured", got)
	}
}

func TestNormalizeLetteredNIP(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		// The ids this SDK actually registers, unchanged by normalization.
		{name: "A0 unchanged", in: "A0", want: "A0"},
		{name: "AZ unchanged", in: "AZ", want: "AZ"},
		{name: "B0 unchanged", in: "B0", want: "B0"},
		{name: "B7 unchanged", in: "B7", want: "B7"},
		{name: "C7 unchanged", in: "C7", want: "C7"},

		// Casing and padding are canonicalized so one NIP cannot register twice.
		{name: "lowercase is upper-cased", in: "b7", want: "B7"},
		{name: "mixed case is upper-cased", in: "aZ", want: "AZ"},
		{name: "surrounding space is trimmed", in: "  a0  ", want: "A0"},

		// Word-style org-private ids are permitted; whether to register them is
		// a separate decision, but the shape is valid.
		{name: "word-style CW", in: "cw", want: "CW"},
		{name: "word-style CASH", in: "cash", want: "CASH"},

		{name: "empty", in: "", wantErr: "empty"},
		{name: "whitespace only", in: "   ", wantErr: "empty"},
		{name: "tab only", in: "\t", wantErr: "empty"},

		// An all-digit id would serialize as the JSON string "53" where every
		// other implementation expects the number 53.
		{name: "all digits", in: "53", wantErr: "all digits"},
		{name: "all digits with padding", in: " 7 ", wantErr: "all digits"},

		{name: "hyphen", in: "B-7", wantErr: "letters and digits"},
		{name: "inner space", in: "B 7", wantErr: "letters and digits"},
		{name: "punctuation", in: "B7!", wantErr: "letters and digits"},
		{name: "spelled-out prefix", in: "nip-b7", wantErr: "letters and digits"},
		{name: "underscore", in: "B_7", wantErr: "letters and digits"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeLetteredNIP(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("normalizeLetteredNIP(%q) = %q, want an error mentioning %q", tc.in, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeLetteredNIP(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeLetteredNIP(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// RegisterLetteredNIP is called from init(), so a bad id has to fail loudly at
// process start rather than quietly serve a malformed supported_nips list for
// the life of the relay.
func TestRegisterLetteredNIPPanicsOnInvalidID(t *testing.T) {
	for _, id := range []string{"", "   ", "53", "B-7", "nip-b7", "B7!"} {
		t.Run(id, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("RegisterLetteredNIP(%q) did not panic", id)
				}
				message, ok := r.(string)
				if !ok {
					t.Fatalf("panic value = %#v, want a string", r)
				}
				if !strings.Contains(message, "RegisterLetteredNIP") {
					t.Errorf("panic message should name the call, got %q", message)
				}
			}()
			RegisterLetteredNIP(id)
		})
	}
}

// The registry has no unregister, so this uses a sentinel id no real NIP uses.
// It asserts the end-to-end behaviour the pure-function test cannot: what
// actually lands in the registry, and therefore on the wire.
func TestRegisterLetteredNIPNormalizesCaseInTheRegistry(t *testing.T) {
	RegisterLetteredNIP("zq9")

	var found bool
	for _, id := range RegisteredNIPs() {
		switch id.String() {
		case "ZQ9":
			found = true
		case "zq9":
			t.Error(`registry holds the un-normalized "zq9"`)
		}
	}
	if !found {
		t.Error(`registry does not hold the normalized "ZQ9"`)
	}

	// Registering the other casing must not create a second entry.
	RegisterLetteredNIP("ZQ9")
	count := 0
	for _, id := range RegisteredNIPs() {
		if id.String() == "ZQ9" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("ZQ9 registered %d times, want 1", count)
	}
}
