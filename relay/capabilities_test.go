package relay

import (
	"testing"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
)

func hasNIP(nips []int, n int) bool {
	for _, v := range nips {
		if v == n {
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
