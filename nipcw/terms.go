package nipcw

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Budget renewal values (NIP-CW §Request, NIP-47), tightest first.
const (
	RenewalDaily   = "daily"
	RenewalWeekly  = "weekly"
	RenewalMonthly = "monthly"
	RenewalYearly  = "yearly"
	RenewalNever   = "never"
)

// MaxTermValue is the largest max_amount, max_receive or expiry a request may
// carry: 2^63-1 (NIP-CW §Processing Algorithm, step 1).
const MaxTermValue = uint64(1<<63 - 1)

// ErrTerms is a terms value out of range, a renewal outside the enum, or a terms
// tag that does not have the spec's exact form.
var ErrTerms = errors.New("nipcw: malformed terms")

// renewalRank orders the renewals tightest to loosest.
var renewalRank = map[string]int{
	RenewalDaily: 0, RenewalWeekly: 1, RenewalMonthly: 2, RenewalYearly: 3, RenewalNever: 4,
}

// ValidRenewal reports one of the five renewal values, case-sensitive.
func ValidRenewal(s string) bool {
	_, ok := renewalRank[s]
	return ok
}

// resolveRenewal maps an omitted renewal to never and checks the enum.
func resolveRenewal(s string) (string, error) {
	if s == "" {
		return RenewalNever, nil
	}
	if !ValidRenewal(s) {
		return "", fmt.Errorf("%w: budget_renewal %q", ErrTerms, s)
	}
	return s, nil
}

// RenewalAtLeast reports whether requested satisfies the Hub's floor: it is
// floor or looser (NIP-CW §Budget Renewal Floor). An omitted requested renewal
// is never; an empty floor allows everything. An unknown value never satisfies.
func RenewalAtLeast(requested, floor string) bool {
	r, err := resolveRenewal(requested)
	if err != nil {
		return false
	}
	if floor == "" {
		return true
	}
	f, ok := renewalRank[floor]
	return ok && renewalRank[r] >= f
}

// Terms are the requested terms a join proof's terms tag binds. Expiry is in
// seconds, 0 for the Hub's default; an empty Renewal is never.
type Terms struct {
	MaxAmount, MaxReceive, Expiry uint64
	Renewal                       string
}

// TermsTag is the terms tag value <max_amount>:<max_receive>:<expiry>:<budget_renewal>
// (NIP-CW §Identity Proof, check 7): unsigned decimals with no leading zeros, an
// omitted renewal written as never. It refuses a value above MaxTermValue and a
// renewal outside the enum.
func TermsTag(t Terms) (string, error) {
	if err := t.check(); err != nil {
		return "", err
	}
	r, _ := resolveRenewal(t.Renewal)
	return fmt.Sprintf("%d:%d:%d:%s", t.MaxAmount, t.MaxReceive, t.Expiry, r), nil
}

func (t Terms) check() error {
	for _, v := range []struct {
		name string
		v    uint64
	}{{"max_amount", t.MaxAmount}, {"max_receive", t.MaxReceive}, {"expiry", t.Expiry}} {
		if v.v > MaxTermValue {
			return fmt.Errorf("%w: %s %d is above 2^63-1", ErrTerms, v.name, v.v)
		}
	}
	_, err := resolveRenewal(t.Renewal)
	return err
}

// ParseTerms reads a terms tag value strictly: exactly four parts, each number
// unsigned decimal ASCII without a sign or leading zero and at most 2^63-1, and
// the renewal one of the five values, case-sensitive. The parsed Renewal is
// never empty.
func ParseTerms(s string) (Terms, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return Terms{}, fmt.Errorf("%w: %d parts, want 4", ErrTerms, len(parts))
	}
	var nums [3]uint64
	for i, p := range parts[:3] {
		n, err := parseTermNumber(p)
		if err != nil {
			return Terms{}, err
		}
		nums[i] = n
	}
	if !ValidRenewal(parts[3]) {
		return Terms{}, fmt.Errorf("%w: budget_renewal %q", ErrTerms, parts[3])
	}
	return Terms{MaxAmount: nums[0], MaxReceive: nums[1], Expiry: nums[2], Renewal: parts[3]}, nil
}

func parseTermNumber(p string) (uint64, error) {
	if p == "" {
		return 0, fmt.Errorf("%w: empty number", ErrTerms)
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%w: %q is not unsigned decimal", ErrTerms, p)
		}
	}
	if len(p) > 1 && p[0] == '0' {
		return 0, fmt.Errorf("%w: %q has a leading zero", ErrTerms, p)
	}
	n, err := strconv.ParseUint(p, 10, 64)
	if err != nil || n > MaxTermValue {
		return 0, fmt.Errorf("%w: %q is above 2^63-1", ErrTerms, p)
	}
	return n, nil
}
