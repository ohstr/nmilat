package nipcw

import (
	"testing"
	"time"
)

// K-BP-1..8 (NIP-CW §Budget Renewal Floor).
func TestBudgetPeriodStart_KnownAnswers(t *testing.T) {
	cases := []struct {
		name    string
		created int64
		renewal string
		k       int64
		want    int64
	}{
		{"K-BP-1", 1706695200, RenewalMonthly, 1, 1709200800},
		{"K-BP-2", 1706695200, RenewalMonthly, 2, 1711879200},
		{"K-BP-3", 1706695200, RenewalMonthly, 3, 1714471200},
		{"K-BP-4", 1709200800, RenewalYearly, 1, 1740736800},
		{"K-BP-5", 1709200800, RenewalYearly, 2, 1772272800},
		{"K-BP-6", 1709200800, RenewalYearly, 3, 1803808800},
		{"K-BP-7", 1709200800, RenewalYearly, 4, 1835431200},
		{"K-BP-8 daily", 1706695200, RenewalDaily, 1, 1706781600},
		{"K-BP-8 weekly", 1706695200, RenewalWeekly, 1, 1707300000},
	}
	for _, c := range cases {
		got, err := BudgetPeriodStart(time.Unix(c.created, 0), c.renewal, c.k)
		if err != nil || got.Unix() != c.want {
			t.Errorf("%s: start = %d, %v; want %d", c.name, got.Unix(), err, c.want)
		}
	}
	if _, err := BudgetPeriodStart(time.Unix(0, 0), RenewalNever, 1); err == nil {
		t.Error("never has no period 1")
	}
	if _, err := BudgetPeriodStart(time.Unix(0, 0), "Monthly", 0); err == nil {
		t.Error("an unknown renewal is an error")
	}
}

// T12-11: periods are [start, next); a payment at 1709200799 is in period 1, one
// at 1709200800 in period 2 (S-CW-71, 72).
func TestBudgetPeriod_Edges(t *testing.T) {
	created := time.Unix(1706695200, 0)
	s, n, err := BudgetPeriod(created, RenewalMonthly, time.Unix(1709200799, 0))
	if err != nil || s.Unix() != 1706695200 || n.Unix() != 1709200800 {
		t.Fatalf("at 1709200799: [%d, %d) %v", s.Unix(), n.Unix(), err)
	}
	s, n, err = BudgetPeriod(created, RenewalMonthly, time.Unix(1709200800, 0))
	if err != nil || s.Unix() != 1709200800 || n.Unix() != 1711879200 {
		t.Fatalf("at 1709200800: [%d, %d) %v", s.Unix(), n.Unix(), err)
	}
	// Far ahead: the O(1) estimate still lands on the right period.
	for _, r := range []string{RenewalDaily, RenewalWeekly, RenewalMonthly, RenewalYearly} {
		now := time.Unix(1706695200+10*365*86400+12345, 0)
		s, n, err := BudgetPeriod(created, r, now)
		if err != nil || s.After(now) || !n.After(now) {
			t.Errorf("%s: [%v, %v) does not hold %v (%v)", r, s, n, now, err)
		}
	}
	s, n, err = BudgetPeriod(created, "", time.Unix(1806695200, 0))
	if err != nil || s.Unix() != 1706695200 || !n.IsZero() {
		t.Fatalf("never: [%v, %v) %v", s, n, err)
	}
	s, _, _ = BudgetPeriod(created, RenewalDaily, time.Unix(0, 0))
	if s.Unix() != 1706695200 {
		t.Fatalf("before creation: start %d", s.Unix())
	}
}

// A monthly period is anchored to the creation day, never to the previous
// start: from Jan 31 the starts go Feb 29, Mar 31, Apr 30.
func TestBudgetPeriodStart_AnchoredNotChained(t *testing.T) {
	c := time.Date(2024, 1, 31, 10, 0, 0, 0, time.UTC)
	got, _ := BudgetPeriodStart(c, RenewalMonthly, 2)
	if want := time.Date(2024, 3, 31, 10, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("k=2: %v, want %v", got, want)
	}
}
