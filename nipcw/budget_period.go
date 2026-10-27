package nipcw

import (
	"fmt"
	"time"
)

// BudgetPeriodStart is the start of the k-th budget period of a wallet created
// at created (NIP-CW §Budget Renewal Floor), in UTC; k = 0 is the creation
// instant. Daily and weekly periods add k × 24 hours or k × 7 days. Monthly and
// yearly ones stay anchored to the creation day, clamped to the month's last
// day, at the creation's time of day, and are always counted from the creation,
// never from the previous start. never has only period 0. An empty renewal is
// never; a negative k or an unknown renewal is an error.
func BudgetPeriodStart(created time.Time, renewal string, k int64) (time.Time, error) {
	r, err := resolveRenewal(renewal)
	if err != nil {
		return time.Time{}, err
	}
	if k < 0 {
		return time.Time{}, fmt.Errorf("nipcw: budget period %d is negative", k)
	}
	c := created.UTC().Truncate(time.Second)
	switch r {
	case RenewalDaily:
		return c.Add(time.Duration(k) * 24 * time.Hour), nil
	case RenewalWeekly:
		return c.Add(time.Duration(k) * 7 * 24 * time.Hour), nil
	case RenewalMonthly:
		return addMonthsClamped(c, k), nil
	case RenewalYearly:
		return addMonthsClamped(c, 12*k), nil
	default: // never
		if k != 0 {
			return time.Time{}, fmt.Errorf("nipcw: a never renewal has one period")
		}
		return c, nil
	}
}

// addMonthsClamped moves c by months whole months, keeping c's day of month
// clamped to the target month's last day and c's time of day.
func addMonthsClamped(c time.Time, months int64) time.Time {
	total := int64(c.Year())*12 + int64(c.Month()-1) + months
	y, m := int(total/12), time.Month(total%12+1)
	day := min(c.Day(), daysIn(y, m))
	return time.Date(y, m, day, c.Hour(), c.Minute(), c.Second(), 0, time.UTC)
}

func daysIn(y int, m time.Month) int {
	return time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// BudgetPeriod returns the period now falls in, [start, next): the latest
// period start at or before now, and the one after it. With never, the whole
// life is one period and next is the zero time. A now before created is in
// period 0.
func BudgetPeriod(created time.Time, renewal string, now time.Time) (start, next time.Time, err error) {
	r, err := resolveRenewal(renewal)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	c := created.UTC().Truncate(time.Second)
	if r == RenewalNever {
		return c, time.Time{}, nil
	}
	k := estimatePeriod(c, r, now.UTC())
	// The estimate is off by at most one either way; correct it.
	for k > 0 {
		s, _ := BudgetPeriodStart(c, r, k)
		if !s.After(now) {
			break
		}
		k--
	}
	for {
		n, _ := BudgetPeriodStart(c, r, k+1)
		if n.After(now) {
			s, _ := BudgetPeriodStart(c, r, k)
			return s, n, nil
		}
		k++
	}
}

func estimatePeriod(c time.Time, r string, now time.Time) int64 {
	if !now.After(c) {
		return 0
	}
	switch r {
	case RenewalDaily:
		return int64(now.Sub(c) / (24 * time.Hour))
	case RenewalWeekly:
		return int64(now.Sub(c) / (7 * 24 * time.Hour))
	}
	months := int64(now.Year()-c.Year())*12 + int64(now.Month()-c.Month())
	if r == RenewalYearly {
		return months / 12
	}
	return months
}
