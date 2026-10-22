package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Day, Week and Month are the calendar-free units ParseDuration accepts;
// a month is 30 days.
const (
	Day   = 24 * time.Hour
	Week  = 7 * Day
	Month = 30 * Day
)

// ParseDuration parses a positive duration made of number+unit parts, e.g.
// "90s", "24h", "7d", "2w", "1mo", "1w 2d", "1.5h". Units: s, m, h, d, w, mo.
func ParseDuration(s string) (time.Duration, error) {
	in := strings.ReplaceAll(s, " ", "")
	if in == "" {
		return 0, fmt.Errorf("empty duration")
	}
	var total time.Duration
	for in != "" {
		i := 0
		for i < len(in) && (in[i] >= '0' && in[i] <= '9' || in[i] == '.') {
			i++
		}
		j := i
		for j < len(in) && !(in[j] >= '0' && in[j] <= '9' || in[j] == '.') {
			j++
		}
		num, unit := in[:i], in[i:j]
		n, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		u, ok := durationUnits[unit]
		if !ok {
			return 0, fmt.Errorf("invalid duration %q: unknown unit %q", s, unit)
		}
		total += time.Duration(n * float64(u))
		in = in[j:]
	}
	if total <= 0 {
		return 0, fmt.Errorf("invalid duration %q: must be positive", s)
	}
	return total, nil
}

var durationUnits = map[string]time.Duration{
	"s":  time.Second,
	"m":  time.Minute,
	"h":  time.Hour,
	"d":  Day,
	"w":  Week,
	"mo": Month,
}
