package utils

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	ok := map[string]time.Duration{
		"90s":    90 * time.Second,
		"15m":    15 * time.Minute,
		"24h":    24 * time.Hour,
		"7d":     7 * Day,
		"2w":     2 * Week,
		"1mo":    Month,
		"1w 2d":  Week + 2*Day,
		"1h30m":  90 * time.Minute,
		"1.5h":   90 * time.Minute,
		" 30d ":  30 * Day,
		"1mo1d":  Month + Day,
		"0.5d":   12 * time.Hour,
		"1m30s":  90 * time.Second,
		"2h 15m": 2*time.Hour + 15*time.Minute,
	}
	for in, want := range ok {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", " ", "7", "d", "7x", "1y", "-1h", "0h", "1..5h", "h1", "all"} {
		if got, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q) = %v, want an error", in, got)
		}
	}
}
