package nippf

import (
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	indexRe    = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	optionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	numberRe   = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
	dateRe     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	unixRe     = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	positiveRe = regexp.MustCompile(`^[1-9][0-9]*$`)
	hex64Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// maxSignificant is the most significant digits a number answer may have.
const maxSignificant = 18

// parseIndex reads a question index: a decimal string without leading zeros.
func parseIndex(s string) (int, bool) {
	if !indexRe.MatchString(s) || len(s) > 9 {
		return 0, false
	}
	i, err := strconv.Atoi(s)
	return i, err == nil
}

// parseUnix reads unix seconds (0|[1-9][0-9]*), within int64.
func parseUnix(s string) (int64, bool) {
	if !unixRe.MatchString(s) {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

// significant counts a number's significant digits: every digit after the
// leading zeros, the fraction's trailing zeros included; zero has one.
func significant(v string) int {
	d := strings.TrimLeft(strings.NewReplacer("-", "", ".", "").Replace(v), "0")
	if d == "" {
		return 1
	}
	return len(d)
}

// ValidValue reports whether v is a valid answer of a question of type typ
// (text, number, date, time); a choice or unknown type has no answer value.
func ValidValue(typ, v string) bool {
	switch typ {
	case TypeText:
		return v != ""
	case TypeNumber:
		return numberRe.MatchString(v) && significant(v) <= maxSignificant
	case TypeDate:
		if !dateRe.MatchString(v) {
			return false
		}
		_, err := time.Parse(time.DateOnly, v)
		return err == nil
	case TypeTime:
		return unixRe.MatchString(v) // any size: compared as integers
	}
	return false
}

// bounded reports whether typ takes min and max: number, date and time.
func bounded(typ string) bool {
	return typ == TypeNumber || typ == TypeDate || typ == TypeTime
}

// compareValues orders two valid values of a bounded type: -1, 0 or 1.
// Numbers compare numerically, dates as calendar dates, times as integers.
func compareValues(typ, a, b string) int {
	switch typ {
	case TypeNumber:
		x, _ := new(big.Rat).SetString(a)
		y, _ := new(big.Rat).SetString(b)
		return x.Cmp(y)
	case TypeTime:
		x, _ := new(big.Int).SetString(a, 10)
		y, _ := new(big.Int).SetString(b, 10)
		return x.Cmp(y)
	default: // date: YYYY-MM-DD orders as text
		return strings.Compare(a, b)
	}
}

// noteOf is a note as read: one empty after trimming whitespace is no note.
func noteOf(t []string, pos int) string {
	if len(t) <= pos || strings.TrimSpace(t[pos]) == "" {
		return ""
	}
	return t[pos]
}
