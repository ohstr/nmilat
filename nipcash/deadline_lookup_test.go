package nipcash

import (
	"errors"
	"strings"
	"testing"
)

// T07-01, T07-02 (K-RID-1).
func TestT07_01_RequestIDs(t *testing.T) {
	for _, s := range []string{strings.Repeat("a", 32), strings.Repeat("a", 34), strings.Repeat("a", 64), "00112233445566778899aabbccddeeff"} {
		if !ValidRequestID(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{strings.Repeat("a", 31), strings.Repeat("a", 63), strings.Repeat("a", 66), strings.Repeat("a", 33),
		"00112233445566778899AABBCCDDEEFF", strings.Repeat("g", 32), ""} {
		if ValidRequestID(s) {
			t.Errorf("%q accepted", s)
		}
	}
	seen := map[string]bool{}
	for range 1000 {
		id, err := NewRequestID()
		if err != nil || len(id) != 64 || !ValidRequestID(id) || seen[id] {
			t.Fatalf("NewRequestID %q %v", id, err)
		}
		seen[id] = true
	}
}

// T07-03 (K-DID-1..2).
func TestT07_03_DerivedRequestID(t *testing.T) {
	d1, err := DerivedRequestID("00112233445566778899aabbccddeeff")
	if err != nil || d1 != "1f0d61013abef39098ffb0a7c72008a17099c52aca3d5ee8d6ce8de065db5d37" {
		t.Fatalf("K-DID-1 %s %v", d1, err)
	}
	if d2, _ := DerivedRequestID(d1); d2 != "c4c6d6c4893cca6283c95ea32a0b6bef6be796804e62e21e30113b63c676457e" {
		t.Errorf("K-DID-2 %s", d2)
	}
	if _, err := DerivedRequestID("XYZ"); err == nil {
		t.Error("an invalid id derived")
	}
}

// T11-03, T07-04, T07-05, T07-06 (K-DL-1).
func TestT07_04_Deadlines(t *testing.T) {
	const T, H = int64(1720000000), int64(300)
	for deadline, want := range map[int64]error{T + 300: nil, T: nil, T + 301: ErrDeadlineTooFar, T - 1: ErrDeadlinePassed, 0: ErrDeadlineMissing} {
		if err := CheckDeadline(deadline, T, H); !errors.Is(err, want) {
			t.Errorf("deadline %d: %v, want %v", deadline-T, err, want)
		}
	}
	if err := CheckDeadline(T+10, T, 59); !errors.Is(err, ErrHorizonUnusable) {
		t.Errorf("H 59: %v", err)
	}
	// A client 30 s ahead setting client+300 is too far for the Hub; client+120 fits.
	if err := CheckDeadline(T+30+300, T, H); !errors.Is(err, ErrDeadlineTooFar) {
		t.Errorf("skew 300: %v", err)
	}
	if err := CheckDeadline(T+30+120, T, H); err != nil {
		t.Errorf("skew 120: %v", err)
	}
	if !CommitAllowed(T, T) || CommitAllowed(T, T+1) {
		t.Error("CommitAllowed")
	}
	for h, w := range map[int64]int64{60: 30, 120: 60, 300: 60, 86401: 60} {
		if DeadlineWindow(h) != w {
			t.Errorf("DeadlineWindow(%d) = %d", h, DeadlineWindow(h))
		}
	}
}

// E-LK-03, T07-07..T07-12 (K-LK-1..7, K-JLK-1).
func TestT07_07_DecideLookup(t *testing.T) {
	const D, H = int64(1720000000), int64(300)
	for now, want := range map[int64]LookupDecision{
		D:       {LookupPending, D + 1},
		D + 1:   {LookupUnknown, 0},
		D + 300: {LookupUnknown, 0},
		D + 301: {LookupExpired, 0},
	} {
		if got := DecideLookup(LookupInput{Now: now, Deadline: D, Horizon: H}); got != want {
			t.Errorf("now D%+d: %+v, want %+v", now-D, got, want)
		}
	}
	if got := DecideLookup(LookupInput{Now: D + 9999, Deadline: D, Horizon: H, HaveRecord: true}); got.Status != LookupDone {
		t.Errorf("record: %+v", got)
	}
	now := D
	if got := DecideLookup(LookupInput{Now: now, Deadline: now + 10000, Horizon: H}); got != (LookupDecision{LookupPending, now + 301}) {
		t.Errorf("K-LK-6: %+v", got)
	}
	if got := DecideLookup(LookupInput{Now: D - 100, Deadline: D - 200, Horizon: H}); got.Status != LookupUnknown {
		t.Errorf("T07-09: %+v", got)
	}
	if got := DecideLookup(LookupInput{Now: D + 450, Deadline: D, Horizon: 600}); got.Status != LookupUnknown {
		t.Errorf("K-LK-7: %+v", got)
	}
	const J = int64(1720000000)
	for now, want := range map[int64]LookupStatus{J + 300: LookupPending, J + 301: LookupUnknown, J + 660: LookupUnknown, J + 661: LookupExpired} {
		got := DecideLookup(LookupInput{Now: now, Deadline: J + 300, Horizon: H, Join: true})
		if got.Status != want {
			t.Errorf("join J%+d: %+v", now-J, got)
		}
	}
	if got := DecideLookup(LookupInput{Now: J + 300, Deadline: J + 300, Join: true}); got.RetryAfter != J+301 {
		t.Errorf("K-JLK-1 retry %d", got.RetryAfter)
	}
	if got := DecideLookup(LookupInput{Now: J, Deadline: J + 1000, Join: true}); got.RetryAfter != J+361 {
		t.Errorf("join deadline now+1000: retry %d", got.RetryAfter)
	}
	if !RecordRetained(D+H, D, H) || RecordRetained(D+H+1, D, H) {
		t.Error("RecordRetained")
	}
	// No path answers unknown once the record may be dropped.
	if DecideLookup(LookupInput{Now: D + H + 1, Deadline: D, Horizon: H}).Status == LookupUnknown {
		t.Error("unknown after the drop point")
	}
}

// T07-13, T07-14.
func TestT07_13_TombstoneAndSlice(t *testing.T) {
	const R = int64(1720000000)
	if !TombstoneAnswerable(R, R) || TombstoneAnswerable(R+1, R) {
		t.Error("TombstoneAnswerable")
	}
	e, zero := R, int64(0)
	if !SliceLive(R, &e) || SliceLive(R+1, &e) || !SliceLive(R*2, nil) || !SliceLive(R*2, &zero) {
		t.Error("SliceLive")
	}
}

// T07-15, T07-18.
func TestT07_15_Codes(t *testing.T) {
	retry := map[string]bool{
		ErrCodeBadRequest: false, ErrCodeRequestReused: false, ErrCodeRestricted: false, ErrCodeUnauthorized: true,
		ErrCodeInsufficientBalance: true, ErrCodeQuotaExceeded: true, ErrCodeRateLimited: true, ErrCodeNotFound: false,
		ErrCodeNotImplemented: false, ErrCodePaymentFailed: true, ErrCodeInternal: true,
	}
	for code, want := range retry {
		if CodeRetryable(code) != want {
			t.Errorf("CodeRetryable(%s)", code)
		}
		if FinalCode(code) != (code == "BAD_REQUEST") {
			t.Errorf("FinalCode(%s)", code)
		}
	}
	if ErrCodeRequestReused != "REQUEST_REUSED" || ErrCodeQuotaExceeded != "QUOTA_EXCEEDED" {
		t.Error("code spelling")
	}
}
