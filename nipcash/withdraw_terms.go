package nipcash

import (
	"errors"
	"fmt"
)

// WithdrawTerms is cash_status' withdraw object: a Hub's current on-chain
// withdrawal terms, for display (only a quote fixes a payout).
type WithdrawTerms struct {
	FeeBase     uint64   `json:"withdraw_fee_base"`
	FeePpm      uint64   `json:"withdraw_fee_ppm"`
	MinMillis   *uint64  `json:"min_millis,omitempty"`
	MaxMillis   *uint64  `json:"max_millis,omitempty"`
	ScriptTypes [][2]int `json:"script_types"`
	FinalDepth  int      `json:"final_depth"`
}

// Validate checks the terms: ppm ≤ 1,000,000; min ≤ max; every script type a
// witness version 0 to 16 with a program of 20 or 32 bytes for version 0 and 2
// to 40 otherwise; a final depth of at least 1.
func (w WithdrawTerms) Validate() error {
	if w.FeePpm > 1_000_000 {
		return fmt.Errorf("%w: withdraw_fee_ppm %d", ErrFeeRate, w.FeePpm)
	}
	if w.MinMillis != nil && w.MaxMillis != nil && *w.MinMillis > *w.MaxMillis {
		return errors.New("nipcash: min_millis exceeds max_millis")
	}
	if len(w.ScriptTypes) == 0 {
		return errors.New("nipcash: script_types lists no script type")
	}
	for _, st := range w.ScriptTypes {
		v, n := st[0], st[1]
		switch {
		case v < 0 || v > 16:
			return fmt.Errorf("nipcash: witness version %d", v)
		case v == 0 && n != 20 && n != 32:
			return fmt.Errorf("nipcash: a version-0 program is 20 or 32 bytes, not %d", n)
		case n < 2 || n > 40:
			return fmt.Errorf("nipcash: a witness program is 2 to 40 bytes, not %d", n)
		}
	}
	if w.FinalDepth < 1 {
		return errors.New("nipcash: final_depth is at least 1")
	}
	return nil
}
