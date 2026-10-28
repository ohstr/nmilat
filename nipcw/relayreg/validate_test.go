package relayreg

import (
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcw"
)

// T17-02 (S-CW-44): a follow set dated now+900 is accepted, now+901 refused;
// other kinds are not looked at.
func TestValidateFollowSetFuture(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	at := func(kind int, d int64) *nip01.Event {
		return &nip01.Event{Kind: kind, CreatedAt: uint64(now.Unix() + d)}
	}
	if err := validate(at(nipcw.KindFollowSet, 900), now); err != nil {
		t.Fatalf("now+900: %v", err)
	}
	if err := validate(at(nipcw.KindFollowSet, -86400), now); err != nil {
		t.Fatalf("a day old: %v", err)
	}
	if err := validate(at(nipcw.KindFollowSet, 901), now); !errors.Is(err, ErrFutureFollowSet) {
		t.Fatalf("now+901: %v", err)
	}
	if err := validate(at(30001, 3600), now); err != nil {
		t.Fatalf("kind 30001: %v", err)
	}
}
