package nip34

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

const testPrivKey = "48939ec93986b59b58d7206887b42ff74d99dd3258782e2fdfd720eb74d547a5"

func signed(t *testing.T, ev *nip01.Event) *nip01.Event {
	t.Helper()
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return ev
}

var (
	ownerPubkey     = strings.Repeat("a", 64)
	maintainer      = strings.Repeat("b", 64)
	otherUserPubkey = strings.Repeat("c", 64)
	someEventID     = strings.Repeat("d", 64)
	someEventID2    = strings.Repeat("e", 64)
)

func testRepoAddress(t *testing.T) string {
	t.Helper()
	return "30617:" + ownerPubkey + ":ngit"
}

func TestIsStatusKind(t *testing.T) {
	for _, k := range []int{KindStatusOpen, KindStatusApplied, KindStatusClosed, KindStatusDraft} {
		if !IsStatusKind(k) {
			t.Errorf("IsStatusKind(%d) = false, want true", k)
		}
	}
	for _, k := range []int{0, 1617, 1620, 1634, 30617} {
		if IsStatusKind(k) {
			t.Errorf("IsStatusKind(%d) = true, want false", k)
		}
	}
}
