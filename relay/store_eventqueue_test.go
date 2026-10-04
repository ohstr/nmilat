package relay

import (
	"container/heap"
	"testing"
)

// eventQueue.Less used to compare CreatedAt only. container/heap gives no
// stable order among equal-priority elements, so a tie on CreatedAt meant
// AddEvent/Pop could return the tied events in whatever order the heap's
// internal swaps happened to produce -- not newest-arrival-first, and not
// even consistent from one run to the next for the same input. Evsid is
// the one value every event has distinctly, so it is what breaks the tie.
func TestEventQueuePopOrdersTiedCreatedAtByEvsidDescending(t *testing.T) {
	eq := newEventQueue()

	// Pushed deliberately out of evsid order, so a correct pop order can
	// only come from Less's own tie-break, not from insertion order.
	for _, evsid := range []uint64{3, 1, 5, 2, 4} {
		eq.AddEvent(&PotentialEvent{Evsid: evsid, CreatedAt: 1000})
	}

	want := []uint64{5, 4, 3, 2, 1}
	for i, w := range want {
		if eq.Len() == 0 {
			t.Fatalf("queue exhausted early at index %d, want evsid %d", i, w)
		}
		got := heap.Pop(eq).(*PotentialEvent)
		if got.Evsid != w {
			t.Fatalf("pop %d: got evsid %d, want %d", i, got.Evsid, w)
		}
	}
}
