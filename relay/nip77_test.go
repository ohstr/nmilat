package relay

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip77"
	"github.com/ohstr/nmilat/wire"
)

func TestNegOpenPacket_Integration(t *testing.T) {
	// 1. Setup Store
	store := newStore(t)
	defer store.Close()

	// 2. Insert Events
	// 10 events, kind 1. Timestamps: Now, Now-10, Now-20...
	events := []*nip01.Event{}
	now := uint64(time.Now().Unix())
	for i := 0; i < 10; i++ {
		events = append(events, CreateEventWithTimestamp(t, 1, now-uint64(i*10)))
	}
	InsertTestEvents(t, store, events)

	// 3. Setup Session
	// replyer and store are in SessionContext
	replyer := &replyer{
		incoming: make(chan wire.SubscriptionResponse, 100),
		closeCh:  make(chan interface{}),
	}
	session := &Session{
		SessionContext: &SessionContext{
			store:   store,
			replyer: replyer,
		},
		negentropySessions: make(map[string]*nip77.Negentropy),
	}
	ctx := context.WithValue(context.Background(), sessionContextKey{}, session)

	// 4. Create NEG-OPEN packet
	filter := &nip01.SubscriptionFilter{
		Kinds: []int{1},
	}

	// Client has nothing
	emptyMsg := &nip77.Message{
		ProtocolVersion: nip77.ProtocolVersion1,
		Ranges:          []nip77.Range{},
	}
	emptyMsgHex, err := emptyMsg.ToHex()
	if err != nil {
		t.Fatalf("Failed to encode empty msg: %v", err)
	}

	packet := &wire.NegOpenPacket{
		SubscriptionID: "sub1",
		Filter:         filter,
		Message:        emptyMsgHex,
	}

	// 5. Call ProcessPacket
	err = session.ProcessPacket(ctx, packet)
	if err != nil {
		t.Fatalf("ProcessPacket failed: %v", err)
	}

	// 6. Check response
	select {
	case resp := <-session.incoming:
		// We expect NegMsgPacket
		msgPacket, ok := resp.(*wire.NegMsgPacket)
		if !ok {
			// Check if it's NegErrPacket
			if errPacket, ok := resp.(*wire.NegErrPacket); ok {
				t.Fatalf("Got NEG-ERR: %s", errPacket.Code)
			}
			t.Fatalf("Unexpected response type: %T", resp)
		}

		t.Logf("Got NEG-MSG: %s", msgPacket.Message)

		// Parse the response
		respMsg, err := nip77.FromHex(msgPacket.Message)
		if err != nil {
			t.Fatalf("Failed to parse response msg: %v", err)
		}

		if len(respMsg.Ranges) == 0 {
			t.Log("Got empty ranges in response (expected if input was empty ranges)")
		} else {
			t.Logf("Got %d ranges", len(respMsg.Ranges))
		}

	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for response")
	}

	// 7. Verification of Session
	session.negMu.Lock()
	neg, exists := session.negentropySessions["sub1"]
	session.negMu.Unlock()

	if !exists {
		t.Fatal("Session should have negentropy object")
	}
	if len(neg.Items) != 10 {
		t.Errorf("Negentropy should have 10 items, got %d", len(neg.Items))
	}
}
