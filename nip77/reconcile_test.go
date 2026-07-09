package nip77

import (
	"fmt"
	"testing"
)

// TestReconcileMatrix is a table-driven test covering different Negentropy reconciliation scenarios.
func TestReconcileMatrix(t *testing.T) {
	// Helper to build items from simple timestamps
	makeItems := func(timestamps ...uint64) []Item {
		items := make([]Item, len(timestamps))
		for i, ts := range timestamps {
			items[i] = Item{Timestamp: ts}
			// Deterministic ID derived from timestamp so same timestamp = same item
			b := []byte(fmt.Sprintf("%016x", ts))
			copy(items[i].ID[:], b)
		}
		return items
	}

	tests := []struct {
		name string

		// Setup
		clientItems []Item // items the client (initiator) has
		serverItems []Item // items the server (responder) has

		// Expectations after full reconciliation
		expectClientNeed int // IDs client needs (server has, client doesn't)
		expectClientHave int // IDs client has (server doesn't)
		expectConverge   bool
		maxRounds        int
	}{
		{
			name:             "both empty",
			clientItems:      []Item{},
			serverItems:      []Item{},
			expectClientNeed: 0,
			expectClientHave: 0,
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "identical sets",
			clientItems:      makeItems(100, 200, 300),
			serverItems:      makeItems(100, 200, 300),
			expectClientNeed: 0,
			expectClientHave: 0,
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "client empty, server has items",
			clientItems:      []Item{},
			serverItems:      makeItems(100, 200, 300),
			expectClientNeed: 3,
			expectClientHave: 0,
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "server empty, client has items",
			clientItems:      makeItems(100, 200, 300),
			serverItems:      []Item{},
			expectClientNeed: 0,
			expectClientHave: 3,
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "partial overlap",
			clientItems:      makeItems(100, 200, 300),
			serverItems:      makeItems(200, 300, 400),
			expectClientNeed: 1, // 400
			expectClientHave: 1, // 100
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "disjoint sets",
			clientItems:      makeItems(100, 200),
			serverItems:      makeItems(300, 400),
			expectClientNeed: 2, // 300, 400
			expectClientHave: 2, // 100, 200
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "single item each, different",
			clientItems:      makeItems(100),
			serverItems:      makeItems(200),
			expectClientNeed: 1,
			expectClientHave: 1,
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "single item each, same",
			clientItems:      makeItems(100),
			serverItems:      makeItems(100),
			expectClientNeed: 0,
			expectClientHave: 0,
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "client subset of server",
			clientItems:      makeItems(200, 300),
			serverItems:      makeItems(100, 200, 300, 400, 500),
			expectClientNeed: 3, // 100, 400, 500
			expectClientHave: 0,
			expectConverge:   true,
			maxRounds:        5,
		},
		{
			name:             "server subset of client",
			clientItems:      makeItems(100, 200, 300, 400, 500),
			serverItems:      makeItems(200, 300),
			expectClientNeed: 0,
			expectClientHave: 3, // 100, 400, 500
			expectConverge:   true,
			maxRounds:        5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientNeg := New(tc.clientItems)
			serverNeg := New(tc.serverItems)

			// Client initiates
			clientMsg := clientNeg.Initiate()

			var totalClientHave, totalClientNeed []string
			converged := false

			for round := 0; round < tc.maxRounds; round++ {
				// Server processes client's message
				serverResp, _, _, err := serverNeg.Reconcile(clientMsg)
				if err != nil {
					t.Fatalf("round %d: server Reconcile error: %v", round, err)
				}

				// Client processes server's response
				clientResp, roundHave, roundNeed, err := clientNeg.Reconcile(serverResp)
				if err != nil {
					t.Fatalf("round %d: client Reconcile error: %v", round, err)
				}

				totalClientHave = append(totalClientHave, roundHave...)
				totalClientNeed = append(totalClientNeed, roundNeed...)

				// Check convergence
				if IsComplete(clientResp) {
					converged = true
					t.Logf("converged after %d rounds", round+1)
					break
				}

				// Next round
				clientMsg = clientResp
			}

			if tc.expectConverge && !converged {
				t.Errorf("expected convergence within %d rounds, did not converge", tc.maxRounds)
			}

			if len(totalClientNeed) != tc.expectClientNeed {
				t.Errorf("clientNeed: got %d, want %d (IDs: %v)", len(totalClientNeed), tc.expectClientNeed, totalClientNeed)
			}

			if len(totalClientHave) != tc.expectClientHave {
				t.Errorf("clientHave: got %d, want %d (IDs: %v)", len(totalClientHave), tc.expectClientHave, totalClientHave)
			}

			// Log details
			t.Logf("Result: need=%d, have=%d, converged=%v", len(totalClientNeed), len(totalClientHave), converged)
		})
	}
}

// TestReconcileIdListResponse verifies IdList response behavior for both roles.
func TestReconcileIdListResponse(t *testing.T) {
	items := makeTestItems(100, 200, 300)

	// Simulate receiving an IdList from the other party with items {200, 400}
	otherItem200 := Item{Timestamp: 200}
	otherItem200.ID[0] = 2
	otherItem200.ID[31] = 2
	otherItem400 := Item{Timestamp: 400}
	otherItem400.ID[0] = 10
	otherItem400.ID[31] = 10

	payload, err := encodeIdList([]Item{otherItem200, otherItem400})
	if err != nil {
		t.Fatal(err)
	}

	msg := &Message{
		ProtocolVersion: ProtocolVersion1,
		Ranges: []Range{
			{
				UpperBound: Bound{Timestamp: InfiniteTimestamp},
				Mode:       2, // IdList
				Payload:    payload,
			},
		},
	}

	t.Run("initiator responds with Skip", func(t *testing.T) {
		neg := New(items)
		neg.IsInitiator = true

		resp, have, need, err := neg.Reconcile(msg)
		if err != nil {
			t.Fatalf("Reconcile error: %v", err)
		}
		if len(resp.Ranges) != 1 {
			t.Fatalf("expected 1 range, got %d", len(resp.Ranges))
		}
		if resp.Ranges[0].Mode != 0 {
			t.Errorf("initiator should respond with Skip (mode 0), got mode %d", resp.Ranges[0].Mode)
		}
		if len(have) != 2 {
			t.Errorf("expected 2 have IDs, got %d", len(have))
		}
		if len(need) != 1 {
			t.Errorf("expected 1 need ID, got %d", len(need))
		}
	})

	t.Run("non-initiator responds with IdList", func(t *testing.T) {
		neg := New(items)
		neg.IsInitiator = false

		resp, have, need, err := neg.Reconcile(msg)
		if err != nil {
			t.Fatalf("Reconcile error: %v", err)
		}
		if len(resp.Ranges) != 1 {
			t.Fatalf("expected 1 range, got %d", len(resp.Ranges))
		}
		if resp.Ranges[0].Mode != 2 {
			t.Errorf("non-initiator should respond with IdList (mode 2), got mode %d", resp.Ranges[0].Mode)
		}
		if len(have) != 2 {
			t.Errorf("expected 2 have IDs, got %d", len(have))
		}
		if len(need) != 1 {
			t.Errorf("expected 1 need ID, got %d", len(need))
		}
	})
}

// TestReconcileEncodeDecode verifies message roundtrip through hex encoding.
func TestReconcileEncodeDecode(t *testing.T) {
	items := makeTestItems(100, 200, 300, 400, 500)
	neg := New(items)

	initMsg := neg.Initiate()
	hexStr, err := initMsg.ToHex()
	if err != nil {
		t.Fatalf("ToHex error: %v", err)
	}

	decoded, err := FromHex(hexStr)
	if err != nil {
		t.Fatalf("FromHex error: %v", err)
	}

	if decoded.ProtocolVersion != ProtocolVersion1 {
		t.Errorf("protocol version: got %x, want %x", decoded.ProtocolVersion, ProtocolVersion1)
	}

	if len(decoded.Ranges) != len(initMsg.Ranges) {
		t.Errorf("ranges count: got %d, want %d", len(decoded.Ranges), len(initMsg.Ranges))
	}
}

func makeTestItems(timestamps ...uint64) []Item {
	items := make([]Item, len(timestamps))
	for i, ts := range timestamps {
		items[i] = Item{Timestamp: ts}
		items[i].ID[0] = byte(i + 1)
		items[i].ID[31] = byte(i + 1)
	}
	return items
}
