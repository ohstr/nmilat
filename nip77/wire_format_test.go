package nip77

import (
	"fmt"
	"sort"
	"testing"
)

// TestReconcileWireFormat runs the full client-server reconciliation through
// hex encoding/decoding between each step — exactly like the real wire protocol.
// This exposes any bugs in ToHex/FromHex that the in-memory tests miss.
func TestReconcileWireFormat(t *testing.T) {
	tests := []struct {
		name             string
		clientTimestamps []uint64
		serverTimestamps []uint64
		expectNeed       int
		expectHave       int
	}{
		{
			name:             "both empty",
			clientTimestamps: []uint64{},
			serverTimestamps: []uint64{},
			expectNeed:       0,
			expectHave:       0,
		},
		{
			name:             "identical 3 items",
			clientTimestamps: []uint64{100, 200, 300},
			serverTimestamps: []uint64{100, 200, 300},
			expectNeed:       0,
			expectHave:       0,
		},
		{
			name:             "client empty, server has 3",
			clientTimestamps: []uint64{},
			serverTimestamps: []uint64{100, 200, 300},
			expectNeed:       3,
			expectHave:       0,
		},
		{
			name:             "server empty, client has 3",
			clientTimestamps: []uint64{100, 200, 300},
			serverTimestamps: []uint64{},
			expectNeed:       0,
			expectHave:       3,
		},
		{
			name:             "partial overlap",
			clientTimestamps: []uint64{100, 200, 300},
			serverTimestamps: []uint64{200, 300, 400},
			expectNeed:       1,
			expectHave:       1,
		},
		{
			name:             "disjoint",
			clientTimestamps: []uint64{100, 200},
			serverTimestamps: []uint64{300, 400},
			expectNeed:       2,
			expectHave:       2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientItems := tsToItems(tc.clientTimestamps)
			serverItems := tsToItems(tc.serverTimestamps)

			clientNeg := New(clientItems)
			serverNeg := New(serverItems)

			// Client initiates (sets IsInitiator=true)
			initMsg := clientNeg.Initiate()

			// Encode to hex (simulates wire transmission)
			wireHex, err := initMsg.ToHex()
			if err != nil {
				t.Fatalf("client ToHex: %v", err)
			}
			t.Logf("Init msg: %d hex chars (%d bytes)", len(wireHex), len(wireHex)/2)

			// Decode on server side
			serverReceived, err := FromHex(wireHex)
			if err != nil {
				t.Fatalf("server FromHex: %v", err)
			}

			var totalNeed, totalHave []string

			for round := 0; round < 20; round++ {
				// Server reconciles
				serverResp, _, _, err := serverNeg.Reconcile(serverReceived)
				if err != nil {
					t.Fatalf("round %d server Reconcile: %v", round, err)
				}

				// Log server response details
				for i, r := range serverResp.Ranges {
					t.Logf("  round %d server range[%d]: mode=%d, payload=%d bytes, bound.ts=%d, bound.prefix=%d bytes",
						round, i, r.Mode, len(r.Payload), r.UpperBound.Timestamp, len(r.UpperBound.IDPrefix))
				}

				// Encode server response to hex
				serverHex, err := serverResp.ToHex()
				if err != nil {
					t.Fatalf("round %d server ToHex: %v", round, err)
				}

				// Decode on client side
				clientReceived, err := FromHex(serverHex)
				if err != nil {
					t.Fatalf("round %d client FromHex: %v", round, err)
				}

				// Verify decoded matches original
				if len(clientReceived.Ranges) != len(serverResp.Ranges) {
					t.Fatalf("round %d: decode lost ranges! sent=%d, received=%d",
						round, len(serverResp.Ranges), len(clientReceived.Ranges))
				}
				for i := range clientReceived.Ranges {
					if clientReceived.Ranges[i].Mode != serverResp.Ranges[i].Mode {
						t.Errorf("round %d range[%d]: mode mismatch! sent=%d, received=%d",
							round, i, serverResp.Ranges[i].Mode, clientReceived.Ranges[i].Mode)
					}
				}

				// Client reconciles
				clientResp, roundHave, roundNeed, err := clientNeg.Reconcile(clientReceived)
				if err != nil {
					t.Fatalf("round %d client Reconcile: %v", round, err)
				}

				totalHave = append(totalHave, roundHave...)
				totalNeed = append(totalNeed, roundNeed...)

				t.Logf("round %d: have=%d, need=%d, total_need=%d, total_have=%d",
					round+1, len(roundHave), len(roundNeed), len(totalNeed), len(totalHave))

				// Check convergence
				if IsComplete(clientResp) {
					t.Logf("converged after %d rounds", round+1)
					break
				}

				// Log client response details
				for i, r := range clientResp.Ranges {
					t.Logf("  round %d client range[%d]: mode=%d, payload=%d bytes",
						round, i, r.Mode, len(r.Payload))
				}

				// Encode client response to hex
				clientHex, err := clientResp.ToHex()
				if err != nil {
					t.Fatalf("round %d client ToHex: %v", round, err)
				}

				// Decode on server side for next round
				serverReceived, err = FromHex(clientHex)
				if err != nil {
					t.Fatalf("round %d server FromHex: %v", round, err)
				}
			}

			if len(totalNeed) != tc.expectNeed {
				t.Errorf("need: got %d, want %d", len(totalNeed), tc.expectNeed)
			}
			if len(totalHave) != tc.expectHave {
				t.Errorf("have: got %d, want %d", len(totalHave), tc.expectHave)
			}
		})
	}
}

// TestEncodeDecodeRangeTypes tests roundtrip encoding for each range mode.
func TestEncodeDecodeRangeTypes(t *testing.T) {
	t.Run("Skip range", func(t *testing.T) {
		msg := &Message{
			ProtocolVersion: ProtocolVersion1,
			Ranges: []Range{
				{
					UpperBound: Bound{Timestamp: InfiniteTimestamp},
					Mode:       0,
				},
			},
		}
		roundtrip(t, msg)
	})

	t.Run("Fingerprint range", func(t *testing.T) {
		items := tsToItems([]uint64{100, 200, 300})
		fp := computeFingerprint(items)

		msg := &Message{
			ProtocolVersion: ProtocolVersion1,
			Ranges: []Range{
				{
					UpperBound: Bound{Timestamp: InfiniteTimestamp},
					Mode:       1,
					Payload:    fp,
				},
			},
		}
		roundtrip(t, msg)
	})

	t.Run("IdList range", func(t *testing.T) {
		items := tsToItems([]uint64{100, 200, 300})
		payload, err := encodeIdList(items)
		if err != nil {
			t.Fatal(err)
		}

		msg := &Message{
			ProtocolVersion: ProtocolVersion1,
			Ranges: []Range{
				{
					UpperBound: Bound{Timestamp: InfiniteTimestamp},
					Mode:       2,
					Payload:    payload,
				},
			},
		}
		roundtrip(t, msg)
	})

	t.Run("Multiple ranges with split bound", func(t *testing.T) {
		items := tsToItems([]uint64{100, 200})
		fp1 := computeFingerprint(items[:1])
		fp2 := computeFingerprint(items[1:])

		msg := &Message{
			ProtocolVersion: ProtocolVersion1,
			Ranges: []Range{
				{
					UpperBound: Bound{Timestamp: 150, IDPrefix: []byte{0xAA, 0xBB}},
					Mode:       1,
					Payload:    fp1,
				},
				{
					UpperBound: Bound{Timestamp: InfiniteTimestamp},
					Mode:       1,
					Payload:    fp2,
				},
			},
		}
		roundtrip(t, msg)
	})

	t.Run("Fingerprint with empty payload check", func(t *testing.T) {
		// Empty items fingerprint
		fp := computeFingerprint([]Item{})
		t.Logf("Empty fingerprint: %x (%d bytes)", fp, len(fp))

		if len(fp) != 16 {
			t.Errorf("fingerprint should be 16 bytes, got %d", len(fp))
		}

		msg := &Message{
			ProtocolVersion: ProtocolVersion1,
			Ranges: []Range{
				{
					UpperBound: Bound{Timestamp: InfiniteTimestamp},
					Mode:       1,
					Payload:    fp,
				},
			},
		}
		roundtrip(t, msg)
	})
}

func roundtrip(t *testing.T, msg *Message) {
	t.Helper()

	hex1, err := msg.ToHex()
	if err != nil {
		t.Fatalf("ToHex: %v", err)
	}

	decoded, err := FromHex(hex1)
	if err != nil {
		t.Fatalf("FromHex: %v", err)
	}

	if decoded.ProtocolVersion != msg.ProtocolVersion {
		t.Errorf("version: got %x, want %x", decoded.ProtocolVersion, msg.ProtocolVersion)
	}

	if len(decoded.Ranges) != len(msg.Ranges) {
		t.Fatalf("ranges: got %d, want %d", len(decoded.Ranges), len(msg.Ranges))
	}

	for i := range msg.Ranges {
		orig := msg.Ranges[i]
		got := decoded.Ranges[i]

		if got.Mode != orig.Mode {
			t.Errorf("range[%d] mode: got %d, want %d", i, got.Mode, orig.Mode)
		}
		if got.UpperBound.Timestamp != orig.UpperBound.Timestamp {
			t.Errorf("range[%d] timestamp: got %d, want %d", i, got.UpperBound.Timestamp, orig.UpperBound.Timestamp)
		}
		if len(got.Payload) != len(orig.Payload) {
			t.Errorf("range[%d] payload len: got %d, want %d", i, len(got.Payload), len(orig.Payload))
		}
	}

	// Re-encode and compare
	hex2, err := decoded.ToHex()
	if err != nil {
		t.Fatalf("re-encode ToHex: %v", err)
	}

	if hex1 != hex2 {
		t.Errorf("roundtrip hex mismatch!\n  original: %s\n  re-encoded: %s", hex1, hex2)
	}
}

func tsToItems(timestamps []uint64) []Item {
	items := make([]Item, len(timestamps))
	for i, ts := range timestamps {
		items[i] = Item{Timestamp: ts}
		b := []byte(fmt.Sprintf("%016x", ts))
		copy(items[i].ID[:], b)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Compare(items[j]) < 0
	})
	return items
}
