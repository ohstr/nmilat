package nip77

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestVarintEncoding(t *testing.T) {
	tests := []struct {
		val uint64
		hex string
	}{
		{0, "00"},
		{1, "01"},
		{127, "7f"},
		{128, "8100"},
		{255, "817f"},
		{16383, "ff7f"},
		{16384, "818000"},
	}

	for _, tc := range tests {
		encoded := encodeVarint(tc.val)
		hexStr := hex.EncodeToString(encoded)
		if hexStr != tc.hex {
			t.Errorf("encodeVarint(%d) = %s, want %s", tc.val, hexStr, tc.hex)
		}

		decoded, err := decodeReaderVarint(bytes.NewReader(encoded))
		if err != nil {
			t.Errorf("decodeReaderVarint(%s) error: %v", hexStr, err)
		}
		if decoded != tc.val {
			t.Errorf("decodeReaderVarint(%s) = %d, want %d", hexStr, decoded, tc.val)
		}
	}
}

func TestItemIsBeforeBound(t *testing.T) {
	// Bounds are exclusive upper bounds.
	// item < bound?

	// T=10, Bound=11 -> True
	b11 := Bound{Timestamp: 11}
	i10 := Item{Timestamp: 10}
	if !ItemIsBeforeBound(i10, b11) {
		t.Error("10 should be before 11")
	}

	// T=11, Bound=11 -> False
	i11 := Item{Timestamp: 11}
	if ItemIsBeforeBound(i11, b11) {
		t.Error("11 should NOT be before 11 (exclusive)")
	}

	// T=10, Bound=10+Prefix(A)
	b10A := Bound{Timestamp: 10, IDPrefix: []byte{0xAA}}

	// Item T=10, ID=0x00... -> Before
	i10_00 := Item{Timestamp: 10} // ID is all zeros
	if !ItemIsBeforeBound(i10_00, b10A) {
		t.Error("10:00... should be before 10:AA...")
	}

	// Item T=10, ID=0xAA... -> Not Before (Equal prefix means >= bound, since bound is strict prefix?)
	// Logic: 0xAA (item) vs 0xAA (bound). Loop finishes. logic returns false. Correct.
	i10_AA := Item{Timestamp: 10}
	i10_AA.ID[0] = 0xAA
	if ItemIsBeforeBound(i10_AA, b10A) {
		t.Error("10:AA... should NOT be before 10:AA...")
	}

	// Item T=10, ID=0xBB... -> Not Before
	i10_BB := Item{Timestamp: 10}
	i10_BB.ID[0] = 0xBB
	if ItemIsBeforeBound(i10_BB, b10A) {
		t.Error("10:BB... should NOT be before 10:AA...")
	}
}

func TestReconcile_Match(t *testing.T) {
	// Setup items
	items := []Item{
		{Timestamp: 100, ID: [32]byte{1}},
		{Timestamp: 200, ID: [32]byte{2}},
	}
	neg := New(items)

	// Simulate message from someone with SAME items
	// They send range (Infinity, Fingerprint(items))
	fp := computeFingerprint(items)

	msg := &Message{
		ProtocolVersion: ProtocolVersion1,
		Ranges: []Range{
			{
				UpperBound: Bound{Timestamp: InfiniteTimestamp},
				Mode:       1, // Fingerprint
				Payload:    fp,
			},
		},
	}

	resp, have, need, err := neg.Reconcile(msg)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	if len(have) != 0 || len(need) != 0 {
		t.Errorf("Expected match (skip), got diffs: have=%d need=%d", len(have), len(need))
	}

	if len(resp.Ranges) != 1 {
		t.Fatalf("Expected 1 range response, got %d", len(resp.Ranges))
	}

	if resp.Ranges[0].Mode != 0 {
		t.Errorf("Expected Skip (0) mode, got %d", resp.Ranges[0].Mode)
	}
}

func TestReconcile_Mismatch(t *testing.T) {
	// We have 1 item. They have 0.
	items := []Item{
		{Timestamp: 100, ID: [32]byte{1}},
	}
	neg := New(items)

	// They send (Inf, Fingerprint(Empty))
	fpEmpty := computeFingerprint([]Item{})

	msg := &Message{
		ProtocolVersion: ProtocolVersion1,
		Ranges: []Range{
			{
				UpperBound: Bound{Timestamp: InfiniteTimestamp},
				Mode:       1,
				Payload:    fpEmpty,
			},
		},
	}

	resp, _, _, err := neg.Reconcile(msg)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}

	// We expect since len(n.Items) < 100, we send IdList
	if len(resp.Ranges) != 1 {
		t.Fatalf("Expected 1 range response, got %d", len(resp.Ranges))
	}

	if resp.Ranges[0].Mode != 2 {
		t.Errorf("Expected IdList (2) mode, got %d", resp.Ranges[0].Mode)
	}

	// Check payload
	decoded, err := decodeIdList(resp.Ranges[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Errorf("Expected 1 ID in list, got %d", len(decoded))
	}

	expectedID := hex.EncodeToString(items[0].ID[:])
	if decoded[0] != expectedID {
		t.Errorf("Expected ID %s, got %s", expectedID, decoded[0])
	}
}
