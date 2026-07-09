package nip16

import "testing"

func TestIsReplaceableKind(t *testing.T) {
	tests := []struct {
		name string
		kind int
		want bool
	}{
		{"Kind 0 (Metadata)", 0, true},
		{"Kind 3 (Contact List)", 3, true},
		{"Kind 10000 (Lower Bound)", 10000, true},
		{"Kind 15000 (Mid Bound)", 15000, true},
		{"Kind 19999 (Upper Bound)", 19999, true},
		{"Kind 20000 (Out of Bound)", 20000, false},
		{"Kind 9999 (Out of Bound)", 9999, false},
		{"Kind 1 (Text Note)", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsReplaceableKind(tt.kind); got != tt.want {
				t.Errorf("IsReplaceableKind(%d) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}

func TestIsEphemeralKind(t *testing.T) {
	tests := []struct {
		name string
		kind int
		want bool
	}{
		{"Kind 20000 (Lower Bound)", 20000, true},
		{"Kind 25000 (Mid Bound)", 25000, true},
		{"Kind 29999 (Upper Bound)", 29999, true},
		{"Kind 30000 (Out of Bound)", 30000, false},
		{"Kind 19999 (Out of Bound)", 19999, false},
		{"Kind 1 (Text Note)", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEphemeralKind(tt.kind); got != tt.want {
				t.Errorf("IsEphemeralKind(%d) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}
