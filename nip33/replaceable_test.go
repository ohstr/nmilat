package nip33

import "testing"

func TestIsParamReplaceableKind(t *testing.T) {
	tests := []struct {
		name string
		kind int
		want bool
	}{
		{"Kind 30000 (Lower Bound)", 30000, true},
		{"Kind 35000 (Mid Bound)", 35000, true},
		{"Kind 39999 (Upper Bound)", 39999, true},
		{"Kind 40000 (Out of Bound)", 40000, false},
		{"Kind 29999 (Out of Bound)", 29999, false},
		{"Kind 1 (Text Note)", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsParamReplaceableKind(tt.kind); got != tt.want {
				t.Errorf("IsParamReplaceableKind(%d) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}
