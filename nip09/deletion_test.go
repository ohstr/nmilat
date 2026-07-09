package nip09

import (
	"testing"
)

func TestIsDeletionKind(t *testing.T) {
	tests := []struct {
		name string
		kind int
		want bool
	}{
		{
			name: "deletion kind",
			kind: 5,
			want: true,
		},
		{
			name: "text note kind",
			kind: 1,
			want: false,
		},
		{
			name: "metadata kind",
			kind: 0,
			want: false,
		},
		{
			name: "random kind",
			kind: 12345,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDeletionKind(tt.kind); got != tt.want {
				t.Errorf("IsDeletionKind() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	if KindDeletion != 5 {
		t.Errorf("KindDeletion constant = %d, want 5", KindDeletion)
	}
}
