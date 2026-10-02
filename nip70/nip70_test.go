package nip70

import "testing"

func TestIsProtected(t *testing.T) {
	tests := []struct {
		name string
		tags [][]string
		want bool
	}{
		{"the bare marker", [][]string{{"-"}}, true},
		{"alongside other tags", [][]string{{"p", "abc"}, {"-"}}, true},
		// A value after the marker is not part of the spec, so it must not be a
		// way to carry a protected event past a relay that only looks for the
		// exact one-element tag.
		{"padded marker still protects", [][]string{{"-", "x"}}, true},
		{"no tags", nil, false},
		{"no marker", [][]string{{"p", "abc"}, {"e", "def"}}, false},
		{"empty tag", [][]string{{}}, false},
		{"a tag merely containing a dash", [][]string{{"d", "-"}}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsProtected(tc.tags); got != tc.want {
				t.Fatalf("IsProtected(%v) = %v, want %v", tc.tags, got, tc.want)
			}
		})
	}
}
