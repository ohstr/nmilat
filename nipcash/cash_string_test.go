package nipcash

import "testing"

func TestSplitCashSliceString(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantToken  string
		wantSecret string
	}{
		{"no hash: identity-bound or separately-presented token", "lokicash1abc", "lokicash1abc", ""},
		{"combined presentation: token and secret", "lokicash1abc#deadbeef", "lokicash1abc", "deadbeef"},
		{"only the first hash matters", "lokicash1abc#dead#beef", "lokicash1abc", "dead#beef"},
		{"empty string", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, gotSecret := SplitCashSliceString(tt.in)
			if gotToken != tt.wantToken || gotSecret != tt.wantSecret {
				t.Errorf("SplitCashSliceString(%q) = (%q, %q), want (%q, %q)", tt.in, gotToken, gotSecret, tt.wantToken, tt.wantSecret)
			}
		})
	}
}
