package ranking

import (
	"testing"
)

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name        string
		inputName   string
		displayName string
		about       string
		nip05       string
		lud16       string
		picture     string
		expected    int64
	}{
		{
			name:      "Empty Shell",
			inputName: "", about: "", picture: "",
			expected: -500,
		},
		{
			name:      "Basic Identity",
			inputName: "alice",
			expected:  10, // Base Identity (+10)
		},
		{
			name:      "Complete Profile",
			inputName: "alice",
			about:     "I am a very interesting person with a long bio.", // > 15 chars (+10)
			picture:   "https://example.com/pic.jpg",                     // http prefix (+30)
			expected:  10 + 10 + 30,                                      // 50
		},
		{
			name:      "Verified Profile",
			inputName: "bob",
			nip05:     "bob@example.com", // (+50 async)
			lud16:     "bob@ln.tips",     // (+20 async)
			expected:  10,                // 10
		},
		{
			name: "Hex Name Penalty",
			// use 'deadbeef' repeated to 64 chars. 'e' and 'a' are vowels.
			inputName: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			expected:  10 - 100, // -90 (Base 10 - Penalty 100). Gibberish penalty skipped because hasVowels=true.
		},
		{
			name:      "Gibberish Name Penalty",
			inputName: "bcdfghj", // > 6 chars, no vowels
			expected:  10 - 200,  // -190 (Base 10 - Penalty 200)
		},
		{
			name:      "Full Penalties",
			inputName: "0000000000000000000000000000000000000000000000000000000000000000", // Hex (-100)
			// Hex string also has numbers (0), so it might pass "no vowels" check if 0 is not vowel?
			// `hasVowels` checks "aeiouAEIOU". "0" is not a vowel.
			// So "000...000" (64 chars) is > 6 chars AND has no vowels -> Gibberish (-200).
			// So total penalty: -100 (Hex) - 200 (Gibberish) = -300?
			// Let's verify `isHex` logic. It returns true.
			// `hasVowels` returns false.
			// Base: +10.
			// Score: 10 - 100 - 200 = -290.
			expected: -290,
		},
		{
			name:      "Valid Name with Numbers",
			inputName: "alice123", // Has vowels ('a', 'i', 'e')
			expected:  10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateScore(tt.inputName, tt.displayName, tt.about, tt.nip05, tt.lud16, tt.picture)
			if got != tt.expected {
				t.Errorf("CalculateScore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abcdef123456", true},
		{"ABCDEF123456", true},
		{"g123", false},
		{"", true}, // loop doesn't run, returns true (vacuously true)
	}

	for _, tt := range tests {
		if got := isHex(tt.input); got != tt.want {
			t.Errorf("isHex(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestHasVowels(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", true},
		{"SKY", false}, // Y is not in list
		{"apple", true},
		{"123", false},
	}

	for _, tt := range tests {
		if got := hasVowels(tt.input); got != tt.want {
			t.Errorf("hasVowels(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
