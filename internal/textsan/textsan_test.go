package textsan

import (
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	oneLine := Options{StripControls: true, TrimSpace: true}
	multi := Options{KeepNewlines: true, StripControls: true}
	for _, c := range []struct {
		in   string
		max  int
		o    Options
		want string
	}{
		// Always: marks, bidi and zero-width stripped, a selector after a mark too.
		{"Alice\u200b's\u202e cash counter", 40, Options{}, "Alice's cash counter"},
		{"\u2714\ufe0f Alice", 40, Options{}, " Alice"},
		{"\u2066x\u2069\u2060\ufeff\u200c\u200d\u221a\u2611\u2705\U0001F5F8\u2713", 0, Options{}, "x"},
		{"A\r\nB\tC\rD\u2028E", 0, Options{}, "A B C D E"},
		// Controls are kept unless StripControls.
		{"a\x00b\x07", 0, Options{}, "a\x00b\x07"},
		{"a\x00b\x07", 0, oneLine, "ab"},
		// KeepNewlines: \n and CR LF stay one \n; tabs still a space.
		{"two\r\nlines\tx\n", 0, multi, "two\nlines x\n"},
		{"two\r\nlines\n", 0, oneLine, "two lines"},
		// TrimSpace before the cap.
		{"  padded  ", 3, oneLine, "pad"},
		// The cap counts clusters and never cuts inside one.
		{strings.Repeat("e\u0301", 41), 40, Options{}, strings.Repeat("e\u0301", 40)},
		{strings.Repeat("\U0001F44D\U0001F3FD", 3), 2, Options{}, strings.Repeat("\U0001F44D\U0001F3FD", 2)},
		{"abc", 0, Options{}, "abc"},
		{"abc", -1, Options{}, "abc"},
	} {
		if got := Sanitize(c.in, c.max, c.o); got != c.want {
			t.Errorf("Sanitize(%q, %d, %+v) = %q, want %q", c.in, c.max, c.o, got, c.want)
		}
	}
}

// Sanitize never returns a code point it strips, nor a line break unless kept.
func FuzzSanitize(f *testing.F) {
	f.Add("Alice\u200b's\u202e cash counter", 40, false)
	f.Add("\u2714\ufe0f \u00e9\r\n\x00", 3, true)
	f.Fuzz(func(t *testing.T, s string, n int, keep bool) {
		out := Sanitize(s, n%300, Options{KeepNewlines: keep, StripControls: keep})
		for _, r := range out {
			if stripped(r) || (lineBreak(r) && !(keep && r == '\n')) {
				t.Fatalf("%q kept %U", out, r)
			}
		}
	})
}
