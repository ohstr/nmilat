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
		// A4-NM-1: warning/negative badge look-alikes and the extra check sibling
		// go too, a selector after one included; a legitimate emoji and text stay.
		{"\u274c\u26a0\u274e\U0001F5F9 Alice", 40, Options{}, " Alice"},
		{"\u26a0\ufe0f warning", 40, Options{}, " warning"},
		{"ok \u2612\u2717\u2718\U0001F5F6\U0001F5F7 done", 40, Options{}, "ok  done"},
		// R-NM-TEXTSAN: the whole ballot-X block U+1F5F4-U+1F5F7 goes, not just the
		// bold pair - the script-X pair U+1F5F4/U+1F5F5 is a badge look-alike too,
		// and a variation selector after one is swallowed with it.
		{"ok \U0001F5F4\U0001F5F5\U0001F5F6\U0001F5F7 done", 40, Options{}, "ok  done"},
		{"\U0001F5F4\ufe0f\U0001F5F5\ufe0f ballot", 40, Options{}, " ballot"},
		// multiplication signs are maths, not status badges: kept.
		{"5\u2715\u2716 is maths", 40, Options{}, "5\u2715\u2716 is maths"},
		{"Caf\u00e9 \u2764 5x3 a=b", 40, Options{}, "Caf\u00e9 \u2764 5x3 a=b"},
		{"A\r\nB\tC\rD\u2028E", 0, Options{}, "A B C D E"},
		// Directional marks and other invisibles.
		{"a\u200eb\u200fc\u061cd\u00ade\u180ef\u2061g\u2064h", 0, Options{}, "abcdefgh"},
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
		// R2-N4: every other format character goes, tag characters included.
		{"a\u206ab\u206fc\ufff9d\ufffbe\U000E0001f\U000E0041g\U000E007Fh\u0600i", 0, Options{}, "abcdefghi"},
		// A ZWJ stays only between two emoji, after a selector or skin tone too.
		{"\U0001F468\u200d\U0001F469\u200d\U0001F467", 0, Options{}, "\U0001F468\u200d\U0001F469\u200d\U0001F467"},
		{"\U0001F3F3\ufe0f\u200d\U0001F308", 0, Options{}, "\U0001F3F3\ufe0f\u200d\U0001F308"},
		{"\U0001F44D\U0001F3FD\u200d\u2642", 0, Options{}, "\U0001F44D\U0001F3FD\u200d\u2642"},
		{"a\u200d\U0001F469", 0, Options{}, "a\U0001F469"},
		{"\U0001F469\u200db", 0, Options{}, "\U0001F469b"},
		{"\u2714\u200d\U0001F469", 0, Options{}, "\U0001F469"},
		{"\U0001F469\u200d\u200d\U0001F469", 0, Options{}, "\U0001F469\u200d\U0001F469"},
		// The byte cap: a cluster grown with combining marks is cut whole.
		{"a" + strings.Repeat("\u0301", 40) + "b", 2, Options{}, ""},
		{"abc" + strings.Repeat("\u0301", 60), 3, Options{}, "ab"},
		{strings.Repeat("x", 100), 0, Options{MaxBytes: 10}, strings.Repeat("x", 10)},
		{strings.Repeat("x", 100), 50, Options{MaxBytes: -1}, strings.Repeat("x", 50)},
		{strings.Repeat("x", 100), 2, Options{MaxBytes: 1}, "x"},
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
			if (stripped(r) && r != 0x200D) || (lineBreak(r) && (!keep || r != '\n')) {
				t.Fatalf("%q kept %U", out, r)
			}
		}
		if lim := (n % 300) * MaxClusterBytes; lim > 0 && len(out) > lim {
			t.Fatalf("%q is %d bytes, over %d", out, len(out), lim)
		}
	})
}
