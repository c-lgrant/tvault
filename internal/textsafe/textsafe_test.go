package textsafe

import "testing"

func TestSafe(t *testing.T) {
	if got := Safe("plain name 1"); got != "plain name 1" {
		t.Errorf("plain text changed: %q", got)
	}
	for _, in := range []string{"a\x1b[2Jb", "a\nb", "a‮b"} {
		got := Safe(in)
		if got == in || got[0] != '"' {
			t.Errorf("Safe(%q) = %q, want a quoted form", in, got)
		}
	}
}
