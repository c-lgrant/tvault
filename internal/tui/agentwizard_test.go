package tui

import "testing"

func TestGrantSelectionToggle(t *testing.T) {
	sel := newGrantSelection([]string{"github", "spotify", "stripe"})
	sel.toggle(1)
	sel.toggle(0)
	sel.toggle(1)
	got := sel.selected()
	if len(got) != 1 || got[0] != "github" {
		t.Errorf("selected = %v, want [github]", got)
	}
}

func TestGrantSelectionEmpty(t *testing.T) {
	sel := newGrantSelection(nil)
	if len(sel.selected()) != 0 {
		t.Error("empty selection should yield nothing")
	}
}
