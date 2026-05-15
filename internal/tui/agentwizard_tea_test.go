package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func TestAgentWizardNameThenGrants(t *testing.T) {
	services := []string{"github", "spotify", "stripe"}
	ni := newAgentModelForTest(services)
	tm := teatest.NewTestModel(t, ni, teatest.WithInitialTermSize(80, 24))

	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return contains(b, "Create agent")
	}, teatest.WithDuration(2*time.Second))

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("pi-mixer")})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" ")})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(2*time.Second)).(agentModel)
	if final.canceled {
		t.Fatal("agent wizard canceled unexpectedly")
	}
	if final.nameIn.Value() != "pi-mixer" {
		t.Errorf("name = %q", final.nameIn.Value())
	}
	if got := final.grants.selected(); len(got) != 1 || got[0] != "github" {
		t.Errorf("grants = %v, want [github]", got)
	}
}
