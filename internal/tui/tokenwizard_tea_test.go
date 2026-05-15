package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

// contains/indexOf are tiny []byte substring helpers shared by the teatest
// snapshot tests (teatest.WaitFor hands us a []byte view of the terminal).
func contains(b []byte, s string) bool {
	return len(b) >= len(s) && (string(b) == s || indexOf(string(b), s) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestTokenWizardPickTypeThenFields drives the real two-step token wizard:
// the type picker first, then the service + credential field entry.
func TestTokenWizardPickTypeThenFields(t *testing.T) {
	tm := teatest.NewTestModel(t, newModel(), teatest.WithInitialTermSize(80, 24))

	// Step 0: the type picker.
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return contains(b, "choose a type")
	}, teatest.WithDuration(2*time.Second))

	// Pick the first type (JWT) by pressing its number.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})

	// Step 1: the field-entry screen.
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return contains(b, "Create OAuth · JWT token")
	}, teatest.WithDuration(2*time.Second))

	// Fill the service name, advance, fill the credential, finish.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("github")})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ghp_secret")})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	final := tm.FinalModel(t, teatest.WithFinalTimeout(2*time.Second)).(model)
	if final.canceled {
		t.Fatal("token wizard canceled unexpectedly")
	}
	if final.tokenType != "JWT" {
		t.Errorf("tokenType = %q, want JWT", final.tokenType)
	}
	if final.inputs[0].Value() != "github" {
		t.Errorf("service input = %q, want github", final.inputs[0].Value())
	}
	if final.inputs[1].Value() != "ghp_secret" {
		t.Errorf("credential input = %q, want ghp_secret", final.inputs[1].Value())
	}
}
