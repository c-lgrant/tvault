// agentwizard.go is the `ag new` flow: enter a name, then multi-select which
// vault services to grant the new agent.
package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// grantSelection is the pure, testable core of the grants multi-select.
type grantSelection struct {
	services []string
	chosen   map[int]bool
}

func newGrantSelection(services []string) *grantSelection {
	return &grantSelection{services: services, chosen: map[int]bool{}}
}

func (g *grantSelection) toggle(i int) {
	if i < 0 || i >= len(g.services) {
		return
	}
	if g.chosen[i] {
		delete(g.chosen, i)
	} else {
		g.chosen[i] = true
	}
}

func (g *grantSelection) selected() []string {
	var out []string
	for i, svc := range g.services {
		if g.chosen[i] {
			out = append(out, svc)
		}
	}
	return out
}

type agentModel struct {
	step     int
	nameIn   textinput.Model
	grants   *grantSelection
	cursor   int
	done     bool
	canceled bool
}

// newAgentModelForTest builds the wizard model directly — used by teatest.
func newAgentModelForTest(services []string) agentModel {
	ni := textinput.New()
	ni.Placeholder = "agent name"
	ni.Focus()
	return agentModel{nameIn: ni, grants: newGrantSelection(services)}
}

func RunAgentWizard(services []string) (string, []string, error) {
	m := newAgentModelForTest(services)

	final, err := tea.NewProgram(m).Run()
	if err != nil {
		return "", nil, err
	}
	fm := final.(agentModel)
	if fm.canceled {
		return "", nil, fmt.Errorf("canceled")
	}
	return fm.nameIn.Value(), fm.grants.selected(), nil
}

func (m agentModel) Init() tea.Cmd { return textinput.Blink }

func (m agentModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		m.nameIn, cmd = m.nameIn.Update(msg)
		return m, cmd
	}
	switch key.Type {
	case tea.KeyCtrlC, tea.KeyEsc:
		m.canceled = true
		return m, tea.Quit
	case tea.KeyEnter:
		if m.step == 0 {
			m.step = 1
			return m, nil
		}
		m.done = true
		return m, tea.Quit
	}
	if m.step == 0 {
		var cmd tea.Cmd
		m.nameIn, cmd = m.nameIn.Update(msg)
		return m, cmd
	}
	switch key.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.grants.services)-1 {
			m.cursor++
		}
	case " ":
		m.grants.toggle(m.cursor)
	}
	return m, nil
}

func (m agentModel) View() string {
	if m.done || m.canceled {
		return ""
	}
	if m.step == 0 {
		return "Create agent\n\nName: " + m.nameIn.View() + "\n\n(enter = next · esc = cancel)\n"
	}
	s := "Select grants (space = toggle, enter = finish):\n\n"
	for i, svc := range m.grants.services {
		cursor := "  "
		if i == m.cursor {
			cursor = "> "
		}
		box := "[ ]"
		if m.grants.chosen[i] {
			box = "[x]"
		}
		s += fmt.Sprintf("%s%s %s\n", cursor, box, svc)
	}
	return s + "\n(esc = cancel)\n"
}
