// Package tui holds the Bubbletea interactive wizards. tokenwizard.go is the
// `tk new` flow: pick a type, then fill the fields that type needs.
package tui

import (
	"fmt"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// SupportedTokenTypes is the ordered list of backend tokenType values shown
// in the type picker. These are the exact strings the backend dispatches on
// (see backend/routes/tokens.py enrich_* and the web console token wizard) —
// not friendly labels. tokenTypeLabel renders the friendly name.
func SupportedTokenTypes() []string {
	return []string{
		"JWT", "PlainText", "Certificate", "SSHKey", "RawCredential", "TOTP",
	}
}

// tokenTypeLabel is the human-friendly name shown in the type picker. It
// mirrors the labels in the web console's token wizard.
func tokenTypeLabel(typ string) string {
	switch typ {
	case "JWT":
		return "OAuth · JWT"
	case "PlainText":
		return "API key / PAT"
	case "Certificate":
		return "Certificate (X.509)"
	case "SSHKey":
		return "SSH key"
	case "RawCredential":
		return "Raw credential blob"
	case "TOTP":
		return "TOTP · 2FA"
	default:
		return typ
	}
}

// FieldsForType returns the field names a given token type needs, or nil for
// an unknown type.
func FieldsForType(typ string) []string {
	for _, t := range SupportedTokenTypes() {
		if t == typ {
			return []string{"service", "credential"}
		}
	}
	return nil
}

func promptForField(typ, field string) string {
	if field == "service" {
		return "Service name"
	}
	switch typ {
	case "TOTP":
		return "TOTP secret (base32) or otpauth:// URI"
	case "SSHKey":
		return "SSH private key (PEM)"
	case "Certificate":
		return "Certificate PEM"
	case "RawCredential":
		return "Credential blob (JSON/INI/YAML)"
	default:
		return "Credential value"
	}
}

// wizardStep is the two-phase state: pick a type, then fill its fields.
type wizardStep int

const (
	stepPickType wizardStep = iota
	stepFields
)

type model struct {
	step      wizardStep
	tokenType string
	fields    []string
	inputs    []textinput.Model
	idx       int
	done      bool
	canceled  bool
}

func RunTokenWizard() (*api.CreateTokenRequest, error) {
	m := newModel()
	final, err := tea.NewProgram(m).Run()
	if err != nil {
		return nil, err
	}
	fm := final.(model)
	if fm.canceled {
		return nil, fmt.Errorf("canceled")
	}
	req := &api.CreateTokenRequest{Type: fm.tokenType}
	for i, f := range fm.fields {
		switch f {
		case "service":
			req.ServiceName = fm.inputs[i].Value()
		case "credential":
			req.Credential = fm.inputs[i].Value()
		}
	}
	return req, nil
}

// newModel starts the wizard on the type-picker step.
func newModel() model {
	return model{step: stepPickType}
}

// buildInputs (re)creates the field inputs for the chosen type and advances
// the wizard to the field-entry step.
func (m *model) buildInputs() {
	m.fields = FieldsForType(m.tokenType)
	m.inputs = make([]textinput.Model, len(m.fields))
	for i := range m.fields {
		ti := textinput.New()
		ti.Placeholder = promptForField(m.tokenType, m.fields[i])
		if i == 0 {
			ti.Focus()
		}
		m.inputs[i] = ti
	}
	m.idx = 0
	m.step = stepFields
}

func (m model) Init() tea.Cmd { return textinput.Blink }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, isKey := msg.(tea.KeyMsg)
	if isKey {
		switch key.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			m.canceled = true
			return m, tea.Quit
		}
	}

	if m.step == stepPickType {
		if isKey && key.Type == tea.KeyRunes && len(key.Runes) == 1 {
			r := key.Runes[0]
			types := SupportedTokenTypes()
			if r >= '1' && int(r-'1') < len(types) {
				m.tokenType = types[r-'1']
				m.buildInputs()
				return m, textinput.Blink
			}
		}
		return m, nil
	}

	// stepFields
	if isKey && key.Type == tea.KeyEnter {
		if m.idx == len(m.inputs)-1 {
			m.done = true
			return m, tea.Quit
		}
		m.inputs[m.idx].Blur()
		m.idx++
		m.inputs[m.idx].Focus()
		return m, textinput.Blink
	}
	var cmd tea.Cmd
	m.inputs[m.idx], cmd = m.inputs[m.idx].Update(msg)
	return m, cmd
}

func (m model) View() string {
	if m.done || m.canceled {
		return ""
	}
	if m.step == stepPickType {
		s := "Create a token — choose a type:\n\n"
		for i, t := range SupportedTokenTypes() {
			s += fmt.Sprintf("  %d) %s\n", i+1, tokenTypeLabel(t))
		}
		s += "\n(press a number · esc = cancel)\n"
		return s
	}

	s := fmt.Sprintf("Create %s token\n\n", tokenTypeLabel(m.tokenType))
	for i, in := range m.inputs {
		cursor := "  "
		if i == m.idx {
			cursor = "> "
		}
		s += cursor + promptForField(m.tokenType, m.fields[i]) + ": " + in.View() + "\n"
	}
	s += "\n(enter = next/finish · esc = cancel)\n"
	return s
}
