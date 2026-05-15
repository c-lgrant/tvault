package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFieldsForType(t *testing.T) {
	cases := map[string][]string{
		"JWT":           {"service", "credential"},
		"PlainText":     {"service", "credential"},
		"Certificate":   {"service", "credential"},
		"SSHKey":        {"service", "credential"},
		"RawCredential": {"service", "credential"},
		"TOTP":          {"service", "credential"},
	}
	for typ, want := range cases {
		got := FieldsForType(typ)
		if len(got) != len(want) {
			t.Errorf("FieldsForType(%q) = %v, want %v", typ, got, want)
		}
	}
	if FieldsForType("nonsense") != nil {
		t.Error("unknown type should return nil")
	}
}

func TestSupportedTokenTypes(t *testing.T) {
	types := SupportedTokenTypes()
	if len(types) < 5 {
		t.Errorf("expected the full supported-type list, got %v", types)
	}
}

func TestModelTypePickerAdvances(t *testing.T) {
	m := newModel()
	if m.step != stepPickType {
		t.Fatalf("fresh model step = %v, want stepPickType", m.step)
	}
	// "2" selects the second supported type, then advances to field entry.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	fm := updated.(model)
	if fm.step != stepFields {
		t.Errorf("after selecting a type, step = %v, want stepFields", fm.step)
	}
	want := SupportedTokenTypes()[1]
	if fm.tokenType != want {
		t.Errorf("tokenType = %q, want %q", fm.tokenType, want)
	}
	if len(fm.inputs) != len(FieldsForType(want)) {
		t.Errorf("inputs len = %d, want %d", len(fm.inputs), len(FieldsForType(want)))
	}
}
