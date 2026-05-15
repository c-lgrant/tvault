package config

import (
	"os"
	"path/filepath"
	"testing"
)

func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	withTempHome(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() on missing file errored: %v", err)
	}
	if len(cfg.Contexts) != 0 || cfg.Current != "" {
		t.Errorf("expected empty config, got %+v", cfg)
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	dir := withTempHome(t)
	cfg := &Config{
		Current: "nuc-admin",
		Contexts: map[string]*Context{
			"nuc-admin": {
				Type:         "admin",
				APIURL:       "https://api.tokenvault.uk",
				Identity:     "conor@example.com",
				RefreshToken: "rt-secret",
			},
		},
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() errored: %v", err)
	}

	// File must be mode 0600.
	path := filepath.Join(dir, "tvault", "contexts.yaml")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat contexts.yaml: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("contexts.yaml mode = %o, want 600", info.Mode().Perm())
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() errored: %v", err)
	}
	if loaded.Current != "nuc-admin" {
		t.Errorf("Current = %q, want nuc-admin", loaded.Current)
	}
	got := loaded.Contexts["nuc-admin"]
	if got == nil || got.Identity != "conor@example.com" || got.RefreshToken != "rt-secret" {
		t.Errorf("round-trip lost data: %+v", got)
	}
}

// TestSaveProducesMode0600EvenAfterPriorSave proves the 0600 guarantee holds
// on the overwrite path: the second Save() runs with contexts.yaml already
// present, and the result must still be 0600.
func TestSaveProducesMode0600EvenAfterPriorSave(t *testing.T) {
	dir := withTempHome(t)
	cfg := &Config{
		Current: "nuc-admin",
		Contexts: map[string]*Context{
			"nuc-admin": {Type: "admin", RefreshToken: "rt-secret"},
		},
	}
	path := filepath.Join(dir, "tvault", "contexts.yaml")

	for i, label := range []string{"first save", "overwrite save"} {
		if err := cfg.Save(); err != nil {
			t.Fatalf("%s: Save() errored: %v", label, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: stat contexts.yaml: %v", label, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s (call %d): contexts.yaml mode = %o, want 600", label, i+1, info.Mode().Perm())
		}
	}
}

func TestActiveContextRespectsOverride(t *testing.T) {
	withTempHome(t)
	cfg := &Config{
		Current: "a",
		Contexts: map[string]*Context{
			"a": {Type: "admin"},
			"b": {Type: "agent"},
		},
	}
	ctx, name, err := cfg.ActiveContext("b")
	if err != nil || name != "b" || ctx.Type != "agent" {
		t.Errorf("override ignored: name=%q ctx=%+v err=%v", name, ctx, err)
	}
	ctx, name, err = cfg.ActiveContext("")
	if err != nil || name != "a" {
		t.Errorf("default current ignored: name=%q err=%v", name, err)
	}
	if _, _, err := cfg.ActiveContext("missing"); err == nil {
		t.Error("expected error for unknown context override")
	}
}
