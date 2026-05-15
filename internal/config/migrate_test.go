package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateLegacyTvConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	// Seed a legacy ~/.config/tv/config (v0.4.8 format: KEY=value lines).
	legacyDir := filepath.Join(home, ".config", "tv")
	os.MkdirAll(legacyDir, 0o700)
	os.WriteFile(filepath.Join(legacyDir, "config"),
		[]byte("TV_AGENT_KEY=tvagent_legacy\nTV_API_URL=https://api.tokenvault.uk\n"), 0o600)

	migrated, err := MigrateLegacy(func(prompt string) bool { return true })
	if err != nil {
		t.Fatalf("MigrateLegacy errored: %v", err)
	}
	if !migrated {
		t.Fatal("expected migration to happen")
	}

	cfg, _ := Load()
	ctx := cfg.Contexts["default"]
	if ctx == nil || ctx.Type != "agent" || ctx.AgentKey != "tvagent_legacy" {
		t.Errorf("migrated context wrong: %+v", ctx)
	}
	if cfg.Current != "default" {
		t.Errorf("Current = %q, want default", cfg.Current)
	}
}

func TestMigrateLegacyDeclined(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	legacyDir := filepath.Join(home, ".config", "tv")
	os.MkdirAll(legacyDir, 0o700)
	os.WriteFile(filepath.Join(legacyDir, "config"), []byte("TV_AGENT_KEY=tvagent_legacy\n"), 0o600)

	migrated, err := MigrateLegacy(func(string) bool { return false })
	if err != nil || migrated {
		t.Errorf("declined migration should be a no-op: migrated=%v err=%v", migrated, err)
	}
}

func TestMigrateLegacyNoLegacyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	migrated, err := MigrateLegacy(func(string) bool { return true })
	if err != nil || migrated {
		t.Errorf("no legacy file should be a no-op: migrated=%v err=%v", migrated, err)
	}
}
