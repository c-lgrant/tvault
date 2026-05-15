package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ConfirmFunc asks the user a yes/no question. Tests inject a stub.
type ConfirmFunc func(prompt string) bool

// MigrateLegacy looks for a v0.4.8 ~/.config/tv/config file when no
// contexts.yaml exists yet. If found, it asks the user (via confirm) whether
// to import it as an agent context named "default". The legacy file is left
// in place so old binaries keep working. Returns true when a migration ran.
func MigrateLegacy(confirm ConfirmFunc) (bool, error) {
	// Only migrate when there is no contexts.yaml at all.
	p, err := Path()
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); err == nil {
		return false, nil // already have a config
	}

	// Resolve the legacy path with the same precedence the v0.4.8 bash
	// script used: TV_CONFIG_DIR overrides XDG_CONFIG_HOME, which overrides
	// $HOME/.config.
	var legacyPath string
	if dir := os.Getenv("TV_CONFIG_DIR"); dir != "" {
		legacyPath = filepath.Join(dir, "config")
	} else if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		legacyPath = filepath.Join(xdg, "tv", "config")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return false, err
		}
		legacyPath = filepath.Join(home, ".config", "tv", "config")
	}
	data, err := os.ReadFile(legacyPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	kv := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	agentKey := kv["TV_AGENT_KEY"]
	if agentKey == "" {
		return false, nil // nothing useful to migrate
	}
	apiURL := kv["TV_API_URL"]
	if apiURL == "" {
		apiURL = "https://api.tokenvault.uk"
	}

	if !confirm("Found a legacy ~/.config/tv/config. Import it as context \"default\"? [Y/n] ") {
		return false, nil
	}

	cfg := &Config{
		Current: "default",
		Contexts: map[string]*Context{
			"default": {Type: "agent", APIURL: apiURL, Identity: "default", AgentKey: agentKey},
		},
	}
	if err := cfg.Save(); err != nil {
		return false, err
	}
	return true, nil
}
