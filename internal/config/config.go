// Package config loads and saves the CLI's persona state — the set of
// kubectl-style contexts in ~/.config/tvault/contexts.yaml (mode 0600).
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/c-lgrant/tvault/internal/clierr"
	"gopkg.in/yaml.v3"
)

// Context is one stored persona — either an admin (Firebase refresh token)
// or an agent (tvagent_* key).
type Context struct {
	Type         string `yaml:"type"`                    // "admin" | "agent"
	APIURL       string `yaml:"api_url"`                 // base API URL
	Identity     string `yaml:"identity"`                // email or agent name
	RefreshToken string `yaml:"refresh_token,omitempty"` // admin only
	AgentKey     string `yaml:"agent_key,omitempty"`     // agent only

	// Process-only — never persisted. Populated by the refresh loop.
	idToken          string `yaml:"-"`
	idTokenExpiresAt int64  `yaml:"-"`
}

// SetIDToken stores a freshly minted ID token and its absolute expiry
// (unix seconds) in process memory only.
func (c *Context) SetIDToken(token string, expiresAt int64) {
	c.idToken = token
	c.idTokenExpiresAt = expiresAt
}

// IDToken returns the in-memory ID token and its expiry.
func (c *Context) IDToken() (string, int64) { return c.idToken, c.idTokenExpiresAt }

// Config is the whole contexts.yaml document.
type Config struct {
	Current  string              `yaml:"current"`
	Contexts map[string]*Context `yaml:"contexts"`
}

func dir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "tvault"), nil
}

// Path returns the absolute path to contexts.yaml.
func Path() (string, error) {
	d, err := dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "contexts.yaml"), nil
}

// Load reads contexts.yaml. A missing file is not an error — it returns an
// empty Config so first-run flows work.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return &Config{Contexts: map[string]*Context{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", p, err)
	}
	if cfg.Contexts == nil {
		cfg.Contexts = map[string]*Context{}
	}
	return &cfg, nil
}

// Save writes contexts.yaml atomically with mode 0600.
func (c *Config) Save() error {
	d, err := dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	p := filepath.Join(d, "contexts.yaml")

	// Write to a unique temp file in the same directory so the rename stays
	// atomic on one filesystem. CreateTemp is subject to umask, so chmod
	// explicitly to guarantee 0600 for the plaintext secrets we're about to
	// write. The deferred Remove cleans up on any failure path and is a
	// harmless no-op once the file has been renamed away.
	tmpFile, err := os.CreateTemp(d, "contexts-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)
	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

// ActiveContext resolves which context a command should use: the --context
// override when non-empty, otherwise Current. Returns the context, its name,
// and a KindAuth CLIError when nothing usable is found.
func (c *Config) ActiveContext(override string) (*Context, string, error) {
	name := override
	if name == "" {
		name = c.Current
	}
	if name == "" {
		return nil, "", &clierr.CLIError{
			Kind:    clierr.KindAuth,
			Message: "no active context — run `tvault login` first",
		}
	}
	ctx, ok := c.Contexts[name]
	if !ok {
		return nil, "", &clierr.CLIError{
			Kind:    clierr.KindAuth,
			Message: fmt.Sprintf("context %q not found — run `tvault context list`", name),
		}
	}
	return ctx, name, nil
}
