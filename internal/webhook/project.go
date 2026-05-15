package webhook

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Project is a generated webhook deployment directory.
type Project struct {
	Dir         string // absolute path to the project directory
	ExternalURL string // WEBHOOK_EXTERNAL_URL from the project .env
}

// LoadProject locates a generated webhook project. dir is the project
// directory (cwd when empty). It requires docker-compose.yml and a .env with
// WEBHOOK_EXTERNAL_URL.
func LoadProject(dir string) (*Project, error) {
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "docker-compose.yml")); err != nil {
		return nil, fmt.Errorf("no docker-compose.yml in %s — run `tvault webhook init` first", abs)
	}
	env, err := parseEnvFile(filepath.Join(abs, ".env"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no .env in %s — run `tvault webhook init` first", abs)
		}
		return nil, err
	}
	externalURL := env["WEBHOOK_EXTERNAL_URL"]
	if externalURL == "" {
		return nil, fmt.Errorf("%s/.env has no WEBHOOK_EXTERNAL_URL", abs)
	}
	return &Project{Dir: abs, ExternalURL: externalURL}, nil
}

// parseEnvFile reads a KEY=VALUE .env file, skipping blank and #-comment lines.
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		// generated .env never produces bare (no-'=') lines; skip them defensively.
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, sc.Err()
}
