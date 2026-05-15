package webhook

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// imageRepo is the GHCR repository the webhook image is published to. The tag
// is chosen by DefaultImageFor so it tracks the running CLI's lineage.
const imageRepo = "ghcr.io/c-lgrant/tvault-webhook"

// DefaultImage is the fallback when the caller has no version to pin against.
// Production code uses DefaultImageFor; tests and other callers reach for this.
const DefaultImage = imageRepo + ":latest"

// DefaultImageFor returns the default webhook image for a CLI of the given
// version. It picks a tag built from the same source line as the CLI:
//
//   - "preview-<sha>" (CI-built preview binary)        -> :preview
//   - "v0.5.0" / "0.5.0" (a real release tag)          -> :0.5.0
//   - Go pseudo-version (go install ...@preview/main)  -> :preview
//   - anything else — "dev", "(devel)", "", "unknown"  -> :latest
//
// Pseudo-versions are treated as preview because they only exist for
// `go install` builds against an unreleased commit — a real release would
// produce a clean semver. :latest is the last-resort fallback for genuinely
// unknown situations; once a real release exists, :latest will point at it.
func DefaultImageFor(version string) string {
	v := strings.TrimSpace(version)
	switch {
	case strings.HasPrefix(v, "preview-"):
		return imageRepo + ":preview"
	case isReleaseSemver(v):
		return imageRepo + ":" + strings.TrimPrefix(v, "v")
	case isPseudoVersion(v):
		return imageRepo + ":preview"
	default:
		return DefaultImage
	}
}

// isReleaseSemver returns true for X.Y.Z or vX.Y.Z (with no extra suffix).
// Pseudo-versions like v0.4.10-0.20260515140135-... contain a '-' and are
// rejected here — see isPseudoVersion for that path.
func isReleaseSemver(v string) bool {
	v = strings.TrimPrefix(v, "v")
	if v == "" || strings.ContainsAny(v, "-+ ") {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// isPseudoVersion matches Go module pseudo-versions:
//
//	v0.4.10-0.20260515140135-f760cf955e71  (commit after a tag, prerelease counter prefix)
//	v0.0.0-20260515140135-f760cf955e71      (no tags exist on the module)
//	v0.5.0-pre.0.20260515140135-f760cf955e71 (commit after an existing prerelease tag)
//
// The signature: dash-split into >=3 parts, the LAST is a 12-char hex sha, and
// the LAST DOT-segment of the second-to-last dash-part is a 14-digit timestamp.
// The "0." or "pre.0." prerelease prefix lives before the timestamp.
func isPseudoVersion(v string) bool {
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return false
	}
	sha := parts[len(parts)-1]
	if len(sha) != 12 {
		return false
	}
	for _, r := range sha {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isHex {
			return false
		}
	}
	// Inside the prerelease segment, the timestamp is the last dot-piece —
	// after any optional "0" or "pre.0" counter.
	dotPieces := strings.Split(parts[len(parts)-2], ".")
	ts := dotPieces[len(dotPieces)-1]
	if len(ts) != 14 {
		return false
	}
	for _, r := range ts {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// webhookEntrypoint runs the webhook as a plain HTTP service, bypassing the
// image's bundled-ngrok entrypoint so the tunnel can live in its own container.
var webhookEntrypoint = []string{
	"gunicorn", "-k", "uvicorn.workers.UvicornWorker",
	"--bind", "0.0.0.0:8080", "main:app",
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]struct{}       `yaml:"volumes,omitempty"`
}

type composeService struct {
	Image       string            `yaml:"image,omitempty"`
	Entrypoint  []string          `yaml:"entrypoint,omitempty"`
	Command     []string          `yaml:"command,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty"`
	Volumes     []string          `yaml:"volumes,omitempty"`
	NetworkMode string            `yaml:"network_mode,omitempty"`
	Hostname    string            `yaml:"hostname,omitempty"`
}

// externalURL returns the public webhook URL for a method given the collected
// param values. ngrok derives it from NGROK_URL; every other method collects
// WEBHOOK_EXTERNAL_URL directly.
func externalURL(m Method, values map[string]string) string {
	if m.ID == "ngrok" {
		host := strings.TrimPrefix(values["NGROK_URL"], "https://")
		return "https://" + host
	}
	return values["WEBHOOK_EXTERNAL_URL"]
}

// buildCompose returns the docker-compose.yml bytes for a method.
func buildCompose(m Method, image string) ([]byte, error) {
	webhook := composeService{
		Image:       image,
		Entrypoint:  webhookEntrypoint,
		Environment: map[string]string{"WEBHOOK_EXTERNAL_URL": "${WEBHOOK_EXTERNAL_URL}"},
		Volumes:     []string{"tv-webhook-data:/data"},
	}
	cf := composeFile{
		Services: map[string]composeService{},
		Volumes:  map[string]struct{}{"tv-webhook-data": {}},
	}

	switch m.ID {
	case "ngrok":
		cf.Services["webhook"] = webhook
		cf.Services["tunnel"] = composeService{
			Image:       "ngrok/ngrok:latest",
			Command:     []string{"http", "webhook:8080", "--url=${NGROK_URL}"},
			Environment: map[string]string{"NGROK_AUTHTOKEN": "${NGROK_AUTHTOKEN}"},
		}
	case "cloudflare":
		cf.Services["webhook"] = webhook
		cf.Services["tunnel"] = composeService{
			Image:   "cloudflare/cloudflared:latest",
			Command: []string{"tunnel", "--no-autoupdate", "run", "--token", "${CLOUDFLARE_TUNNEL_TOKEN}"},
		}
	case "tailscale":
		webhook.NetworkMode = "service:tailscale"
		cf.Services["tailscale"] = composeService{
			Image:    "tailscale/tailscale:latest",
			Hostname: "${TS_HOSTNAME}",
			Environment: map[string]string{
				"TS_AUTHKEY":      "${TS_AUTHKEY}",
				"TS_USERSPACE":    "true",
				"TS_STATE_DIR":    "/var/lib/tailscale",
				"TS_SERVE_CONFIG": "/config/serve.json",
			},
			Volumes: []string{"tailscale-state:/var/lib/tailscale", "./serve.json:/config/serve.json"},
		}
		cf.Services["webhook"] = webhook
		cf.Volumes["tailscale-state"] = struct{}{}
	case "custom":
		cf.Services["webhook"] = webhook
	default:
		return nil, fmt.Errorf("unknown method %q", m.ID)
	}

	var b strings.Builder
	b.WriteString("# Token Vault webhook — generated by `tvault webhook init`\n")
	b.WriteString("# Docs: https://docs.tokenvault.uk/guides/webhook-setup\n")
	b.WriteString("# Edit freely; re-run `tvault webhook init` to regenerate.\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(cf); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// serveJSON is the Tailscale Funnel config: expose :443 publicly, proxy to the
// webhook on localhost:8080. ${TS_CERT_DOMAIN} is substituted by tailscaled.
const serveJSON = `{
  "TCP": { "443": { "HTTPS": true } },
  "Web": {
    "${TS_CERT_DOMAIN}:443": {
      "Handlers": { "/": { "Proxy": "http://127.0.0.1:8080" } }
    }
  },
  "AllowFunnel": { "${TS_CERT_DOMAIN}:443": true }
}
`

// GeneratedFile is one file the generator writes into the project directory.
type GeneratedFile struct {
	Name string
	Mode os.FileMode
	Data []byte
}

// buildEnv returns the .env bytes: every collected value plus the resolved
// WEBHOOK_EXTERNAL_URL, sorted by key for deterministic output.
func buildEnv(m Method, values map[string]string) []byte {
	out := map[string]string{}
	for k, v := range values {
		out[k] = v
	}
	out["WEBHOOK_EXTERNAL_URL"] = externalURL(m, values)
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Token Vault webhook env — generated by `tvault webhook init`\n")
	b.WriteString("# Contains tunnel-provider secrets. Do not commit (see .gitignore).\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, out[k])
	}
	return []byte(b.String())
}

// buildREADME returns a short project README with next steps and doc links.
func buildREADME(m Method) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Token Vault webhook (%s)\n\n", m.Label)
	b.WriteString("Generated by `tvault webhook init`.\n\n")
	b.WriteString("## Next steps\n\n")
	b.WriteString("1. `tvault webhook up`     — start the webhook + tunnel\n")
	b.WriteString("2. `tvault webhook bind`   — connect it to your vault (no browser)\n")
	b.WriteString("3. `tvault webhook status` — check local + backend state\n\n")
	b.WriteString("## Docs\n\n")
	b.WriteString("- Webhook setup guide: https://docs.tokenvault.uk/guides/webhook-setup\n")
	b.WriteString("- Webhook protocol:    https://docs.tokenvault.uk/webhook-protocol\n")
	fmt.Fprintf(&b, "- %s setup:\t%s\n", m.Label, m.HelpURL)
	return []byte(b.String())
}

// Generate builds the full file set for a method. image overrides the webhook
// image when non-empty.
func Generate(m Method, values map[string]string, image string) ([]GeneratedFile, error) {
	if image == "" {
		image = DefaultImage
	}
	compose, err := buildCompose(m, image)
	if err != nil {
		return nil, err
	}
	files := []GeneratedFile{
		{Name: "docker-compose.yml", Mode: 0o644, Data: compose},
		{Name: ".env", Mode: 0o600, Data: buildEnv(m, values)},
		{Name: "README.md", Mode: 0o644, Data: buildREADME(m)},
		{Name: ".gitignore", Mode: 0o644, Data: []byte(".env\n")},
	}
	if m.ID == "tailscale" {
		files = append(files, GeneratedFile{Name: "serve.json", Mode: 0o644, Data: []byte(serveJSON)})
	}
	return files, nil
}

// Conflicts returns the names of files in dir that WriteProject would
// overwrite. dir does not need to exist (a missing dir means no conflicts).
// Caller decides whether to prompt, --force, or abort.
func Conflicts(dir string, files []GeneratedFile) []string {
	var out []string
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f.Name)); err == nil {
			out = append(out, f.Name)
		}
	}
	return out
}

// WriteProject writes the generated files into dir, creating it if needed. It
// refuses to overwrite an existing docker-compose.yml unless force is true.
func WriteProject(dir string, files []GeneratedFile, force bool) error {
	if !force {
		if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err == nil {
			return fmt.Errorf("%s already contains a docker-compose.yml — pass --force to overwrite", dir)
		}
	} else {
		if _, err := os.Stat(filepath.Join(dir, ".env")); err == nil {
			fmt.Fprintf(os.Stderr, "warning: overwriting existing %s/.env — any hand-edited secrets will be lost\n", dir)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		path := filepath.Join(dir, f.Name)
		if err := os.WriteFile(path, f.Data, f.Mode); err != nil {
			return err
		}
		// os.WriteFile does not chmod an existing file; enforce the mode so a
		// regenerated .env can never be left world-readable.
		if err := os.Chmod(path, f.Mode); err != nil {
			return err
		}
	}
	return nil
}
