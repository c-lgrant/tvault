package webhook

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ComposeRunner runs docker compose lifecycle commands against a project dir.
// The interface lets commands inject a fake in tests.
type ComposeRunner interface {
	Up(dir string) error
	Down(dir string) error
	PS(dir string) (string, error)
	Logs(dir string, tail int) (string, error)
}

// ExecRunner is the real ComposeRunner — it shells out to `docker compose`.
type ExecRunner struct{}

func (ExecRunner) run(dir string, args ...string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker not found on PATH — install Docker to use `tvault webhook`")
	}
	cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
	// dir is caller-supplied (a --dir flag or cwd); docker runs as the invoking user.
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker compose %s failed: %w\n%s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Up runs `docker compose up -d`.
func (e ExecRunner) Up(dir string) error { _, err := e.run(dir, "up", "-d"); return err }

// Down runs `docker compose down`.
func (e ExecRunner) Down(dir string) error { _, err := e.run(dir, "down"); return err }

// PS runs `docker compose ps` and returns its output.
func (e ExecRunner) PS(dir string) (string, error) { return e.run(dir, "ps") }

// Logs runs `docker compose logs --tail <n>` and returns its output.
func (e ExecRunner) Logs(dir string, tail int) (string, error) {
	return e.run(dir, "logs", "--tail", strconv.Itoa(tail))
}
