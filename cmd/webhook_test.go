package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// newWebhookTestCmd builds a throwaway command carrying the same flags
// runWebhookInit reads, so tests stay isolated from rootCmd's global state.
func newWebhookTestCmd() *cobra.Command {
	c := &cobra.Command{}
	c.Flags().String("dir", "", "")
	c.Flags().String("image", "", "")
	c.Flags().Bool("force", false, "")
	c.Flags().String("method", "", "")
	c.Flags().StringArray("set", nil, "")
	c.SetErr(io.Discard)
	c.SetOut(io.Discard)
	return c
}

// --set values must go through the same Normalize as the wizard so both
// non-interactive and interactive paths produce identical .env values.
// User pastes a bare hostname for WEBHOOK_EXTERNAL_URL → must end up with
// https:// in the on-disk .env, mirroring what the wizard would do.
func TestWebhookInitNormalizesSet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proj")
	c := newWebhookTestCmd()
	c.Flags().Set("method", "custom")
	c.Flags().Set("set", "WEBHOOK_EXTERNAL_URL=foo.example.com/")
	c.Flags().Set("dir", dir)
	if err := runWebhookInit(c, nil); err != nil {
		t.Fatalf("runWebhookInit: %v", err)
	}
	env, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(env), "WEBHOOK_EXTERNAL_URL=https://foo.example.com\n") {
		t.Errorf(".env did not normalize URL:\n%s", string(env))
	}
}

// Mirror for ngrok: --set NGROK_URL with https:// must be stripped to bare
// hostname (the ngrok container's --url= flag wants no scheme).
func TestWebhookInitStripsScheme(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proj")
	c := newWebhookTestCmd()
	c.Flags().Set("method", "ngrok")
	c.Flags().Set("set", "NGROK_AUTHTOKEN=tok")
	c.Flags().Set("set", "NGROK_URL=https://foo.ngrok-free.app/")
	c.Flags().Set("dir", dir)
	if err := runWebhookInit(c, nil); err != nil {
		t.Fatalf("runWebhookInit: %v", err)
	}
	env, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(env), "NGROK_URL=foo.ngrok-free.app\n") {
		t.Errorf(".env did not strip scheme from NGROK_URL:\n%s", string(env))
	}
}

// When --dir is omitted, runWebhookInit defaults to the current working
// directory — chdir into a tempdir to verify, restore on cleanup.
func TestWebhookInitDefaultsToCWD(t *testing.T) {
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(prev) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	c := newWebhookTestCmd()
	c.Flags().Set("method", "custom")
	c.Flags().Set("set", "WEBHOOK_EXTERNAL_URL=https://wh.example.com")
	if err := runWebhookInit(c, nil); err != nil {
		t.Fatalf("runWebhookInit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err != nil {
		t.Errorf("docker-compose.yml not written into CWD: %v", err)
	}
}

// confirmOverwrite is the gate. When it returns false, runWebhookInit must
// abort with an actionable error and not touch the existing files. Stub the
// package-level confirmOverwrite to simulate the user answering 'n' (or the
// no-TTY default).
func TestWebhookInitAbortsOnOverwriteNo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("DO NOT CLOBBER"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := confirmOverwrite
	t.Cleanup(func() { confirmOverwrite = prev })
	confirmOverwrite = func(*cobra.Command, string, []string) bool { return false }

	c := newWebhookTestCmd()
	c.Flags().Set("method", "custom")
	c.Flags().Set("set", "WEBHOOK_EXTERNAL_URL=https://wh.example.com")
	c.Flags().Set("dir", dir)
	err := runWebhookInit(c, nil)
	if err == nil {
		t.Fatal("expected abort error when confirm returns false")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if string(got) != "DO NOT CLOBBER" {
		t.Errorf("existing file was overwritten despite abort; got %q", string(got))
	}
}

// Inverse: confirm returns true → write proceeds, files end up overwritten.
func TestWebhookInitProceedsOnOverwriteYes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := confirmOverwrite
	t.Cleanup(func() { confirmOverwrite = prev })
	called := false
	confirmOverwrite = func(*cobra.Command, string, []string) bool { called = true; return true }

	c := newWebhookTestCmd()
	c.Flags().Set("method", "custom")
	c.Flags().Set("set", "WEBHOOK_EXTERNAL_URL=https://wh.example.com")
	c.Flags().Set("dir", dir)
	if err := runWebhookInit(c, nil); err != nil {
		t.Fatalf("runWebhookInit: %v", err)
	}
	if !called {
		t.Error("confirmOverwrite was not consulted")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if string(got) == "OLD" {
		t.Error("existing file was NOT overwritten despite confirm=true")
	}
}

// helper: substring check that also tolerates the value appearing once.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestWebhookInitNonInteractive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proj")
	c := newWebhookTestCmd()
	c.Flags().Set("method", "custom")
	c.Flags().Set("set", "WEBHOOK_EXTERNAL_URL=https://wh.example.com")
	c.Flags().Set("dir", dir)
	if err := runWebhookInit(c, nil); err != nil {
		t.Fatalf("runWebhookInit: %v", err)
	}
	for _, name := range []string{"docker-compose.yml", ".env", "README.md", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
}

func TestWebhookInitUnknownMethod(t *testing.T) {
	c := newWebhookTestCmd()
	c.Flags().Set("method", "bogus")
	c.Flags().Set("dir", t.TempDir())
	if err := runWebhookInit(c, nil); err == nil {
		t.Error("unknown method should error")
	}
}

func TestWebhookInitMissingParam(t *testing.T) {
	c := newWebhookTestCmd()
	c.Flags().Set("method", "custom") // custom needs WEBHOOK_EXTERNAL_URL, not provided
	c.Flags().Set("dir", t.TempDir())
	if err := runWebhookInit(c, nil); err == nil {
		t.Error("missing required param should error")
	}
}

func TestWebhookInitBadSet(t *testing.T) {
	c := newWebhookTestCmd()
	c.Flags().Set("method", "custom")
	c.Flags().Set("set", "WEBHOOK_EXTERNAL_URL") // missing =
	c.Flags().Set("dir", t.TempDir())
	if err := runWebhookInit(c, nil); err == nil {
		t.Error("missing = in --set should error")
	}
}

func TestWebhookInitEmptySetKey(t *testing.T) {
	c := newWebhookTestCmd()
	c.Flags().Set("method", "custom")
	c.Flags().Set("set", "=somevalue") // empty key
	c.Flags().Set("dir", t.TempDir())
	if err := runWebhookInit(c, nil); err == nil {
		t.Error("empty key in --set should error")
	}
}

// fakeRunner is a ComposeRunner that records calls instead of running docker.
type fakeRunner struct {
	calls []string
	upErr error
}

func (f *fakeRunner) Up(dir string) error                       { f.calls = append(f.calls, "up"); return f.upErr }
func (f *fakeRunner) Down(dir string) error                     { f.calls = append(f.calls, "down"); return nil }
func (f *fakeRunner) PS(dir string) (string, error)             { return "ps-output", nil }
func (f *fakeRunner) Logs(dir string, tail int) (string, error) { return "log-output", nil }

func writeFakeProject(t *testing.T, externalURL string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("WEBHOOK_EXTERNAL_URL="+externalURL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newDirCmd(dir string) *cobra.Command {
	c := &cobra.Command{}
	c.Flags().String("dir", dir, "")
	c.SetErr(io.Discard)
	c.SetOut(io.Discard)
	return c
}

func TestWebhookUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer srv.Close()
	dir := writeFakeProject(t, srv.URL)

	origRunner, origHTTP := composeRunner, webhookHTTP
	defer func() { composeRunner, webhookHTTP = origRunner, origHTTP }()
	fr := &fakeRunner{}
	composeRunner = fr
	webhookHTTP = srv.Client()

	if err := runWebhookUp(newDirCmd(dir), nil); err != nil {
		t.Fatalf("runWebhookUp: %v", err)
	}
	if len(fr.calls) == 0 || fr.calls[0] != "up" {
		t.Errorf("expected an Up call, got %v", fr.calls)
	}
}

func TestWebhookDown(t *testing.T) {
	dir := writeFakeProject(t, "https://wh.example.com")
	origRunner := composeRunner
	defer func() { composeRunner = origRunner }()
	fr := &fakeRunner{}
	composeRunner = fr

	if err := runWebhookDown(newDirCmd(dir), nil); err != nil {
		t.Fatalf("runWebhookDown: %v", err)
	}
	if len(fr.calls) == 0 || fr.calls[0] != "down" {
		t.Errorf("expected a Down call, got %v", fr.calls)
	}
}
