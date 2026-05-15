package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveInstallPlanPaths(t *testing.T) {
	cases := []struct {
		shell, want    string
		autoDiscovered bool
	}{
		{"bash", ".local/share/bash-completion/completions/tvault", true},
		{"fish", ".config/fish/completions/tvault.fish", true},
		{"zsh", ".local/share/zsh/site-functions/_tvault", false},
	}
	home := "/h/u"
	for _, tc := range cases {
		p, err := resolveInstallPlan(tc.shell, home, "", "")
		if err != nil {
			t.Fatalf("%s: %v", tc.shell, err)
		}
		want := filepath.Join(home, tc.want)
		if p.path != want {
			t.Errorf("%s path = %q, want %q", tc.shell, p.path, want)
		}
		if p.autoDiscover != tc.autoDiscovered {
			t.Errorf("%s autoDiscover = %v, want %v", tc.shell, p.autoDiscover, tc.autoDiscovered)
		}
		if !tc.autoDiscovered && !strings.Contains(p.enableHint, "fpath=") {
			t.Errorf("%s enableHint missing fpath one-liner: %q", tc.shell, p.enableHint)
		}
	}
}

func TestResolveInstallPlanRespectsXDG(t *testing.T) {
	p, err := resolveInstallPlan("bash", "/h", "/custom-data", "/custom-config")
	if err != nil {
		t.Fatal(err)
	}
	if p.path != "/custom-data/bash-completion/completions/tvault" {
		t.Errorf("XDG_DATA_HOME ignored: %q", p.path)
	}
	p, _ = resolveInstallPlan("fish", "/h", "/custom-data", "/custom-config")
	if p.path != "/custom-config/fish/completions/tvault.fish" {
		t.Errorf("XDG_CONFIG_HOME ignored: %q", p.path)
	}
}

func TestResolveInstallPlanUnknownShell(t *testing.T) {
	if _, err := resolveInstallPlan("tcsh", "/h", "", ""); err == nil {
		t.Error("unknown shell should error")
	}
	if _, err := resolveInstallPlan("powershell", "/h", "", ""); err == nil {
		t.Error("powershell should error with hint message")
	}
}

func TestRunInstallWritesAutoDiscoveredFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))

	c := newCompletionInstallCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetArgs([]string{"bash"})
	if err := c.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}
	want := filepath.Join(tmp, "data", "bash-completion", "completions", "tvault")
	st, err := os.Stat(want)
	if err != nil {
		t.Fatalf("expected file at %s: %v", want, err)
	}
	if st.Size() == 0 {
		t.Error("file is empty")
	}
	if !strings.Contains(out.String(), want) {
		t.Errorf("output missing path:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "automatically") {
		t.Errorf("auto-discover message missing:\n%s", out.String())
	}
}

func TestRunInstallZshPrintsFpathHint(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))

	c := newCompletionInstallCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetArgs([]string{"zsh"})
	if err := c.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}
	o := out.String()
	if !strings.Contains(o, "fpath=") || !strings.Contains(o, "compinit") {
		t.Errorf("zsh enable hint missing:\n%s", o)
	}
}

func TestRunInstallPrintOnlyDoesNotWrite(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))

	c := newCompletionInstallCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetArgs([]string{"bash", "--print-only"})
	if err := c.Execute(); err != nil {
		t.Fatalf("install --print-only: %v", err)
	}
	want := filepath.Join(tmp, "data", "bash-completion", "completions", "tvault")
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Errorf("expected no file at %s, got err=%v", want, err)
	}
	if !strings.Contains(out.String(), "Would install") {
		t.Errorf("--print-only should say 'Would install', got:\n%s", out.String())
	}
}

func TestRunUninstallRemovesFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))

	// Install first.
	ins := newCompletionInstallCmd()
	ins.SetOut(&bytes.Buffer{})
	ins.SetArgs([]string{"fish"})
	if err := ins.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}
	target := filepath.Join(tmp, "config", "fish", "completions", "tvault.fish")
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("install file missing: %v", err)
	}

	// Uninstall.
	un := newCompletionUninstallCmd()
	var out bytes.Buffer
	un.SetOut(&out)
	un.SetArgs([]string{"fish"})
	if err := un.Execute(); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("file still present after uninstall: %v", err)
	}
	if !strings.Contains(out.String(), "Removed") {
		t.Errorf("uninstall output missing 'Removed':\n%s", out.String())
	}
}

func TestRunUninstallMissingFileIsIdempotent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))

	un := newCompletionUninstallCmd()
	var out bytes.Buffer
	un.SetOut(&out)
	un.SetArgs([]string{"bash"})
	if err := un.Execute(); err != nil {
		t.Fatalf("uninstall on missing file should not error: %v", err)
	}
	if !strings.Contains(out.String(), "nothing to remove") {
		t.Errorf("idempotent message missing:\n%s", out.String())
	}
}

func TestRunInstallRejectsBadShell(t *testing.T) {
	c := newCompletionInstallCmd()
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	c.SetArgs([]string{"tcsh"})
	if err := c.Execute(); err == nil {
		t.Error("install with unknown shell should error")
	}
}

func TestWriteAtomicReplacesExistingFile(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "sub", "file")
	if err := writeAtomic(target, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(target, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Errorf("got %q, want v2", got)
	}
}
