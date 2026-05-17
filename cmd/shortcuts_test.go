package cmd

import (
	"strings"
	"testing"
)

// TestShortcutsRegistered pins the top-level shortcut surface so we don't
// accidentally drop a verb during a refactor. Each name here is part of the
// CLI's public contract — feedback-tvault-cli.md called these out.
func TestShortcutsRegistered(t *testing.T) {
	want := []string{
		"get", "set", "show", "rm", "add", // tokens flat-verbs
		"list",                                           // also has "ls" alias
		"use",                                            // ctx flat-verb
		"grant",                                          // grants flat-verb
		"tokens", "tk", "agents", "ag", "context", "ctx", // groups still present
	}
	have := map[string]bool{}
	for _, c := range rootCmd.Commands() {
		have[c.Name()] = true
		for _, a := range c.Aliases {
			have[a] = true
		}
	}
	for _, name := range want {
		if !have[name] {
			t.Errorf("expected shortcut/group %q registered on root", name)
		}
	}
}

// TestCtxAliasFlag pins that the --ctx persistent flag exists and reads as a
// substitute for --context (the actual fallback logic is verified by command
// behavior tests in their respective files).
func TestCtxAliasFlag(t *testing.T) {
	if f := rootCmd.PersistentFlags().Lookup("ctx"); f == nil {
		t.Fatal("--ctx persistent flag missing")
	}
	if f := rootCmd.PersistentFlags().Lookup("context"); f == nil {
		t.Fatal("--context persistent flag missing")
	}
}

// TestTokenGetHasCheckFlag pins that `tokens get --check` and `get --check`
// (shortcut) both expose the flag — scripts grep `--help` for it.
func TestTokenGetHasCheckFlag(t *testing.T) {
	if f := tokensGetCmd.Flags().Lookup("check"); f == nil {
		t.Error("tokens get is missing --check flag")
	}
	if f := getShortCmd.Flags().Lookup("check"); f == nil {
		t.Error("get shortcut is missing --check flag")
	}
}

// TestAddShortcutHidesService: the add shortcut forwards its positional into
// --service, so --service must exist but stay hidden from help output.
func TestAddShortcutHidesService(t *testing.T) {
	f := addCmd.Flags().Lookup("service")
	if f == nil {
		t.Fatal("add shortcut missing --service flag (forwarded from positional)")
	}
	if !f.Hidden {
		t.Error("add shortcut's --service flag should be hidden — users pass the positional")
	}
	if !strings.Contains(addCmd.Short, "create") {
		t.Errorf("add shortcut help should reference 'create': %q", addCmd.Short)
	}
}
