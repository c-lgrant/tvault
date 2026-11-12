package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/spf13/cobra"
)

// pinTree is a root named like the real one, with the commands the guard
// names and one ordinary command.
func pinTree() (root *cobra.Command, find func(path ...string) *cobra.Command) {
	root = &cobra.Command{Use: "tvault"}
	root.PersistentFlags().String("context", "", "")
	root.PersistentFlags().String("ctx", "", "")
	noop := func(*cobra.Command, []string) error { return nil }
	ctx := &cobra.Command{Use: "context"}
	ctx.AddCommand(&cobra.Command{Use: "use <name>", RunE: noop}, &cobra.Command{Use: "rm <name>", RunE: noop},
		&cobra.Command{Use: "current", RunE: noop})
	root.AddCommand(ctx, &cobra.Command{Use: "get <name>", RunE: noop}, &cobra.Command{Use: "login", RunE: noop},
		&cobra.Command{Use: "logout", RunE: noop}, &cobra.Command{Use: "use <name>", RunE: noop})
	find = func(path ...string) *cobra.Command {
		c, _, err := root.Find(path)
		if err != nil {
			panic(err)
		}
		c.InheritedFlags() // merges the root's persistent flags in, as a real run does
		return c
	}
	return root, find
}

func TestNoPinLeavesEveryCommandAlone(t *testing.T) {
	t.Setenv(contextEnv, "")
	_, find := pinTree()
	for _, path := range [][]string{{"get"}, {"login"}, {"context", "use"}, {"use"}} {
		if err := pinGuard(find(path...)); err != nil {
			t.Errorf("%v without %s: %v", path, contextEnv, err)
		}
	}
	get := find("get")
	_ = get.Flags().Set("context", "admin")
	if got := contextOverride(get); got != "admin" {
		t.Errorf("--context without a pin = %q, want admin", got)
	}
}

func TestPinIsTheContextWithNoFlag(t *testing.T) {
	t.Setenv(contextEnv, " claude-mac ")
	_, find := pinTree()
	get := find("get")
	if err := pinGuard(get); err != nil {
		t.Fatalf("a plain read under a pin: %v", err)
	}
	if got := contextOverride(get); got != "claude-mac" {
		t.Errorf("context under a pin = %q, want claude-mac", got)
	}
	_ = get.Flags().Set("context", "claude-mac") // naming the pinned context is fine
	if err := pinGuard(get); err != nil {
		t.Errorf("--context equal to the pin: %v", err)
	}
}

func TestPinRefusesAnotherContextAndAnyContextChange(t *testing.T) {
	t.Setenv(contextEnv, "claude-mac")
	for _, flag := range []string{"context", "ctx"} {
		_, find := pinTree()
		get := find("get")
		_ = get.Flags().Set(flag, "admin")
		err := pinGuard(get)
		var ce *clierr.CLIError
		if !errors.As(err, &ce) || ce.Kind != clierr.KindUser || !strings.Contains(ce.Message, `"admin" is refused`) {
			t.Errorf("--%s admin under a pin: got %v", flag, err)
		}
	}
	_, find := pinTree()
	for _, path := range [][]string{{"login"}, {"logout"}, {"context", "use"}, {"context", "rm"}, {"use"}} {
		if err := pinGuard(find(path...)); err == nil {
			t.Errorf("%v under a pin was not refused", path)
		}
	}
	if err := pinGuard(find("context", "current")); err != nil {
		t.Errorf("context current under a pin: %v", err)
	}
}

// The guard names commands by path. A renamed command must not fall out of it.
func TestPinnedCommandsExist(t *testing.T) {
	for path := range pinnedCommands {
		parts := strings.Fields(path)[1:]
		c, rest, err := rootCmd.Find(parts)
		if err != nil || len(rest) != 0 || c.CommandPath() != path {
			t.Errorf("pinned command %q is not a real command (found %q, rest %v, err %v)", path, c.CommandPath(), rest, err)
		}
	}
}
