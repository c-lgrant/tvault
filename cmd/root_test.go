package cmd

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestHelpOnMissingArgs(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	child := &cobra.Command{
		Use:  "child",
		Args: cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error { return nil },
	}
	root.AddCommand(child)
	helpOnMissingArgs(root)

	var buf bytes.Buffer
	child.SetOut(&buf)
	child.SetErr(&buf)

	if err := child.Args(child, nil); !errors.Is(err, errShowedHelp) {
		t.Fatalf("missing arg should yield errShowedHelp, got %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected the command's help text to be printed")
	}
	if err := child.Args(child, []string{"x"}); err != nil {
		t.Errorf("valid args should still pass: %v", err)
	}
}

func TestHelpOnMissingArgsSkipsNilArgs(t *testing.T) {
	cmd := &cobra.Command{Use: "x"} // nil Args
	helpOnMissingArgs(cmd)
	if cmd.Args != nil {
		t.Error("commands with nil Args should be left untouched")
	}
}
